import contextlib
import threading
import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import core


class InputValidationTests(unittest.TestCase):
    def test_accepts_https_public_source(self):
        self.assertEqual(
            core.validate_source_url("https://8.8.8.8/list.txt"),
            "https://8.8.8.8/list.txt",
        )

    def test_rejects_insecure_or_local_sources(self):
        for value in (
            "http://example.com/list.txt",
            "https://127.0.0.1/list.txt",
            "https://localhost/list.txt",
            "https://example.com/list.txt?token=secret",
            "https://example.com:8443/list.txt",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                core.validate_source_url(value)

    def test_accepts_public_http_destination(self):
        self.assertEqual(
            core.validate_target_url("https://example.com/path"),
            "https://example.com/path",
        )

    def test_rejects_local_or_credentialed_destinations(self):
        for value in (
            "file:///etc/passwd",
            "http://127.0.0.1/",
            "http://192.168.1.1/",
            "http://localhost/",
            "https://user:pass@example.com/",
            "https://example.com:8443/",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                core.validate_target_url(value)

    def test_proxy_parser_accepts_only_public_ip_endpoints(self):
        self.assertIsNone(core.parse_line("203.0.113.7:8080", "http"))
        good = core.parse_line("8.8.8.8:8080", "http")
        self.assertEqual(good["protocol"], "HTTP")
        self.assertIsNone(core.parse_line("192.168.1.10:8080", "http"))
        self.assertIsNone(core.parse_line("proxy.example.com:8080", "http"))


class ProbeTests(unittest.TestCase):
    def test_tcp_success_is_not_mistaken_for_web_success(self):
        row = {"id": "http://8.8.8.8:8080", "address": "8.8.8.8:8080", "protocol": "HTTP"}
        responses = [
            {"ok": False, "status": 403, "latency_ms": 80},
            {"ok": False, "status": 403, "latency_ms": 90},
            {"ok": False, "status": 403, "latency_ms": 100},
        ]
        with patch.object(core.socket, "create_connection", return_value=contextlib.nullcontext()):
            with patch.object(core, "probe_url", side_effect=responses):
                result = core.check(row)
        self.assertIsNotNone(result["tcp_ping_ms"])
        self.assertEqual(result["status"], "degraded")
        self.assertFalse(result["youtube"])
        self.assertFalse(result["general"])

    def test_successful_web_probes_use_median_latency(self):
        row = {"id": "http://8.8.8.8:8080", "address": "8.8.8.8:8080", "protocol": "HTTP"}
        responses = [
            {"ok": True, "status": 204, "latency_ms": 100},
            {"ok": False, "status": 403, "latency_ms": 200},
            {"ok": True, "status": 200, "latency_ms": 160},
        ]
        with patch.object(core.socket, "create_connection", return_value=contextlib.nullcontext()):
            with patch.object(core, "probe_url", side_effect=responses):
                result = core.check(row)
        self.assertEqual(result["status"], "online")
        self.assertEqual(result["latency_ms"], 130)
        self.assertTrue(result["youtube"])
        self.assertFalse(result["gemini"])
        self.assertTrue(result["general"])

    def test_cancel_keeps_completed_results_and_does_not_queue_the_rest(self):
        rows = [
            {"id": f"http://8.8.8.{i}:8080", "address": f"8.8.8.{i}:8080",
             "protocol": "HTTP"}
            for i in range(1, 31)
        ]

        def slow_check(row):
            time.sleep(0.06)
            return {**row, "status": "online", "checked_at": 123456}

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "proxies.json"
            core.CANCEL.clear()
            timer = threading.Timer(0.01, core.CANCEL.set)
            try:
                with patch.object(core, "DB", db_path):
                    with patch.object(core, "check", side_effect=slow_check):
                        timer.start()
                        core.run_checks(rows, "test-all")
                    saved = core.load_db()
            finally:
                timer.cancel()
                core.CANCEL.clear()

        self.assertGreater(len(saved), 0)
        self.assertLess(len(saved), len(rows))
        self.assertEqual(core.SCAN["stage"], "cancelled")
        self.assertEqual(core.SCAN["done"], len(saved))


    def test_target_result_is_persisted_without_full_url(self):
        target = "https://example.com/private/path?token=should-not-persist"
        row = {"id": "http://8.8.8.8:8080", "address": "8.8.8.8:8080",
               "protocol": "HTTP", "status": "online", "stale": False}
        result = {"ok": True, "status": 200, "latency_ms": 145,
                  "checked_at": 123456, "bytes_received": 512, "note": ""}
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "proxies.json"
            with patch.object(core, "DB", db_path):
                with patch.object(core, "probe_url", return_value=result):
                    core.run_checks([row], "target-test", target)
                saved = core.load_db()
        self.assertEqual(len(saved), 1)
        target_result = next(iter(saved[0]["target_results"].values()))
        self.assertTrue(target_result["ok"])
        self.assertEqual(target_result["latency_ms"], 145)
        self.assertEqual(target_result["target_label"], "https://example.com")
        self.assertNotIn("private/path", str(saved))
        self.assertNotIn("should-not-persist", str(saved))


if __name__ == "__main__":
    unittest.main()
