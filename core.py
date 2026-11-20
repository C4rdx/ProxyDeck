#!/usr/bin/env python3
"""ProxyDeck: local-first proxy discovery, diagnostics and system-proxy control."""
from __future__ import annotations

import concurrent.futures as cf
import hashlib
import http.server
import ipaddress
import json
import os
import platform
import re
import socket
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB = ROOT / "proxies.json"
STATE = ROOT / "state.json"
SETTINGS = ROOT / "sources.json"
UA = "ProxyDeck/0.3"
MAX_BODY = 5 * 1024 * 1024
MAX_TARGET_BYTES = 256 * 1024
DEFAULT_LIMIT = 300

if not os.environ.get("SSL_CERT_FILE"):
    for ca in (
        Path(sys.prefix).parent / "usr" / "ssl" / "cert.pem",
        Path(sys.prefix) / "etc" / "ssl" / "cert.pem",
    ):
        if ca.is_file():
            os.environ["SSL_CERT_FILE"] = str(ca)
            break

DEFAULT_SOURCES = [
    ("hproxy-live", "HProxy live", "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/live.txt", "mixed"),
    ("fusion-http", "Fusion HTTP", "https://raw.githubusercontent.com/FusionProxies/free-proxy-list/main/proxies/http.txt", "http"),
    ("fusion-socks5", "Fusion SOCKS5", "https://raw.githubusercontent.com/FusionProxies/free-proxy-list/main/proxies/socks5.txt", "socks5"),
    ("moleway-all", "Moleway all", "https://raw.githubusercontent.com/Moleway/Free-Proxy-List/main/all.txt", "mixed"),
    ("proxy-free-all", "proxy-free all", "https://raw.githubusercontent.com/proxy-free/free-proxy-list/main/all.txt", "mixed"),
    ("iplocate-http", "iPlocate HTTP", "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/http.txt", "http"),
    ("iplocate-socks5", "iPlocate SOCKS5", "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt", "socks5"),
    ("proxyscrape-http", "ProxyScrape HTTP", "https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/main/proxies/protocols/http/data.txt", "http"),
    ("thordata-all", "Thordata all", "https://raw.githubusercontent.com/Thordata/awesome-free-proxy-list/main/proxies/all.txt", "mixed"),
    ("databay-http", "Databay HTTP", "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/http.txt", "http"),
    ("dahono-http", "Dahono HTTP", "https://raw.githubusercontent.com/Dahono-com/free-proxy-list/main/proxies/http.txt", "http"),
]

LOCK = threading.RLock()
DB_LOCK = threading.RLock()
STATE_LOCK = threading.RLock()
SOURCE_LOCK = threading.RLock()
CANCEL = threading.Event()
SCAN = {
    "running": False, "done": 0, "total": 0, "message": "آماده به کار",
    "kind": "", "stage": "", "started_at": None, "cancel_requested": False,
}


def atomic_json(path: Path, value):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), "utf-8")
    os.replace(tmp, path)


def load_db():
    with DB_LOCK:
        try:
            value = json.loads(DB.read_text("utf-8"))
            return value if isinstance(value, list) else []
        except (OSError, ValueError):
            return []


def save_db(rows):
    with DB_LOCK:
        atomic_json(DB, rows)


def update_db_row(row):
    with DB_LOCK:
        rows = load_db()
        for i, old in enumerate(rows):
            if old.get("id") == row.get("id"):
                rows[i] = row
                break
        else:
            rows.append(row)
        rows.sort(key=lambda x: (x.get("status") != "online", x.get("latency_ms") or 999999))
        atomic_json(DB, rows)


def load_state():
    with STATE_LOCK:
        try:
            value = json.loads(STATE.read_text("utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}


def save_state(value):
    with STATE_LOCK:
        atomic_json(STATE, value)


def _load_sources_unlocked():
    defaults = [
        {"id": sid, "name": name, "url": url, "protocol": proto, "enabled": True,
         "last_candidates": 0, "last_online": 0, "last_checked": None, "last_error": ""}
        for sid, name, url, proto in DEFAULT_SOURCES
    ]
    try:
        saved = json.loads(SETTINGS.read_text("utf-8"))
        if isinstance(saved, list):
            by_id = {x.get("id"): x for x in saved if isinstance(x, dict) and x.get("id")}
            for default in defaults:
                existing = by_id.get(default["id"])
                if existing is None:
                    by_id[default["id"]] = default
                else:
                    # Refresh maintained source URLs/names while preserving user enablement and stats.
                    for key in ("name", "url", "protocol"):
                        existing[key] = default[key]
            return list(by_id.values())
    except (OSError, ValueError):
        pass
    return defaults


def load_sources():
    with SOURCE_LOCK:
        return _load_sources_unlocked()


def save_sources(rows):
    with SOURCE_LOCK:
        atomic_json(SETTINGS, rows)


def public_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def validate_source_url(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("نشانی منبع معتبر نیست.")
    u = urllib.parse.urlsplit(value.strip())
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        raise ValueError("منبع باید HTTPS و بدون اطلاعات ورود باشد.")
    if u.query or u.fragment:
        raise ValueError("پارامتر query و fragment برای منبع پذیرفته نیست؛ نشانی منبع نباید حاوی token باشد.")
    if u.port not in (None, 443):
        raise ValueError("پورت سفارشی برای منبع پذیرفته نیست.")
    host = u.hostname.rstrip(".").lower()
    if host in ("localhost",) or host.endswith((".local", ".internal", ".localhost")):
        raise ValueError("نشانی محلی مجاز نیست.")
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise ValueError("نشانی خصوصی یا محلی مجاز نیست.")
    except ValueError as exc:
        if str(exc) == "نشانی خصوصی یا محلی مجاز نیست.":
            raise
        if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
            raise ValueError("نام میزبان معتبر نیست.")
        try:
            addresses = {x[4][0] for x in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
        except OSError:
            raise ValueError("نام میزبان منبع resolve نشد.")
        if not addresses or not all(public_ip(x) for x in addresses):
            raise ValueError("منبع به نشانی خصوصی یا غیرعمومی اشاره می‌کند.")
    return urllib.parse.urlunsplit(("https", u.netloc, u.path or "/", u.query, ""))


def validate_target_url(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("نشانی مقصد معتبر نیست.")
    u = urllib.parse.urlsplit(value.strip())
    if u.scheme not in ("https", "http") or not u.hostname or u.username or u.password:
        raise ValueError("فقط نشانی HTTP یا HTTPS بدون اطلاعات ورود پذیرفته می‌شود.")
    if u.port not in (None, 80, 443):
        raise ValueError("برای امنیت، پورت مقصد باید استاندارد HTTP/HTTPS باشد.")
    host = u.hostname.rstrip(".").lower()
    if host in ("localhost",) or host.endswith((".local", ".internal", ".localhost")):
        raise ValueError("دسترسی به میزبان محلی مجاز نیست.")
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise ValueError("نشانی خصوصی، محلی یا رزروشده مجاز نیست.")
    except ValueError as exc:
        if str(exc) == "نشانی خصوصی، محلی یا رزروشده مجاز نیست.":
            raise
        if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) or "." not in host:
            raise ValueError("نام دامنه معتبر نیست.")
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path or "/", u.query, ""))


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, mode):
        super().__init__()
        self.mode = mode

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if self.mode == "source":
            validate_source_url(newurl)
        else:
            validate_target_url(newurl)
        if urllib.parse.urlsplit(newurl).scheme != urllib.parse.urlsplit(req.full_url).scheme:
            raise urllib.error.URLError("تغییر پروتکل در redirect مجاز نیست.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def request(url, proxy=None, timeout=8, max_bytes=MAX_TARGET_BYTES, mode="target"):
    handlers = []
    if proxy:
        scheme, address = proxy.split("://", 1)
        if scheme not in ("http", "https"):
            raise ValueError("این پروتکل پراکسی برای درخواست وب پشتیبانی نمی‌شود.")
        handlers.append(urllib.request.ProxyHandler({"http": scheme + "://" + address,
                                                     "https": scheme + "://" + address}))
    else:
        handlers.append(urllib.request.ProxyHandler())
    handlers.append(SafeRedirect(mode))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={
        "User-Agent": UA, "Cache-Control": "no-cache",
        "Accept": "text/html,application/json,text/plain,*/*",
    })
    started = time.perf_counter()
    try:
        response = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            data = data[:max_bytes]
        return response.status, round((time.perf_counter() - started) * 1000), data, response.geturl()


def parse_line(line, default):
    value = line.strip().strip('"').strip("'")
    if not value or value.startswith(("#", "//", "{", "[")):
        return None
    if "://" not in value:
        value = default + "://" + value
    try:
        u = urllib.parse.urlsplit(value)
        scheme, host, port = u.scheme.lower(), u.hostname, u.port
        if scheme not in ("http", "https", "socks4", "socks5") or not host or not port:
            return None
        if u.username or u.password or not 1 <= port <= 65535:
            return None
        if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            return None
        if host.lower() in ("localhost",) or host.lower().endswith((".local", ".internal")):
            return None
        try:
            ip = ipaddress.ip_address(host)
            if not ip.is_global:
                return None
        except ValueError:
            # Proxy endpoints from public lists must be literal public IPs.
            # This avoids DNS rebinding between validation and connection.
            return None
        endpoint = f"{scheme}://{host}:{port}"
        return {"id": endpoint, "address": f"{host}:{port}", "protocol": scheme.upper(),
                "source": "", "status": "untested", "stale": False}
    except (ValueError, TypeError):
        return None


def fetch_source(source):
    try:
        url = validate_source_url(source["url"])
        status, _, data, _ = request(url, timeout=18, max_bytes=MAX_BODY, mode="source")
        if not 200 <= status < 300:
            raise RuntimeError(f"HTTP {status}")
        rows = []
        for line in data.decode("utf-8", "replace").splitlines():
            row = parse_line(line, "http" if source.get("protocol") == "mixed" else source.get("protocol", "http"))
            if row:
                row["source"] = source["name"]
                rows.append(row)
        return source["id"], rows, ""
    except Exception as exc:
        return source["id"], [], str(exc)[:180]


def probe_url(row, url, timeout=10):
    if row.get("protocol") not in ("HTTP", "HTTPS"):
        return {"ok": False, "status": None, "latency_ms": None, "checked_at": int(time.time()),
                "note": "این نوع پراکسی برای درخواست وب در این نسخه پشتیبانی نمی‌شود."}
    endpoint_host = urllib.parse.urlsplit(row["id"]).hostname
    if not endpoint_host or not public_ip(endpoint_host):
        return {"ok": False, "status": None, "latency_ms": None, "checked_at": int(time.time()),
                "note": "نشانی پراکسی عمومی و معتبر نیست."}
    status, latency, body, _ = request(url, row["id"], timeout=timeout, max_bytes=MAX_TARGET_BYTES)
    ok = 200 <= status < 400
    return {"ok": ok, "status": status, "latency_ms": latency, "checked_at": int(time.time()),
            "bytes_received": len(body), "note": "" if ok else f"پاسخ HTTP {status}"}


def check(row):
    result = dict(row)
    for key in ("exit_ip", "error", "note", "youtube_http_status", "gemini_http_status",
                "general_http_status", "youtube_error", "gemini_error", "general_error"):
        result.pop(key, None)
    if result.get("protocol") not in ("HTTP", "HTTPS"):
        result.update(status="unsupported", latency_ms=None, tcp_ping_ms=None,
                      youtube=False, gemini=False, general=False, checked_at=int(time.time()),
                      note="SOCKS در فهرست نگهداری می‌شود اما انتقال وب/اتصال سیستم هنوز پیاده‌سازی نشده است.")
        return result
    parsed = urllib.parse.urlsplit(result["id"])
    host, port = parsed.hostname, parsed.port
    tcp_ms = None
    try:
        if not host or not public_ip(host):
            raise ValueError("فقط endpoint با IP عمومیِ مستقیم پذیرفته می‌شود")
        connect_host = host
        started = time.perf_counter()
        with socket.create_connection((connect_host, port), timeout=4):
            pass
        tcp_ms = round((time.perf_counter() - started) * 1000)
    except Exception as exc:
        result.update(status="offline", latency_ms=None, tcp_ping_ms=tcp_ms,
                      youtube=False, gemini=False, general=False, checked_at=int(time.time()),
                      error=str(exc)[:140], stale=False)
        return result

    tests = {}
    timings = {}
    endpoints = (
        ("youtube", "https://www.youtube.com/generate_204"),
        ("gemini", "https://gemini.google.com/"),
        ("general", "https://example.com/"),
    )
    for key, url in endpoints:
        try:
            measured = probe_url(result, url, timeout=6)
            tests[key] = measured["ok"]
            if measured["status"] is not None:
                result[key + "_http_status"] = measured["status"]
            if measured["ok"] and measured["latency_ms"] is not None:
                timings[key] = measured["latency_ms"]
        except Exception as exc:
            tests[key] = False
            result[key + "_error"] = str(exc)[:100]

    successful = list(timings.values())
    web_latency = round(statistics.median(successful)) if successful else None
    any_web = any(tests.values())
    result.update(
        status="online" if any_web else "degraded",
        latency_ms=web_latency,
        tcp_ping_ms=tcp_ms,
        youtube=tests["youtube"],
        gemini=tests["gemini"],
        general=tests["general"],
        checked_at=int(time.time()),
        security="untrusted",
        security_note="پراکسی عمومی؛ اعتماد و محرمانگی آن تضمین نشده است.",
        stale=False,
    )
    result.pop("exit_ip", None)
    result.pop("error", None)
    if any_web:
        result.pop("note", None)
    else:
        result["note"] = "اتصال TCP برقرار شد، اما هیچ‌یک از مقصدهای آزمایشی پاسخ موفق ندادند؛ تست مقصد دلخواه را امتحان کنید."
    return result


def update_progress(**values):
    with LOCK:
        SCAN.update(values)


def start_job(kind, message, worker, meta=None):
    with LOCK:
        if SCAN["running"]:
            return False
        CANCEL.clear()
        SCAN.update(running=True, done=0, total=0, message=message, kind=kind,
                    stage="starting", started_at=int(time.time()), cancel_requested=False,
                    target_url=(meta or {}).get("target_url", ""),
                    target_key=(meta or {}).get("target_key", ""),
                    target_label=(meta or {}).get("target_label", ""))

    def run():
        try:
            worker()
        except Exception as exc:
            update_progress(message=f"عملیات با خطا متوقف شد: {str(exc)[:180]}", stage="error")
        finally:
            with LOCK:
                SCAN["running"] = False
                SCAN["cancel_requested"] = False
                if SCAN.get("stage") not in ("error", "cancelled"):
                    SCAN["stage"] = "complete"

    threading.Thread(target=run, name=f"ProxyDeck-{kind}", daemon=True).start()
    return True


def run_checks(rows, kind, target_url=None):
    total = len(rows)
    update_progress(total=total, done=0, stage="testing",
                    message=f"آماده‌سازی سنجش {total} پراکسی…")
    if not total:
        update_progress(message="پراکسی‌ای برای بررسی وجود ندارد.", stage="complete")
        return
    workers = min(24, max(1, total))
    completed = 0
    target_key = hashlib.sha256(target_url.encode("utf-8")).hexdigest()[:20] if target_url else ""
    parsed_target = urllib.parse.urlsplit(target_url) if target_url else None
    target_label = (urllib.parse.urlunsplit((parsed_target.scheme, parsed_target.netloc, "", "", ""))
                    if parsed_target else "")

    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        iterator = iter(rows)
        futures = {}

        def submit_next():
            if CANCEL.is_set():
                return False
            try:
                row = next(iterator)
            except StopIteration:
                return False
            fn = (lambda r=row: probe_url(r, target_url)) if target_url else (lambda r=row: check(r))
            futures[pool.submit(fn)] = row
            return True

        # Keep only active work in the executor. A large queued backlog makes cancellation ineffective.
        for _ in range(workers):
            if not submit_next():
                break

        while futures:
            future = next(cf.as_completed(tuple(futures)))
            row = futures.pop(future)
            if future.cancelled():
                continue
            try:
                value = future.result()
                if target_url:
                    updated = dict(row)
                    targets = dict(updated.get("target_results", {}))
                    targets[target_key] = {**value, "target_key": target_key, "target_label": target_label}
                    updated["target_results"] = targets
                else:
                    updated = value
                update_db_row(updated)
            except Exception as exc:
                updated = dict(row)
                if target_url:
                    targets = dict(updated.get("target_results", {}))
                    targets[target_key] = {
                        "ok": False, "status": None, "latency_ms": None,
                        "checked_at": int(time.time()), "target_key": target_key,
                        "target_label": target_label, "note": str(exc)[:140],
                    }
                    updated["target_results"] = targets
                else:
                    updated.update(status="error", error=str(exc)[:140], checked_at=int(time.time()))
                update_db_row(updated)

            completed += 1
            update_progress(done=completed,
                            message=f"{'سنجش مقصد' if target_url else 'بررسی پراکسی‌ها'}: {completed} از {total}")

            if CANCEL.is_set():
                for pending in list(futures):
                    if pending.cancel():
                        futures.pop(pending, None)
            else:
                submit_next()

    if CANCEL.is_set():
        update_progress(stage="cancelled", message=f"لغو شد؛ {completed} نتیجه تکمیل‌شده ذخیره شد.")
    else:
        update_progress(stage="complete", message=f"بررسی تمام شد؛ {completed} نتیجه ثبت شد.")


def scan_worker(limit=DEFAULT_LIMIT):
    sources = [s for s in load_sources() if s.get("enabled")]
    if not sources:
        update_progress(message="هیچ منبع فعالی انتخاب نشده است.", stage="complete", total=0)
        return
    update_progress(stage="sources", total=len(sources), done=0, message="دریافت فهرست منابع فعال…")
    found = {}
    source_rows = {}
    errors = {}
    with cf.ThreadPoolExecutor(max_workers=min(8, len(sources))) as pool:
        iterator = iter(sources)
        futures = {}

        def submit_source():
            if CANCEL.is_set():
                return False
            try:
                source = next(iterator)
            except StopIteration:
                return False
            futures[pool.submit(fetch_source, source)] = source
            return True

        for _ in range(min(8, len(sources))):
            if not submit_source():
                break

        while futures:
            future = next(cf.as_completed(tuple(futures)))
            source = futures.pop(future)
            if future.cancelled():
                continue
            sid, rows, error = future.result()
            source_rows[sid] = rows
            if error:
                errors[sid] = error
            for row in rows:
                if row["id"] in found:
                    names = found[row["id"]]["source"].split(", ")
                    if row["source"] not in names:
                        found[row["id"]]["source"] += ", " + row["source"]
                else:
                    found[row["id"]] = row
            update_progress(done=len(source_rows), message=f"دریافت منابع: {len(source_rows)} از {len(sources)}")
            if CANCEL.is_set():
                for pending in list(futures):
                    if pending.cancel():
                        futures.pop(pending, None)
            else:
                submit_source()
    current = load_db()
    existing = {row.get("id"): row for row in current}
    candidates = []
    existing_changed = False
    for pid, row in found.items():
        if pid in existing:
            old = existing[pid]
            names = set(old.get("source", "").split(", ")) | set(row.get("source", "").split(", "))
            merged_sources = ", ".join(sorted(x for x in names if x))
            if old.get("source", "") != merged_sources or old.get("stale"):
                old["source"] = merged_sources
                old["stale"] = False
                existing[pid] = old
                existing_changed = True
        else:
            candidates.append(row)
    if existing_changed:
        save_db(list(existing.values()))
    candidates.sort(key=lambda row: row.get("protocol") not in ("HTTP", "HTTPS"))
    candidates = candidates[:max(1, min(int(limit), 2000))]
    update_progress(total=len(candidates), done=0, stage="testing",
                    message=f"{len(candidates)} پراکسی تازه برای سنجش پیدا شد؛ موارد قبلی دوباره تست نمی‌شوند.")
    for source in sources:
        rows = source_rows.get(source["id"], [])
        source["last_candidates"] = len(rows)
        source["last_online"] = 0
        source["last_checked"] = int(time.time())
        source["last_error"] = errors.get(source["id"], "")
    if candidates and not CANCEL.is_set():
        run_checks(candidates, "refresh")
    checked = {x.get("id"): x for x in load_db()}
    recent_cutoff = int(time.time()) - 86400
    for source in sources:
        names = {x["id"] for x in source_rows.get(source["id"], [])}
        source["last_online"] = sum(
            1 for pid in names
            if checked.get(pid, {}).get("status") == "online"
            and checked.get(pid, {}).get("checked_at", 0) >= recent_cutoff
        )
    save_sources(load_sources_update(source_updates=sources))
    if CANCEL.is_set():
        update_progress(stage="cancelled", message="کشف لغو شد؛ نتایج تکمیل‌شده حفظ شدند.")
    else:
        update_progress(stage="complete",
                        message=f"کشف تمام شد؛ {len(found)} endpoint یکتا، {len(candidates)} مورد تازه، {len(errors)} خطای منبع.")


def load_sources_update(source_updates):
    by_id = {x["id"]: x for x in source_updates}
    for source in load_sources():
        if source["id"] not in by_id:
            by_id[source["id"]] = source
    return list(by_id.values())


def test_all_worker():
    run_checks(load_db(), "test-all")


def test_one_worker(proxy_id):
    row = next((x for x in load_db() if x.get("id") == proxy_id), None)
    if not row:
        update_progress(message="پراکسی پیدا نشد.", stage="error")
        return
    run_checks([row], "test-one")


def target_worker(url):
    eligible = [row for row in load_db()
                if row.get("status") in ("online", "degraded")
                and row.get("protocol") in ("HTTP", "HTTPS") and not row.get("stale")]
    run_checks(eligible, "target-test", url)


def _connect(proxy_id):
    row = next((x for x in load_db() if x.get("id") == proxy_id), None)
    if not row or row.get("status") not in ("online", "degraded") or row.get("stale"):
        return "ابتدا یک پراکسی تازه را انتخاب و تست کنید."
    if row.get("status") == "degraded" and not any(
        item.get("ok") for item in row.get("target_results", {}).values()
    ):
        return "اتصال TCP برقرار است اما مقصد وب تأیید نشده؛ ابتدا تست مقصد موفق انجام دهید."
    if row.get("protocol") != "HTTP":
        return "در حال حاضر اتصال سیستم فقط برای پراکسی HTTP پیاده‌سازی شده است."
    if not public_ip(urllib.parse.urlsplit(row["id"]).hostname or ""):
        return "برای امنیت، فقط endpoint با IP عمومی مستقیم قابل فعال‌سازی است."
    if platform.system() != "Windows":
        return "اتصال پراکسی سیستم در این نسخه فقط برای Windows فعال است."
    import winreg
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    state = load_state()
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
        original = {}
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
            try:
                original[name] = winreg.QueryValueEx(key, name)[0]
            except OSError:
                original[name] = 0 if name == "ProxyEnable" else ""
    override = "<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;169.254.*;[::1]"
    applied = {"ProxyEnable": 1, "ProxyServer": row["address"], "ProxyOverride": override}
    if "windows_original" not in state:
        state["windows_original"] = original
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, applied["ProxyServer"])
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, applied["ProxyOverride"])
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, applied["ProxyEnable"])
    try:
        import ctypes
        ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)
        ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
    except Exception:
        pass
    state["windows_applied"] = applied
    state["active"] = row["id"]
    save_state(state)
    return "اتصال سیستم تنظیم شد: " + row["address"]


def connect(proxy_id):
    with STATE_LOCK:
        return _connect(proxy_id)


def _disconnect():
    if platform.system() != "Windows":
        return "مدیریت پراکسی سیستم در این سیستم‌عامل فعال نیست."
    import winreg
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    state = load_state()
    original = state.get("windows_original")
    applied = state.get("windows_applied")
    if original:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
            current = {}
            for name in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
                try:
                    current[name] = winreg.QueryValueEx(key, name)[0]
                except OSError:
                    current[name] = 0 if name == "ProxyEnable" else ""
        # Migrate sessions created by ProxyDeck 0.2, which did not persist windows_applied.
        if not applied and state.get("active"):
            old_row = next((x for x in load_db() if x.get("id") == state["active"]), None)
            if old_row:
                legacy = {
                    "ProxyEnable": 1,
                    "ProxyServer": old_row.get("address", ""),
                    "ProxyOverride": "<local>;localhost;127.*;10.*;192.168.*;*.ir",
                }
                if current == legacy:
                    applied = legacy
        if applied and current == applied:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                for name, value in original.items():
                    kind = winreg.REG_DWORD if name == "ProxyEnable" else winreg.REG_SZ
                    winreg.SetValueEx(key, name, 0, kind, value)
            try:
                import ctypes
                ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)
                ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
            except Exception:
                pass
            message = "تنظیمات قبلی پراکسی بازگردانده شد."
        elif applied:
            message = "تنظیمات سیستم بعد از اتصال تغییر کرده‌اند؛ برای جلوگیری از بازنویسی تغییر کاربر، آن‌ها را دست‌نخورده گذاشتم."
        else:
            message = "تنظیمات پراکسی با مقادیر ذخیره‌شده قابل تطبیق نبود؛ برای جلوگیری از تغییر ناخواسته، دست‌نخورده باقی ماند."
    else:
        message = "تنظیم قبلی برای بازگردانی ثبت نشده بود."
    state.pop("active", None)
    state.pop("windows_original", None)
    state.pop("windows_applied", None)
    save_state(state)
    return message


def disconnect():
    with STATE_LOCK:
        return _disconnect()


def revision():
    values = []
    for path in (DB, SETTINGS):
        try:
            values.append(path.stat().st_mtime_ns)
        except OSError:
            values.append(0)
    return max(values)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ProxyDeckLocal/0.3"

    def log_message(self, *args):
        pass

    def send_json(self, value, code=200):
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def allowed(self):
        host = self.headers.get("Host", "")
        if host not in ("127.0.0.1:8765", "localhost:8765"):
            self.send_json({"error": "Host rejected"}, 403)
            return False
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            self.send_json({"error": "Loopback only"}, 403)
            return False
        return True

    def read_body(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("طول درخواست معتبر نیست.")
        if size < 0 or size > 65536:
            raise ValueError("حجم درخواست بیش از حد مجاز است.")
        raw = self.rfile.read(size) if size else b"{}"
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("ساختار درخواست معتبر نیست.")
        return value

    def do_GET(self):
        if not self.allowed():
            return
        if self.path in ("/", "/index.html"):
            try:
                body = (ROOT / "index.html").read_bytes()
            except OSError:
                self.send_json({"error": "index.html not found"}, 500)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/proxies":
            with LOCK:
                scan_snapshot = dict(SCAN)
            self.send_json({"rows": load_db(), "scan": scan_snapshot, "state": load_state(),
                            "revision": revision(), "sources": load_sources()})
        elif self.path == "/api/status":
            with LOCK:
                scan_snapshot = dict(SCAN)
            self.send_json({"scan": scan_snapshot, "state": load_state(), "revision": revision()})
        else:
            self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        if not self.allowed():
            return
        origin = self.headers.get("Origin", "")
        if origin not in ("http://127.0.0.1:8765", "http://localhost:8765"):
            self.send_json({"error": "Origin rejected"}, 403)
            return
        try:
            data = self.read_body()
            if self.path == "/api/scan":
                ok = start_job("refresh", "در حال شروع کشف منابع…", lambda: scan_worker(DEFAULT_LIMIT))
                self.send_json({"ok": ok, "message": "کشف شروع شد." if ok else "یک عملیات دیگر در حال اجراست."}, 200 if ok else 409)
            elif self.path == "/api/test-all":
                ok = start_job("test-all", "در حال آماده‌سازی تست همه پراکسی‌ها…", test_all_worker)
                self.send_json({"ok": ok, "message": "تست شروع شد." if ok else "یک عملیات دیگر در حال اجراست."}, 200 if ok else 409)
            elif self.path == "/api/test":
                pid = str(data.get("id", ""))[:300]
                ok = start_job("test-one", "در حال تست پراکسی انتخاب‌شده…", lambda: test_one_worker(pid))
                self.send_json({"ok": ok, "message": "تست شروع شد." if ok else "یک عملیات دیگر در حال اجراست."}, 200 if ok else 409)
            elif self.path == "/api/target-test":
                target = validate_target_url(data.get("url", ""))
                parsed_target = urllib.parse.urlsplit(target)
                label = urllib.parse.urlunsplit((parsed_target.scheme, parsed_target.netloc, "", "", ""))
                target_key = hashlib.sha256(target.encode("utf-8")).hexdigest()[:20]
                ok = start_job("target-test", "در حال آماده‌سازی تست مقصد…",
                               lambda: target_worker(target),
                               {"target_url": target, "target_key": target_key, "target_label": label})
                self.send_json({"ok": ok, "message": "تست مقصد شروع شد." if ok else "یک عملیات دیگر در حال اجراست."}, 200 if ok else 409)
            elif self.path == "/api/cancel":
                with LOCK:
                    if not SCAN["running"]:
                        self.send_json({"ok": False, "message": "عملیاتی برای لغو وجود ندارد."}, 409)
                        return
                    CANCEL.set()
                    SCAN["cancel_requested"] = True
                    SCAN["message"] = "درخواست لغو ثبت شد؛ نتایج تکمیل‌شده ذخیره می‌شوند."
                self.send_json({"ok": True, "message": "درخواست لغو ثبت شد."})
            elif self.path == "/api/connect":
                self.send_json({"message": connect(str(data.get("id", ""))[:300])})
            elif self.path == "/api/disconnect":
                self.send_json({"message": disconnect()})
            elif self.path == "/api/sources/toggle":
                if SCAN["running"]:
                    self.send_json({"error": "هنگام اجرای عملیات، تغییر منابع موقتاً غیرفعال است."}, 409)
                    return
                sid = str(data.get("id", ""))[:100]
                with LOCK:
                    if SCAN["running"]:
                        self.send_json({"error": "هنگام اجرای عملیات، تغییر منابع موقتاً غیرفعال است."}, 409)
                        return
                    with SOURCE_LOCK:
                        rows = load_sources()
                        source = next((x for x in rows if x["id"] == sid), None)
                        if not source:
                            self.send_json({"error": "منبع پیدا نشد."}, 404)
                            return
                        source["enabled"] = bool(data.get("enabled"))
                        save_sources(rows)
                self.send_json({"ok": True, "sources": rows})
            elif self.path == "/api/sources/add":
                if SCAN["running"]:
                    self.send_json({"error": "هنگام اجرای عملیات، افزودن منبع موقتاً غیرفعال است."}, 409)
                    return
                name = str(data.get("name", "")).strip()[:70]
                url = validate_source_url(data.get("url", ""))
                if not name or "," in name:
                    raise ValueError("نام منبع را وارد کنید؛ از ویرگول استفاده نکنید.")
                sid = "custom-" + hashlib.sha256(url.encode()).hexdigest()[:12]
                with LOCK:
                    if SCAN["running"]:
                        self.send_json({"error": "هنگام اجرای عملیات، افزودن منبع موقتاً غیرفعال است."}, 409)
                        return
                    with SOURCE_LOCK:
                        rows = load_sources()
                        if any(x["url"] == url for x in rows):
                            raise ValueError("این منبع قبلاً ثبت شده است.")
                        if any(x["name"].casefold() == name.casefold() for x in rows):
                            raise ValueError("نام این منبع قبلاً استفاده شده است.")
                        rows.append({"id": sid, "name": name, "url": url, "protocol": "mixed",
                                     "enabled": True, "custom": True, "last_candidates": 0,
                                     "last_online": 0, "last_checked": None, "last_error": ""})
                        save_sources(rows)
                self.send_json({"ok": True, "sources": rows})
            else:
                self.send_json({"error": "Not found"}, 404)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)[:220]}, 400)
        except Exception as exc:
            self.send_json({"error": str(exc)[:220]}, 500)


def serve():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    server.daemon_threads = True
    print("ProxyDeck UI: http://127.0.0.1:8765")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def menu():
    while True:
        clear_screen()
        state = load_state()
        print("=" * 72)
        print("ProxyDeck | Local proxy diagnostics")
        print("CONNECTED: " + state.get("active", "Not connected"))
        print("=" * 72)
        print("1. Discover new proxies from enabled sources")
        print("2. Test all saved proxies")
        print("3. Show saved proxies")
        print("4. Open dashboard in the default browser")
        print("5. Disconnect and restore previous settings")
        print("6. Exit")
        choice = input("\nProxyDeck > ").strip()
        if choice == "1":
            if start_job("refresh", "در حال کشف…", lambda: scan_worker(DEFAULT_LIMIT)):
                while SCAN["running"]:
                    print(SCAN["message"])
                    time.sleep(1)
            else:
                print("An operation is already running.")
            input("\nEnter…")
        elif choice == "2":
            if start_job("test-all", "در حال تست…", test_all_worker):
                while SCAN["running"]:
                    print(SCAN["message"])
                    time.sleep(1)
            else:
                print("An operation is already running.")
            input("\nEnter…")
        elif choice == "3":
            clear_screen()
            for i, row in enumerate(load_db(), 1):
                print(f"{i:4} {row.get('address',''):24} {row.get('status','?'):12} "
                      f"TCP={row.get('tcp_ping_ms','—')} Web={row.get('latency_ms','—')} "
                      f"{row.get('country','')}")
            input("\nEnter…")
        elif choice == "4":
            webbrowser.open("http://127.0.0.1:8765")
            try:
                serve()
            except OSError as exc:
                print(exc)
                input("\nEnter…")
        elif choice == "5":
            print(disconnect())
            input("\nEnter…")
        elif choice == "6":
            break


if __name__ == "__main__":
    if "--scan" in sys.argv:
        print(scan_worker(int(sys.argv[sys.argv.index("--scan") + 1]) if len(sys.argv) > 2 else DEFAULT_LIMIT))
    elif "--ui" in sys.argv:
        serve()
    else:
        menu()
