# ProxyDeck

ProxyDeck is a lightweight, local-first workspace for discovering, testing, filtering, and managing public proxy endpoints. It combines a Python standard-library core with a framework-free HTML dashboard and an interactive terminal interface.

> Public proxies are untrusted infrastructure. A successful connection test does not certify anonymity, privacy, operator trust, or reliable access to every feature of a website.

## Features

- Discover endpoints from multiple independently configurable public sources.
- Enable or disable individual sources; add a custom HTTPS text-list source.
- Track candidate counts, endpoints tested online in the last 24 hours, last-check time, and source errors.
- Deduplicate endpoints and retain previously discovered entries.
- Avoid re-testing previously saved endpoints during discovery; only newly discovered endpoints are tested.
- Test one proxy, all saved proxies, or online/TCP-reachable proxies against a user-specified HTTP(S) destination.
- Record each completed result immediately in the local catalogue; cancel long-running jobs without losing completed results.
- Measure TCP connection setup separately from end-to-end HTTPS response time.
- Check lightweight YouTube, Gemini, and general-web endpoints.
- Filter and sort the catalogue, including by custom-destination response time.
- Activate supported HTTP proxies in the Windows per-user system-proxy settings and restore the previous settings safely.
- Open the dashboard in the operating system's default browser; Firefox is not a dependency.

## Requirements

- Python 3.10 or newer.
- A modern browser.
- Internet access for source retrieval and proxy tests.

Only Python's standard library is required. No pip packages, JavaScript framework, remote font, browser extension, administrator permission, network driver, or external runtime service is required.

## Quick start

### Windows

1. Install Python 3.10 or newer.
2. Run RUN-WINDOWS.cmd.
3. The launcher starts the local Python service without a visible console and opens http://127.0.0.1:8765 in the default browser.
4. Run CLI-WINDOWS.cmd for the terminal menu.

The graphical launcher uses the operating system's default browser and starts both the Python service and browser from the temporary directory. This avoids inheriting the project folder as the browser's working directory, which can otherwise keep a Windows directory handle open and prevent moving or renaming the project.

The Windows launcher prefers C:\msys64\ucrt64\bin\pythonw.exe when present and otherwise uses pythonw.exe from PATH. It does not assume Firefox is installed.

### Linux

    chmod +x run-linux.sh cli-linux.sh
    ./run-linux.sh

The dashboard listens on 127.0.0.1:8765; it is not exposed to the LAN.

## Dashboard workflow

1. Discover: fetch enabled source lists and test newly discovered endpoints.
2. Manage sources: disable low-yield sources temporarily or add a direct HTTPS text list.
3. Test: re-test one endpoint or the saved catalogue.
4. Test a destination: enter a URL such as https://www.youtube.com/; online and TCP-reachable/degraded HTTP/HTTPS proxies are tested against that exact destination and sorted by the measured response.
5. Connect: activate a freshly tested HTTP proxy on Windows. A degraded proxy requires at least one successful destination test. The original per-user proxy settings are saved and restored on disconnect, unless another application changed those settings in the meantime.
6. Cancel: stop queued work. Already completed results remain in the local database; in-flight requests finish when their timeout expires.
7. Disable/reset: run DISABLE-RESET-WINDOWS.cmd to cancel active work, restore the previous Windows proxy settings, and stop the local UI service. This safety action preserves the proxy catalogue and source preferences; it does not erase user data.

## Measurements

| Field | Meaning |
|---|---|
| TCP | Time to establish a TCP connection to the proxy endpoint. This is not ICMP ping. |
| Web | Median response time among successful YouTube, Gemini, and general-web HTTPS probes through the proxy. |
| Destination | HTTP status, response time, and received byte count for the exact URL supplied by the user. |
| YouTube | Lightweight request to www.youtube.com/generate_204; this does not test playback or account sign-in. |
| Gemini | HTTP(S) response from the Gemini website; this does not guarantee all features work. |
| General | HTTP(S) response from example.com. |

A low TCP time does not necessarily mean fast browsing. A proxy whose TCP port accepts connections but fails all standard web probes is marked degraded, not offline; it remains eligible for custom-destination tests. Windows activation of a degraded proxy requires at least one successful destination test. Destination response time is generally more representative of a particular route, but it can still vary with server load, rate limits, regional policies, CAPTCHA, and proxy congestion.

## Sources

The default source catalogue is maintained in core.py:

| Provider | Repository |
|---|---|
| HProxy | https://github.com/hproxy-com/free-proxy-list |
| FusionProxies | https://github.com/FusionProxies/free-proxy-list |
| Moleway | https://github.com/Moleway/Free-Proxy-List |
| proxy-free | https://github.com/proxy-free/free-proxy-list |
| iPlocate | https://github.com/iplocate/free-proxy-list |
| ProxyScrape | https://github.com/ProxyScrape/free-proxy-list |
| Thordata | https://github.com/Thordata/awesome-free-proxy-list |
| Databay | https://github.com/databay-labs/free-proxy-list |
| Dahono | https://github.com/Dahono-com/free-proxy-list |

Custom sources must be direct HTTPS text lists. Private/local destinations and non-standard ports are rejected. Source downloads use normal TLS certificate verification and honor the operating system's configured proxy when available.

## Local data

- proxies.json: local proxy catalogue, including test and destination results.
- state.json: active connection and saved Windows proxy settings.
- sources.json: source enablement and custom source configuration.

These files are runtime/user data and are intentionally excluded from source control.

## Security and privacy

- The local HTTP service binds only to 127.0.0.1. It rejects non-loopback clients, unexpected Host headers, and cross-origin POST requests.
- The dashboard uses no third-party scripts, remote fonts, or external UI assets.
- The graphical Windows launcher uses the default browser; Firefox is neither required nor detected as a dependency. Its working directory is deliberately set to the system temporary folder to avoid locking the project directory.
- Source URLs must use HTTPS, and redirects are validated. Local/private source destinations are rejected.
- Destination tests accept HTTP(S) URLs, reject credentials, local/private IP literals, local hostnames, and non-standard ports. Redirects are validated too.
- Proxy endpoints from public lists must use literal public IP addresses; hostname endpoints are rejected to reduce DNS-rebinding and private-network risks.
- Destination tests accept domain names without resolving them locally, so the destination lookup can be performed by the proxy rather than leaking a local DNS query. Local/private IP literals and local hostnames are rejected.
- The full destination path and query are not persisted in the catalogue; only a hash and the destination origin are retained with each result.
- Requests have timeouts and bounded response sizes. Results are written atomically to local JSON files.
- The scanner does not query a third-party geolocation API; exit IP addresses are not sent to a separate geolocation provider.
- Windows disconnect restores the previous settings only if the current values still match the settings ProxyDeck applied. This avoids overwriting a later change made by the user or another application.

Public proxies remain untrusted. Do not use them for passwords, banking, payments, private accounts, or confidential work. HTTPS protects request content between the client and destination when certificate validation succeeds, but the proxy operator can still observe connection metadata and the destination. With a plain HTTP proxy, the ISP may also observe the HTTP CONNECT request, including the destination hostname and port. HTTPS encrypts the tunneled application content to the destination, but does not encrypt the client-to-proxy hop when the proxy itself is plain HTTP. An HTTPS proxy can encrypt that hop as well. This application is not a VPN and does not provide DNS leak protection, TUN routing, a kill switch, or a guarantee that the destination is hidden from every observer.

## Supported platforms and limitations

- Windows system-proxy integration currently activates plain HTTP proxy endpoints only.
- HTTPS proxy endpoints may be tested where supported by Python's proxy handler, but system activation is not enabled for them.
- SOCKS4/SOCKS5 endpoints may be catalogued but are not activated or used for web tests in this build.
- Linux system-wide desktop proxy integration is not implemented.
- UDP tunnelling, TUN mode, DNS leak protection, and kill switch are not implemented.
- Country/city geolocation is intentionally omitted; the app does not query a third-party service for exit IP metadata.

## Development

    python -m py_compile core.py
    python -m unittest discover -s tests -v
    python core.py
    python core.py --ui
    python core.py --scan 500

The dashboard uses native browser APIs and has no JavaScript framework or build step.
