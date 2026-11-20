# ProxyDeck

ProxyDeck is a lightweight, local-first workspace for discovering, testing, filtering, and managing public proxy endpoints. It combines a Python core, an interactive terminal interface, and a browser-based dashboard served only from the local machine.

> Public proxies are untrusted infrastructure. ProxyDeck measures reachability and service compatibility; it does not certify anonymity, privacy, or operator trust.

## Features

- Aggregate public proxy lists from multiple independent sources.
- Deduplicate endpoints and retain previously discovered entries when a source temporarily disappears.
- Test saved endpoints again without downloading the source lists.
- Measure TCP connection time separately from end-to-end HTTPS response time through the proxy.
- Check basic reachability for YouTube, Gemini, and a general web endpoint.
- Filter by country, protocol, status, and tested service; sort by measured latency.
- Inspect and connect to supported HTTP proxies, then restore the original Windows per-user proxy settings.
- Use the same Python core from the terminal or the local web dashboard.
- Resize dashboard columns; widths are remembered by the browser.

## Quick start

### Windows

1. Install Python 3.10 or newer.
2. Run RUN-WINDOWS.cmd to start the dashboard without leaving a visible console window.
3. Run CLI-WINDOWS.cmd to open the interactive terminal menu.

The launcher prefers the MSYS2 UCRT Python installation at C:\msys64\ucrt64\bin\python.exe when present, then falls back to Python on PATH. The GUI launcher uses pythonw.exe to avoid an attached console window.

### Linux

    chmod +x run-linux.sh cli-linux.sh
    ./run-linux.sh
    # or
    ./cli-linux.sh

The web dashboard listens on 127.0.0.1:8765; it is not exposed to the LAN.

## Terminal commands

The interactive CLI provides:

1. Refresh public sources and test newly discovered endpoints.
2. Re-test all endpoints already stored locally.
3. Show saved proxies sorted by measured web response time.
4. Connect to an online HTTP proxy.
5. Disconnect and restore the previous proxy settings.
6. Open the local dashboard.

The terminal list includes compact service tags such as web, youtube, and gemini. After selecting a proxy, the screen is redrawn and the active endpoint is displayed in the header.

## Measurements

| Field | Meaning |
|---|---|
| TCP | Time to establish a TCP connection to the proxy endpoint. This is not ICMP ping. |
| Web | Time to complete an HTTPS request through the proxy to a test endpoint. |
| YouTube / Gemini / Web | Independent reachability checks; not a guarantee of sign-in, playback, or every route. |
| Country / city | Approximate geolocation of the observed exit IP; may be unavailable or inaccurate. |
| Last checked | Local timestamp of the most recent test. |

A low TCP time does not necessarily mean fast browsing. The end-to-end Web measurement is generally more representative of actual use, and both can vary with congestion, routing, and endpoint load.

## Sources

The source list is maintained in core.py and currently includes these upstream projects:

| Provider | Repository |
|---|---|
| HProxy | https://github.com/hproxy-com/free-proxy-list |
| FusionProxies | https://github.com/FusionProxies/free-proxy-list |
| Moleway | https://github.com/Moleway/Free-Proxy-List |
| proxy-free | https://github.com/proxy-free/free-proxy-list |
| iPlocate | https://github.com/iplocate/free-proxy-list |
| Thordata | https://github.com/Thordata/awesome-free-proxy-list |
| Databay | https://github.com/databay-labs/free-proxy-list |
| Dahono | https://github.com/Dahono-com/free-proxy-list |

Source downloads bypass the currently configured public proxy and use normal TLS certificate verification. The scanner does not disable certificate checks.

Source lists are community-maintained and can change, disappear, or contain dead and misclassified endpoints. The default refresh tests up to 500 unique candidates. You can increase this limit with:

    python core.py --scan 1000

The catalogue is stored locally in proxies.json; runtime connection state is stored in state.json. These runtime files are intentionally excluded from source control.

## Supported platforms and limitations

- The Windows system-proxy integration currently activates plain HTTP proxy endpoints through the current user's Internet Settings.
- HTTPS proxy transport and SOCKS endpoints may be catalogued, but are not activated by this build.
- Linux system-wide desktop proxy integration is not implemented yet.
- UDP tunnelling, TUN mode, DNS leak protection, kill switch, and VPN routing are not implemented.
- A public proxy does not encrypt traffic by itself and does not provide the security guarantees of a reputable VPN.
- MAC address and Windows Region changes are deliberately outside the scope of this project.

## Security and privacy

Treat every public proxy as untrusted. Do not use one for passwords, banking, payment, private accounts, or confidential work. Never install a certificate supplied by a proxy operator.

HTTPS protects the content exchanged with the destination when certificate validation succeeds, but the proxy operator can still observe connection metadata such as destination IP/domain in some circumstances, timing, and traffic volume. A successful test only demonstrates that a particular request worked at that moment.

ProxyDeck runs its local API on loopback and does not require administrator privileges, third-party Python packages, custom root certificates, or network-driver installation.

## Development

    python -m py_compile core.py
    python core.py
    python core.py --ui

The dashboard uses native browser APIs and has no JavaScript framework or build step.
