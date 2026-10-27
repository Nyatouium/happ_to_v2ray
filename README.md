Happ Config Converter

Convert Happ JSON configs into share-links for v2rayNG, NekoBox, Hiddify, and other clients — no dependencies, just Python + Tkinter.

Happ Config Converter is a standalone desktop application that reads JSON configuration files exported from Happ (and compatible Xray-based clients) and generates properly formatted share-links. The output can be pasted directly into any client that supports the corresponding URI scheme.

The tool is written entirely with Python's standard library — no pip install required.
Features
Protocol Support
Protocol	Transports & Security
VLESS	TCP, WS, gRPC, HTTP, XHTTP · Reality & TLS
VMess	TCP, WS, gRPC
Shadowsocks	SS URI format
Trojan	TLS, WS
Hysteria	TLS, SNI, ALPN, fingerprint
Hysteria2	TLS, SNI, ALPN, insecure
SOCKS	With optional authentication
HTTP	With optional authentication

Protocols that are recognized but not yet supported are listed in the UI with a clear message — they are never silently dropped.
Input Sources

    JSON file exported from Happ

    Pasted JSON text

    Pasted subscription URL (downloaded in a background process)

    JSON arrays containing multiple Xray configs

    A single Xray config

    Base64-encoded JSON (auto-detected)

    Plain share-link lists

User Interface

    Dark, modern Tkinter theme — no external styling libraries

    Protocol filter (VLESS / VMess / Shadowsocks / Trojan / Hysteria / SOCKS / HTTP)

    Live link preview with one-click copy

    Copy selected link, copy all, or save to a .txt file

    Right-click context menu with full clipboard support on every text widget

    Status bar with conversion statistics

Background Subscription Loading

Subscription downloads are performed in a separate child process, so the UI never freezes. The Cancel button performs a hard OS-level terminate() on the worker — including stuck DNS lookups and TLS handshakes.
Installation
Requirements

    Python 3.9 or newer

    Tkinter (included in standard Python distributions on Windows and macOS; on Linux install python3-tk)

Run from source
bash

git clone https://github.com/<your-user>/happ-config-converter.git
cd happ-config-converter
python happ_to_v2ray_v2.py

No pip install is required.
Build a standalone executable (optional)
bash

pip install pyinstaller
pyinstaller --noconsole --onefile happ_to_v2ray_v2.py

Usage

    Launch the application.

    Load a Happ JSON file, paste JSON, or paste a subscription URL.

    Press Convert (or Load Subscription when a URL is in the input field).

    Select entries in the results list.

    Copy a single link, copy all links, or save them to a .txt file.

    Paste the links into your client.

Example

Input (abbreviated Xray config):
json

{
  "outbounds": [
    {
      "protocol": "vless",
      "tag": "MyServer",
      "settings": {
        "vnext": [{
          "address": "example.com",
          "port": 443,
          "users": [{ "id": "uuid-here", "encryption": "none" }]
        }]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": { "serverName": "example.com" },
        "wsSettings": { "path": "/ws", "headers": { "Host": "example.com" } }
      }
    }
  ]
}

Output:
text

vless://uuid-here@example.com:443?encryption=none&type=ws&security=tls&sni=example.com&path=%2Fws&host=example.com#MyServer

Technical Notes

    Base64 handling is whitespace-tolerant and auto-pads input.

    VMess is emitted as a spec-compliant v2 JSON object (base64-encoded).

    Reality parameters (sni, fp, pbk, sid) are preserved.

    XHTTP extra field is passed through as compact JSON.

    Configs are auto-discovered through nested configs / items / data / result / subscriptions containers.

    Duplicate links are deduplicated before being shown.

    Multiprocessing uses the spawn context, so it works correctly on Windows and in frozen executables.

Known Limitations

    HTTP/3 and QUIC transports are not converted.

    Some exotic Reality or XHTTP edge cases may not round-trip perfectly — the parser reports an error in the UI instead of producing a broken link.

    Subscription download timeout is fixed at 30 seconds; cancel at any time via the red Cancel button.

Project Structure
text

happ_to_v2ray_v2.py   # Single-file application
README.md             # This file
LICENSE               # GNU license

Contributing

Issues and pull requests are welcome. When reporting a conversion problem, please include:

    The protocol name

    A redacted minimal config sample (remove UUIDs, passwords, addresses)

    The expected vs. actual output link

License

Released under the GNU License. See LICENSE for details.
Disclaimer

This tool is intended for legitimate use with your own proxy servers and configurations. Users are responsible for complying with local laws and the terms of service of any subscription providers they use.
