# -*- coding: utf-8 -*-
"""
Happ JSON -> share-link converter
GUI: dark, modern Tkinter interface, no third-party dependencies.

Supported / detected protocols:
- VLESS (TCP, WS, gRPC, XHTTP, Reality/TLS)
- VMess
- Shadowsocks
- Trojan
- Hysteria / Hysteria2
- SOCKS / HTTP
- Unknown protocols are shown in the status area instead of being silently converted.

The program accepts:
1) a JSON file from Happ;
2) pasted JSON text;
3) a JSON array containing several Xray configs;
4) a single Xray config;
5) a subscription URL (loaded in a background *process*; hard-kill via OS terminate).

The generated links are suitable for copying into clients that support
the corresponding URI/share-link format.
"""

import base64
import json
import os
import re
import socket
import subprocess
import multiprocessing as mp
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from urllib.error import URLError, HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


APP_TITLE = "Happ Config Converter"
BG = "#0f1117"
PANEL = "#171a23"
PANEL2 = "#1d212c"
BORDER = "#2a3040"
TEXT = "#e8ecf4"
MUTED = "#9299aa"
ACCENT = "#7c5cff"
ACCENT_HOVER = "#9178ff"
GREEN = "#42d392"
RED = "#ff6b7a"
ENTRY_BG = "#11141b"


# Kept for compatibility; process-kill path does not raise this in the GUI.
class CancelledError(Exception):
    """Raised when the user cancels a background download."""


def safe_str(value):
    if value is None:
        return ""
    return str(value)


def b64encode_text(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def b64decode_text(text):
    text = re.sub(r"\s+", "", text)
    text += "=" * (-len(text) % 4)
    return base64.b64decode(text).decode("utf-8", errors="replace")


def first_dict(value):
    if isinstance(value, list) and value:
        return value[0] if isinstance(value[0], dict) else {}
    return value if isinstance(value, dict) else {}


def clean_fragment(text):
    return quote(safe_str(text), safe="")


def query(params):
    params = [(k, safe_str(v)) for k, v in params.items() if v is not None and v != ""]
    return urlencode(params, doseq=False, safe="")


def user_from_vnext(outbound):
    settings = outbound.get("settings") or {}
    vnext = first_dict(settings.get("vnext"))
    users = vnext.get("users") or []
    user = first_dict(users)
    return vnext, user


def reality_params(stream):
    r = stream.get("realitySettings") or {}
    return {
        "security": "reality",
        "sni": r.get("serverName", ""),
        "fp": r.get("fingerprint", ""),
        "pbk": r.get("publicKey", ""),
        "sid": r.get("shortId", ""),
    }


def tls_params(stream):
    t = stream.get("tlsSettings") or {}
    p = {}
    if t.get("serverName"):
        p["sni"] = t["serverName"]
    if t.get("fingerprint"):
        p["fp"] = t["fingerprint"]
    if t.get("alpn"):
        p["alpn"] = ",".join(map(str, t["alpn"])) if isinstance(t["alpn"], list) else t["alpn"]
    return p


def convert_vless(outbound, remarks=""):
    vnext, user = user_from_vnext(outbound)
    address = vnext.get("address")
    port = vnext.get("port")
    uid = user.get("id")
    if not address or not port or not uid:
        raise ValueError("VLESS: не найден address/port/id")

    stream = outbound.get("streamSettings") or {}
    network = stream.get("network", "tcp")
    security = stream.get("security", "")
    p = {
        "encryption": user.get("encryption", "none"),
        "flow": user.get("flow", ""),
        "type": network,
    }

    if security == "reality":
        p.update(reality_params(stream))
    elif security:
        p["security"] = security
        if security == "tls":
            p.update(tls_params(stream))
    else:
        p["security"] = "none"

    if network == "ws":
        ws = stream.get("wsSettings") or {}
        if ws.get("path"):
            p["path"] = ws["path"]
        headers = ws.get("headers") or {}
        if headers.get("Host"):
            p["host"] = headers["Host"]

    elif network == "grpc":
        grpc = stream.get("grpcSettings") or {}
        if grpc.get("serviceName"):
            p["serviceName"] = grpc["serviceName"]
        if grpc.get("authority"):
            p["authority"] = grpc["authority"]

    elif network == "http":
        hs = stream.get("httpSettings") or {}
        if hs.get("path"):
            p["path"] = hs["path"]
        hosts = hs.get("host") or []
        if isinstance(hosts, list) and hosts:
            p["host"] = ",".join(map(str, hosts))
        elif hosts:
            p["host"] = hosts

    elif network == "xhttp":
        xs = stream.get("xhttpSettings") or {}
        if xs.get("mode"):
            p["mode"] = xs["mode"]
        if xs.get("path"):
            p["path"] = xs["path"]
        if xs.get("host"):
            p["host"] = xs["host"]
        if "extra" in xs and xs["extra"] not in (None, "", {}):
            p["extra"] = json.dumps(xs["extra"], ensure_ascii=False, separators=(",", ":"))

    return (
        f"vless://{quote(str(uid), safe='')}@{quote(str(address), safe='')}:{port}"
        f"?{query(p)}#{clean_fragment(remarks or outbound.get('tag', 'VLESS'))}"
    )


def convert_vmess(outbound, remarks=""):
    settings = outbound.get("settings") or {}
    servers = settings.get("vnext") or []
    server = first_dict(servers)
    address = server.get("address")
    port = server.get("port")
    users = server.get("users") or []
    user = first_dict(users)

    if not address or not port or not user.get("id"):
        raise ValueError("VMess: не найден address/port/id")

    stream = outbound.get("streamSettings") or {}
    network = stream.get("network", "tcp")
    security = stream.get("security", "auto")

    obj = {
        "v": "2",
        "ps": remarks or outbound.get("tag", "VMess"),
        "add": address,
        "port": str(port),
        "id": user.get("id"),
        "aid": str(user.get("alterId", 0)),
        "scy": user.get("security", "auto"),
        "net": network,
        "type": "none",
        "host": "",
        "path": "",
        "tls": "" if security in ("", "none") else security,
        "sni": "",
    }

    if network == "ws":
        ws = stream.get("wsSettings") or {}
        obj["path"] = ws.get("path", "")
        headers = ws.get("headers") or {}
        obj["host"] = headers.get("Host", "")
    elif network == "grpc":
        grpc = stream.get("grpcSettings") or {}
        obj["path"] = grpc.get("serviceName", "")
        obj["type"] = "gun"

    tls = stream.get("tlsSettings") or {}
    if tls.get("serverName"):
        obj["sni"] = tls["serverName"]

    return "vmess://" + b64encode_text(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))


def convert_shadowsocks(outbound, remarks=""):
    settings = outbound.get("settings") or {}
    servers = settings.get("servers") or []
    server = first_dict(servers)
    address = server.get("address")
    port = server.get("port")
    method = server.get("method", "")
    password = server.get("password", "")

    if not address or not port or not method:
        raise ValueError("Shadowsocks: не найден address/port/method")

    userinfo = f"{method}:{password}"
    encoded = b64encode_text(userinfo)
    link = f"ss://{encoded}@{address}:{port}"
    tag = remarks or outbound.get("tag", "Shadowsocks")
    return link + "#" + clean_fragment(tag)


def convert_trojan(outbound, remarks=""):
    settings = outbound.get("settings") or {}
    servers = settings.get("servers") or []
    server = first_dict(servers)
    address = server.get("address")
    port = server.get("port")
    password = server.get("password")
    if not address or not port or not password:
        raise ValueError("Trojan: не найден address/port/password")

    stream = outbound.get("streamSettings") or {}
    p = {"security": "tls"}
    tls = stream.get("tlsSettings") or {}
    if tls.get("serverName"):
        p["sni"] = tls["serverName"]
    if tls.get("fingerprint"):
        p["fp"] = tls["fingerprint"]
    network = stream.get("network")
    if network and network != "tcp":
        p["type"] = network

    if network == "ws":
        ws = stream.get("wsSettings") or {}
        if ws.get("path"):
            p["path"] = ws["path"]
        host = (ws.get("headers") or {}).get("Host")
        if host:
            p["host"] = host

    tag = remarks or outbound.get("tag", "Trojan")
    suffix = "?" + query(p) if p else ""
    return f"trojan://{quote(str(password), safe='')}@{address}:{port}{suffix}#{clean_fragment(tag)}"


def convert_hysteria2(outbound, remarks=""):
    settings = outbound.get("settings") or {}
    address = settings.get("address", "")
    port = settings.get("port", "")
    auth = settings.get("auth", "")
    if not address or not port:
        raise ValueError("Hysteria2: не найден address/port")

    stream = outbound.get("streamSettings") or {}
    tls = stream.get("tlsSettings") or {}
    p = {}
    if tls.get("serverName"):
        p["sni"] = tls["serverName"]
    if tls.get("alpn"):
        p["alpn"] = ",".join(map(str, tls["alpn"])) if isinstance(tls["alpn"], list) else tls["alpn"]
    if tls.get("insecure") is True:
        p["insecure"] = "1"

    tag = remarks or outbound.get("tag", "Hysteria2")
    return f"hysteria2://{quote(str(auth), safe='')}@{address}:{port}?{query(p)}#{clean_fragment(tag)}"


def convert_hysteria(outbound, remarks=""):
    settings = outbound.get("settings") or {}
    address = settings.get("address", "")
    port = settings.get("port", "")
    hs = (outbound.get("streamSettings") or {}).get("hysteriaSettings") or {}
    auth = hs.get("auth", "")
    tls = (outbound.get("streamSettings") or {}).get("tlsSettings") or {}
    if not address or not port:
        raise ValueError("Hysteria: не найден address/port")
    p = {}
    if tls.get("serverName"):
        p["sni"] = tls["serverName"]
    if tls.get("alpn"):
        p["alpn"] = ",".join(map(str, tls["alpn"])) if isinstance(tls["alpn"], list) else tls["alpn"]
    if tls.get("fingerprint"):
        p["fp"] = tls["fingerprint"]
    if hs.get("version") is not None:
        p["version"] = hs["version"]
    tag = remarks or outbound.get("tag", "Hysteria")
    return f"hysteria://{quote(str(auth), safe='')}@{address}:{port}?{query(p)}#{clean_fragment(tag)}"


def convert_socks(outbound, remarks=""):
    settings = outbound.get("settings") or {}
    servers = settings.get("servers") or []
    s = first_dict(servers)
    address = s.get("address")
    port = s.get("port")
    if not address or not port:
        address = settings.get("address")
        port = settings.get("port")
    if not address or not port:
        raise ValueError("SOCKS: не найден address/port")
    user = s.get("users") or []
    u = first_dict(user)
    username = u.get("user", "")
    password = u.get("pass", "")
    auth = ""
    if username:
        auth = quote(str(username), safe="")
        if password:
            auth += ":" + quote(str(password), safe="")
        auth += "@"
    tag = remarks or outbound.get("tag", "SOCKS")
    return f"socks://{auth}{address}:{port}#{clean_fragment(tag)}"


def convert_http(outbound, remarks=""):
    settings = outbound.get("settings") or {}
    servers = settings.get("servers") or []
    s = first_dict(servers)
    address = s.get("address") or settings.get("address")
    port = s.get("port") or settings.get("port")
    if not address or not port:
        raise ValueError("HTTP: не найден address/port")
    user = s.get("users") or []
    u = first_dict(user)
    username = u.get("user", "")
    password = u.get("pass", "")
    auth = ""
    if username:
        auth = quote(str(username), safe="")
        if password:
            auth += ":" + quote(str(password), safe="")
        auth += "@"
    tag = remarks or outbound.get("tag", "HTTP")
    return f"http://{auth}{address}:{port}#{clean_fragment(tag)}"


CONVERTERS = {
    "vless": convert_vless,
    "vmess": convert_vmess,
    "shadowsocks": convert_shadowsocks,
    "trojan": convert_trojan,
    "hysteria2": convert_hysteria2,
    "hysteria": convert_hysteria,
    "socks": convert_socks,
    "http": convert_http,
}


def normalize_protocol(p):
    p = safe_str(p).lower().strip()
    aliases = {
        "ss": "shadowsocks",
        "shadow": "shadowsocks",
        "hy2": "hysteria2",
        "hysteria2": "hysteria2",
    }
    return aliases.get(p, p)


def walk_configs(data):
    if isinstance(data, dict):
        if isinstance(data.get("outbounds"), list):
            yield data
            return
        for key in ("configs", "items", "data", "result", "subscriptions"):
            value = data.get(key)
            if isinstance(value, (dict, list)):
                yield from walk_configs(value)
    elif isinstance(data, list):
        for item in data:
            yield from walk_configs(item)


def extract_entries(data):
    entries = []
    seen = set()

    for cfg_index, cfg in enumerate(walk_configs(data), 1):
        remarks = cfg.get("remarks", "")
        for outbound in cfg.get("outbounds") or []:
            proto = normalize_protocol(outbound.get("protocol"))
            if proto in ("freedom", "blackhole", "dns", "loopback"):
                continue
            if proto not in CONVERTERS:
                entries.append({
                    "protocol": proto or "unknown",
                    "name": remarks or outbound.get("tag", f"Config {cfg_index}"),
                    "tag": outbound.get("tag", ""),
                    "link": None,
                    "error": f"Протокол пока не поддержан: {proto or 'unknown'}",
                })
                continue

            try:
                link = CONVERTERS[proto](outbound, remarks)
                if link in seen:
                    continue
                seen.add(link)
                entries.append({
                    "protocol": proto,
                    "name": remarks or outbound.get("tag", proto.upper()),
                    "tag": outbound.get("tag", ""),
                    "link": link,
                    "error": "",
                })
            except Exception as exc:
                entries.append({
                    "protocol": proto,
                    "name": remarks or outbound.get("tag", proto.upper()),
                    "tag": outbound.get("tag", ""),
                    "link": None,
                    "error": str(exc),
                })
    return entries


def load_json_text(text):
    text = text.strip()
    if not text:
        raise ValueError("JSON пустой")

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    try:
        decoded = b64decode_text(text)
        return json.loads(decoded)
    except Exception:
        pass

    raise ValueError("Не удалось распознать JSON или Base64(JSON)")



def load_subscription_url(url, timeout=30, progress_cb=None):
    """
    Download a subscription body (runs inside a child process).
    progress_cb is optional and only used when called in-process.
    """
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        raise ValueError("Ожидалась ссылка подписки http:// или https://")

    if progress_cb:
        progress_cb("Подключение…")

    request = Request(
        url,
        headers={
            "User-Agent": "Happ-Config-Converter/1.0",
            "Accept": "*/*",
        },
    )

    with urlopen(request, timeout=timeout) as response:
        total = response.headers.get("Content-Length")
        try:
            total = int(total) if total else None
        except (TypeError, ValueError):
            total = None

        chunks = []
        downloaded = 0
        if progress_cb:
            progress_cb("Скачивание…")

        while True:
            block = response.read(64 * 1024)
            if not block:
                break
            chunks.append(block)
            downloaded += len(block)
            if progress_cb:
                if total and total > 0:
                    pct = min(99, int(downloaded * 100 / total))
                    progress_cb(f"Скачивание… {pct}% ({downloaded // 1024} КБ)")
                else:
                    progress_cb(f"Скачивание… {downloaded // 1024} КБ")

        raw = b"".join(chunks)

    if progress_cb:
        progress_cb("Разбор ответа…")

    text = raw.decode("utf-8-sig", errors="replace").strip()
    if not text:
        raise ValueError("Подписка вернула пустой ответ")

    try:
        return load_json_text(text)
    except ValueError:
        pass

    try:
        decoded = b64decode_text(text).strip()
        if decoded:
            return decoded
    except Exception:
        pass

    return text


def subscription_download_process(url, result_queue, timeout=30):
    """
    Top-level entry for multiprocessing.Process (must be picklable).
    Puts messages into result_queue:
      ("progress", str)
      ("ok", payload)      # payload is str | dict | list
      ("err", str)
    """
    try:
        def progress(msg):
            try:
                result_queue.put(("progress", msg))
            except Exception:
                pass

        payload = load_subscription_url(url, timeout=timeout, progress_cb=progress)
        result_queue.put(("ok", payload))
    except Exception as exc:
        try:
            result_queue.put(("err", str(exc)))
        except Exception:
            pass


def extract_entries_from_subscription_payload(payload):
    if isinstance(payload, (dict, list)):
        return extract_entries(payload)

    text = safe_str(payload).strip()
    if not text:
        return []

    entries = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not re.match(r"^(vless|vmess|ss|trojan|hysteria2?|socks|http)://", line, re.I):
            continue
        proto = line.split("://", 1)[0].lower()
        proto = normalize_protocol(proto)
        if line in seen:
            continue
        seen.add(line)
        entries.append({
            "protocol": proto,
            "name": f"Подписка • {proto.upper()}",
            "tag": "",
            "link": line,
            "error": "",
        })
    return entries


def looks_like_share_links(text):
    if not text:
        return False
    return bool(re.search(r"(?im)^(vless|vmess|ss|trojan|hysteria2?|socks|http)://", text))


def first_http_url(text):
    for line in (text or "").splitlines():
        line = line.strip()
        if re.match(r"^https?://\S+", line, re.I):
            return line.split()[0]
    text = (text or "").strip()
    if re.match(r"^https?://\S+", text, re.I):
        return text.split()[0]
    return None


def copy_to_clipboard(text):
    root = tk._default_root
    if root:
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        return
    try:
        flags = subprocess.CREATE_NO_WINDOW if (os.name == "nt" and hasattr(subprocess, "CREATE_NO_WINDOW")) else 0
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", "Set-Clipboard", "-Value", text],
            check=True,
            creationflags=flags,
        )
    except Exception as exc:
        raise RuntimeError(f"Не удалось скопировать в буфер обмена: {exc}")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1180x760")
        self.minsize(980, 650)
        self.configure(bg=BG)

        self.entries = []
        self.filtered_indices = []

        self._proc = None
        self._queue = None
        self._poll_after_id = None
        self._busy = False
        self._job_id = 0  # bumped on each start/cancel; stale results ignored

        self._configure_style()
        self._build_ui()

    def _configure_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "TCombobox",
            fieldbackground=ENTRY_BG,
            background=PANEL2,
            foreground=TEXT,
            arrowcolor=TEXT,
            bordercolor=BORDER,
            lightcolor=BORDER,
            darkcolor=BORDER,
            padding=8,
        )
        style.map("TCombobox", fieldbackground=[("readonly", ENTRY_BG)])
        style.configure(
            "Accent.Horizontal.TProgressbar",
            troughcolor=ENTRY_BG,
            background=ACCENT,
            bordercolor=BORDER,
            lightcolor=ACCENT,
            darkcolor=ACCENT,
        )

    def _button(self, parent, text, command, primary=False, width=None):
        b = tk.Button(
            parent,
            text=text,
            command=command,
            bg=ACCENT if primary else PANEL2,
            fg="#ffffff" if primary else TEXT,
            activebackground=ACCENT_HOVER if primary else BORDER,
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=14,
            pady=9,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
        )
        if width:
            b.configure(width=width)
        return b

    def _get_clipboard_text(self):
        for getter in (
            lambda: self.clipboard_get(),
            lambda: self.selection_get(selection="CLIPBOARD"),
            lambda: self.selection_get(selection="PRIMARY"),
        ):
            try:
                text = getter()
                if text is not None and str(text).strip() != "":
                    return str(text)
            except Exception:
                pass

        if os.name == "nt":
            try:
                flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=flags,
                )
                if result.returncode == 0 and result.stdout:
                    return result.stdout
            except Exception:
                pass
        return None

    def _setup_text_bindings(self, widget, readonly=False):
        menu = tk.Menu(
            widget, tearoff=0, bg=PANEL2, fg=TEXT,
            activebackground=ACCENT, activeforeground="#ffffff",
        )

        def do_cut():
            try:
                widget.event_generate("<<Cut>>")
            except Exception:
                pass

        def do_copy():
            try:
                widget.event_generate("<<Copy>>")
            except Exception:
                pass

        def do_paste():
            text = self._get_clipboard_text()
            if text is None:
                return
            try:
                try:
                    widget.delete("sel.first", "sel.last")
                except tk.TclError:
                    pass
                widget.insert("insert", text)
            except Exception:
                pass

        def do_select_all():
            widget.tag_add("sel", "1.0", "end-1c")
            widget.mark_set("insert", "1.0")
            widget.see("insert")

        if not readonly:
            menu.add_command(label="Вырезать", command=do_cut)
        menu.add_command(label="Копировать", command=do_copy)
        if not readonly:
            menu.add_command(label="Вставить", command=do_paste)
        menu.add_separator()
        menu.add_command(label="Выделить всё", command=do_select_all)

        def show_menu(event):
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        widget.bind("<Button-3>", show_menu)
        widget.bind("<Button-2>", show_menu)
        widget.bind("<Control-c>", lambda e: (do_copy(), "break")[1])
        widget.bind("<Control-C>", lambda e: (do_copy(), "break")[1])
        widget.bind("<Control-v>", lambda e: (do_paste(), "break")[1])
        widget.bind("<Control-V>", lambda e: (do_paste(), "break")[1])
        if not readonly:
            widget.bind("<Control-x>", lambda e: (do_cut(), "break")[1])
            widget.bind("<Control-X>", lambda e: (do_cut(), "break")[1])
        widget.bind("<Control-a>", lambda e: (do_select_all(), "break")[1])
        widget.bind("<Control-A>", lambda e: (do_select_all(), "break")[1])
        widget.bind("<Control-KeyPress>", self._on_ctrl_key_for_text)
        widget._context_menu = menu

    def _on_ctrl_key_for_text(self, event):
        keycode = getattr(event, "keycode", None)
        widget = event.widget
        if not isinstance(widget, tk.Text):
            return None
        if keycode == 65:  # A
            widget.tag_add("sel", "1.0", "end-1c")
            return "break"
        if keycode == 67:  # C
            try:
                widget.event_generate("<<Copy>>")
            except Exception:
                pass
            return "break"
        if keycode == 86:  # V
            text = self._get_clipboard_text()
            if text is not None:
                try:
                    widget.delete("sel.first", "sel.last")
                except tk.TclError:
                    pass
                try:
                    widget.insert("insert", text)
                except Exception:
                    pass
            return "break"
        if keycode == 88:  # X
            try:
                widget.event_generate("<<Cut>>")
            except Exception:
                pass
            return "break"
        return None

    def _build_ui(self):
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=24, pady=(20, 10))

        tk.Label(
            header, text="Happ Config Converter", bg=BG, fg=TEXT,
            font=("Segoe UI", 22, "bold"),
        ).pack(side="left")

        tk.Label(
            header,
            text="JSON → VLESS • VMess • Shadowsocks • Trojan • Hysteria • и другие",
            bg=BG, fg=MUTED, font=("Segoe UI", 10),
        ).pack(side="left", padx=18, pady=(7, 0))

        toolbar = tk.Frame(self, bg=BG)
        toolbar.pack(fill="x", padx=24, pady=(0, 12))

        self._btn_open = self._button(toolbar, "📂 Открыть JSON", self.open_file)
        self._btn_open.pack(side="left", padx=(0, 8))
        self._btn_paste = self._button(toolbar, "📋 Вставить JSON/ссылку", self.paste_json)
        self._btn_paste.pack(side="left", padx=(0, 8))
        self._btn_sub = self._button(toolbar, "🌐 Загрузить подписку", self.load_subscription)
        self._btn_sub.pack(side="left", padx=(0, 8))
        self._btn_convert = self._button(toolbar, "⚡ Конвертировать", self.convert_text, primary=True)
        self._btn_convert.pack(side="left", padx=(0, 16))

        tk.Label(toolbar, text="Фильтр:", bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(side="left")
        self.protocol_var = tk.StringVar(value="AUTO — все протоколы")
        self.protocol_box = ttk.Combobox(
            toolbar, textvariable=self.protocol_var, state="readonly", width=25,
            values=[
                "AUTO — все протоколы", "VLESS", "VMess", "Shadowsocks",
                "Trojan", "Hysteria2", "Hysteria", "SOCKS", "HTTP",
            ],
        )
        self.protocol_box.pack(side="left", padx=8)
        self.protocol_box.bind("<<ComboboxSelected>>", lambda e: self.refresh_list())

        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True, padx=24, pady=(0, 14))
        main.columnconfigure(0, weight=4)
        main.columnconfigure(1, weight=6)
        main.rowconfigure(0, weight=1)

        left = tk.Frame(main, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        left.rowconfigure(1, weight=1)
        left.columnconfigure(0, weight=1)

        tk.Label(
            left, text="Исходный JSON или URL подписки", bg=PANEL, fg=TEXT,
            font=("Segoe UI", 12, "bold"),
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 8))

        self.input_text = tk.Text(
            left, bg=ENTRY_BG, fg=TEXT, insertbackground=TEXT,
            selectbackground=ACCENT, relief="flat", bd=0, wrap="none",
            font=("Cascadia Mono", 9), padx=12, pady=12, undo=True,
        )
        self.input_text.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self._setup_text_bindings(self.input_text)

        right = tk.Frame(main, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        right.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        right.rowconfigure(2, weight=1)
        right.columnconfigure(0, weight=1)

        top = tk.Frame(right, bg=PANEL)
        top.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))

        tk.Label(top, text="Результаты", bg=PANEL, fg=TEXT, font=("Segoe UI", 12, "bold")).pack(side="left")
        self.count_label = tk.Label(top, text="0 ссылок", bg=PANEL, fg=MUTED, font=("Segoe UI", 9))
        self.count_label.pack(side="left", padx=10)

        actions = tk.Frame(right, bg=PANEL)
        actions.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))
        self._button(actions, "⧉ Копировать выбранную", self.copy_selected).pack(side="left", padx=(0, 7))
        self._button(actions, "⧉ Копировать все", self.copy_all).pack(side="left", padx=(0, 7))
        self._button(actions, "💾 Сохранить .txt", self.save_txt).pack(side="left")

        list_frame = tk.Frame(right, bg=PANEL)
        list_frame.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 8))
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)

        self.listbox = tk.Listbox(
            list_frame, bg=ENTRY_BG, fg=TEXT, selectbackground=ACCENT,
            selectforeground="white", activestyle="none", relief="flat",
            bd=0, font=("Segoe UI", 10),
        )
        self.listbox.grid(row=0, column=0, sticky="nsew")
        scroll = tk.Scrollbar(list_frame, command=self.listbox.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.listbox.configure(yscrollcommand=scroll.set)
        self.listbox.bind("<<ListboxSelect>>", self.show_selected)

        tk.Label(
            right, text="Предпросмотр ссылки", bg=PANEL, fg=MUTED, font=("Segoe UI", 9),
        ).grid(row=3, column=0, sticky="w", padx=16, pady=(4, 5))

        self.preview = tk.Text(
            right, height=5, bg=ENTRY_BG, fg=GREEN, insertbackground=TEXT,
            relief="flat", bd=0, wrap="word", font=("Cascadia Mono", 9),
            padx=12, pady=10,
        )
        self.preview.grid(row=4, column=0, sticky="ew", padx=12, pady=(0, 12))
        self._setup_text_bindings(self.preview)

        footer = tk.Frame(self, bg=BG)
        footer.pack(fill="x", padx=24, pady=(0, 6))

        self.status_var = tk.StringVar(value="Готово. Откройте JSON Happ или вставьте его сюда.")
        tk.Label(
            footer, textvariable=self.status_var, bg=BG, fg=MUTED,
            font=("Segoe UI", 9), anchor="w",
        ).pack(side="left", fill="x", expand=True)

        self._btn_cancel = tk.Button(
            footer, text="⏹ Отмена", command=self.cancel_work,
            bg=RED, fg="#ffffff", activebackground="#ff8a95",
            activeforeground="#ffffff", relief="flat", bd=0,
            padx=12, pady=4, cursor="hand2", font=("Segoe UI", 9, "bold"),
        )

        tk.Label(
            footer, text="Автоопределение протокола", bg=BG, fg=GREEN,
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right")

        progress_row = tk.Frame(self, bg=BG)
        progress_row.pack(fill="x", padx=24, pady=(0, 14))
        self.progress = ttk.Progressbar(
            progress_row, mode="indeterminate",
            style="Accent.Horizontal.TProgressbar", length=200,
        )
        # hidden until busy

    def _set_busy(self, busy, message=None):
        self._busy = busy
        state = "disabled" if busy else "normal"
        for btn in (self._btn_open, self._btn_paste, self._btn_sub, self._btn_convert):
            try:
                btn.configure(state=state)
            except Exception:
                pass

        if busy:
            self.progress.pack(fill="x")
            self.progress.start(12)
            try:
                self._btn_cancel.pack_forget()
            except Exception:
                pass
            self._btn_cancel.pack(side="right", padx=(8, 12))
            if message:
                self.status_var.set(message)
        else:
            try:
                self.progress.stop()
            except Exception:
                pass
            self.progress.pack_forget()
            try:
                self._btn_cancel.pack_forget()
            except Exception:
                pass
            if message:
                self.status_var.set(message)

    def cancel_work(self):
        """
        Hard-cancel: OS-level terminate of the download process + instant UI reset.
        Repeated clicks re-issue terminate/kill.
        """
        if not self._busy and self._proc is None:
            return

        self._job_id += 1
        self._stop_poll()
        self._kill_download_process()

        self.entries = []
        self.refresh_list()
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", "⏹ Загрузка отменена пользователем")
        self._set_busy(False, "Загрузка отменена")

    def _stop_poll(self):
        if self._poll_after_id is not None:
            try:
                self.after_cancel(self._poll_after_id)
            except Exception:
                pass
            self._poll_after_id = None

    def _kill_download_process(self):
        proc = self._proc
        self._proc = None
        q = self._queue
        self._queue = None
        if proc is None:
            return
        try:
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=0.4)
            if proc.is_alive():
                try:
                    proc.kill()
                except Exception:
                    pass
                proc.join(timeout=0.3)
        except Exception:
            pass
        # Drain queue so it can be GC'd
        if q is not None:
            try:
                while True:
                    q.get_nowait()
            except Exception:
                pass


    def _ui_from_thread(self, fn):
        self.after(0, fn)

    def open_file(self):
        if self._busy:
            return
        path = filedialog.askopenfilename(
            title="Выберите JSON Happ",
            filetypes=[
                ("JSON / TXT", "*.json *.txt"),
                ("JSON", "*.json"),
                ("TXT", "*.txt"),
                ("Все файлы", "*.*"),
            ],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                text = f.read()
            self.input_text.delete("1.0", "end")
            self.input_text.insert("1.0", text)
            self.status_var.set(f"Загружен файл: {os.path.basename(path)}")
            # Do not auto-convert; user presses «Конвертировать»
        except Exception as exc:
            messagebox.showerror("Ошибка открытия", str(exc))

    def paste_json(self):
        """Only paste clipboard text into the input field — no auto load/convert."""
        if self._busy:
            return
        text = self._get_clipboard_text()
        if text is None or not str(text).strip():
            messagebox.showwarning("Буфер обмена", "В буфере обмена нет текста.")
            return
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", text)
        self.status_var.set("Текст вставлен. Нажмите «Конвертировать» или «Загрузить подписку».")

    def load_subscription(self):
        if self._busy:
            return
        text = self.input_text.get("1.0", "end").strip()
        url = first_http_url(text)
        if not url:
            self._show_invalid("Нет URL подписки (http:// или https://) в поле слева.")
            return
        self._start_subscription_download(url)

    def convert_text(self):
        if self._busy:
            return
        text = self.input_text.get("1.0", "end").strip()
        if not text:
            self._show_invalid("Пустой ввод. Вставьте JSON, Base64 или share-ссылки.")
            return
        self._process_local(text)

    def _show_invalid(self, message):
        self.entries = []
        self.refresh_list()
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", "⚠ " + message)
        self.status_var.set("Неверный формат данных")
        self.count_label.configure(text="0 найдено • 0 ссылок")

    def _process_local(self, text):
        """Local-only processing (no network). URLs are not fetched here."""
        text = (text or "").strip()
        if not text:
            self._show_invalid("Пустой ввод")
            return

        # If user hit Convert with only a URL — hint to use Load Subscription
        url = first_http_url(text)
        if url and re.match(r"^https?://\S+$", text.strip(), re.I):
            self._show_invalid(
                "Это URL подписки. Нажмите «🌐 Загрузить подписку», чтобы скачать её."
            )
            return

        if looks_like_share_links(text):
            entries = extract_entries_from_subscription_payload(text)
            if entries:
                self.entries = entries
                self.refresh_list()
                supported = sum(1 for x in self.entries if x["link"])
                self.status_var.set(f"Найдено готовых ссылок: {supported}")
                return

        try:
            decoded = b64decode_text(text).strip()
            if looks_like_share_links(decoded):
                entries = extract_entries_from_subscription_payload(decoded)
                if entries:
                    self.entries = entries
                    self.refresh_list()
                    supported = sum(1 for x in self.entries if x["link"])
                    self.status_var.set(f"Найдено готовых ссылок (Base64): {supported}")
                    return
        except Exception:
            pass

        try:
            data = load_json_text(text)
        except ValueError:
            self._show_invalid("Неверный формат данных")
            return

        try:
            self.entries = extract_entries(data)
            self.refresh_list()
            supported = sum(1 for x in self.entries if x["link"])
            errors = len(self.entries) - supported
            if not self.entries:
                self._show_invalid("В данных нет поддерживаемых конфигураций")
                return
            self.status_var.set(
                f"Найдено: {len(self.entries)} конфигураций • успешно: {supported} • проблем: {errors}"
            )
        except Exception as exc:
            self._show_invalid(f"Ошибка разбора: {exc}")

    def _start_subscription_download(self, url):
        if self._busy:
            return

        self._job_id += 1
        job_id = self._job_id
        self._stop_poll()
        self._kill_download_process()

        # Spawn a child process so Cancel can OS-terminate it (DNS/TLS included)
        ctx = mp.get_context("spawn")
        queue = ctx.Queue()
        proc = ctx.Process(
            target=subscription_download_process,
            args=(url, queue, 30),
            daemon=True,
        )
        self._queue = queue
        self._proc = proc
        self._set_busy(True, f"Загрузка подписки… {url[:60]}")
        try:
            proc.start()
        except Exception as exc:
            self._proc = None
            self._queue = None
            self._set_busy(False, "Ошибка запуска")
            self._show_invalid(f"Не удалось запустить загрузку: {exc}")
            return

        self._poll_download(job_id)

    def _poll_download(self, job_id):
        """Poll the child-process queue on the Tk main thread."""
        if job_id != self._job_id:
            return

        queue = self._queue
        proc = self._proc

        # Consume all pending messages
        if queue is not None:
            while True:
                try:
                    kind, data = queue.get_nowait()
                except Exception:
                    break
                if job_id != self._job_id:
                    return
                if kind == "progress":
                    self.status_var.set(str(data))
                elif kind == "ok":
                    self._stop_poll()
                    self._kill_download_process()
                    try:
                        entries = extract_entries_from_subscription_payload(data)
                    except Exception as exc:
                        self._set_busy(False, "Ошибка разбора")
                        self._show_invalid(str(exc))
                        return
                    self.entries = entries
                    self.refresh_list()
                    supported = sum(1 for x in self.entries if x["link"])
                    errors = len(self.entries) - supported
                    if not self.entries:
                        self._show_invalid("Подписка загружена, но конфигураций не найдено")
                    else:
                        self.status_var.set(
                            f"Подписка загружена: {len(self.entries)} • успешно: {supported} • проблем: {errors}"
                        )
                    self._set_busy(False)
                    return
                elif kind == "err":
                    self._stop_poll()
                    self._kill_download_process()
                    self._set_busy(False, "Ошибка загрузки")
                    self._show_invalid(str(data))
                    return

        # Process died without a final message (terminated or crashed)
        if proc is not None and not proc.is_alive():
            exitcode = proc.exitcode
            self._stop_poll()
            self._kill_download_process()
            if job_id != self._job_id:
                return
            if not self._busy:
                # UI already reset by cancel_work()
                return
            # Still busy → unexpected death
            self._set_busy(False, "Ошибка загрузки")
            if exitcode in (None, 0):
                self._show_invalid("Процесс загрузки завершился без данных")
            else:
                self._show_invalid(f"Процесс загрузки аварийно завершён (код {exitcode})")
            return

        self._poll_after_id = self.after(80, lambda: self._poll_download(job_id))


    def selected_filter(self):
        value = self.protocol_var.get()
        if value.startswith("AUTO"):
            return None
        return normalize_protocol(value)

    def refresh_list(self):
        self.listbox.delete(0, "end")
        filt = self.selected_filter()
        self.filtered_indices = []

        for i, item in enumerate(self.entries):
            if filt and item["protocol"] != filt:
                continue
            self.filtered_indices.append(i)
            icon = {
                "vless": "🔵", "vmess": "🟣", "shadowsocks": "🟠",
                "trojan": "🔴", "hysteria2": "🟢", "hysteria": "🟢",
                "socks": "⚪", "http": "⚪",
            }.get(item["protocol"], "⚫")
            label = f"{icon} {item['protocol'].upper():12}  {item['name']}"
            if item["error"]:
                label += "  ⚠"
            self.listbox.insert("end", label)

        ok = sum(1 for i in self.filtered_indices if self.entries[i]["link"])
        self.count_label.configure(text=f"{len(self.filtered_indices)} найдено • {ok} ссылок")
        self.preview.delete("1.0", "end")

    def show_selected(self, _event=None):
        sel = self.listbox.curselection()
        if not sel:
            return
        idx = self.filtered_indices[sel[0]]
        item = self.entries[idx]
        self.preview.delete("1.0", "end")
        if item["link"]:
            self.preview.insert("1.0", item["link"])
            self.status_var.set(f"Выбрано: {item['protocol'].upper()} • {item['name']}")
        else:
            self.preview.insert("1.0", "⚠ " + item["error"])
            self.status_var.set(f"Не удалось создать ссылку: {item['error']}")

    def copy_selected(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showinfo("Выбор", "Выберите конфигурацию в списке.")
            return
        idx = self.filtered_indices[sel[0]]
        link = self.entries[idx]["link"]
        if not link:
            messagebox.showwarning("Нельзя скопировать", self.entries[idx]["error"])
            return
        copy_to_clipboard(link)
        self.status_var.set("✓ Ссылка скопирована в буфер обмена — можно Ctrl+V в NekoBox/v2rayNG.")

    def copy_all(self):
        links = [
            self.entries[i]["link"]
            for i in self.filtered_indices
            if self.entries[i]["link"]
        ]
        if not links:
            messagebox.showinfo("Нет ссылок", "Нет успешно сконвертированных ссылок.")
            return
        copy_to_clipboard("\n".join(links))
        self.status_var.set(f"✓ Скопировано {len(links)} ссылок.")

    def save_txt(self):
        links = [
            self.entries[i]["link"]
            for i in self.filtered_indices
            if self.entries[i]["link"]
        ]
        if not links:
            messagebox.showinfo("Нет ссылок", "Нет ссылок для сохранения.")
            return
        path = filedialog.asksaveasfilename(
            title="Сохранить ссылки",
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("Все файлы", "*.*")],
            initialfile="happ_links.txt",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(links))
            self.status_var.set(f"✓ Сохранено: {path}")
        except Exception as exc:
            messagebox.showerror("Ошибка сохранения", str(exc))


if __name__ == "__main__":
    # Required on Windows for multiprocessing spawn + frozen executables
    mp.freeze_support()
    app = App()
    app.mainloop()
