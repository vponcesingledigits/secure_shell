from __future__ import annotations

import re

MAC_COMPACT_RE = re.compile(r"^[0-9a-fA-F]{12}$")
PORT_TOKEN_RE = re.compile(r"^[A-Za-z0-9_./:-]+$")
PORT_NAME_RE = re.compile(r"^[A-Za-z0-9_ .:/#()\-]{1,64}$")

def normalize_mac_strict(mac: str) -> str:
    compact = re.sub(r"[^0-9a-fA-F]", "", mac or "").lower()
    if not MAC_COMPACT_RE.fullmatch(compact):
        raise ValueError("Invalid MAC address. Use 12 hex digits, colon, hyphen, or dotted format.")
    return compact

def mac_formats(mac: str) -> dict[str, str]:
    c = normalize_mac_strict(mac)
    return {
        "compact": c,
        "dot": f"{c[0:4]}.{c[4:8]}.{c[8:12]}",
        "colon": ":".join(c[i:i+2] for i in range(0, 12, 2)),
        "dash6": f"{c[0:6]}-{c[6:12]}",
        "dash4": f"{c[0:4]}-{c[4:8]}-{c[8:12]}",
    }

def validate_port_token(port: str) -> str:
    p = str(port or "").strip()
    if not p:
        return ""
    if not PORT_TOKEN_RE.fullmatch(p):
        raise ValueError(f"Invalid interface/port value: '{p}'")
    return p

def sanitize_cli_label(value: str, max_len: int = 64) -> str:
    text = " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())[:max_len]
    if text and not PORT_NAME_RE.fullmatch(text):
        text = re.sub(r"[^A-Za-z0-9_ .:/#()\-]", "_", text)[:max_len]
    return text
