from __future__ import annotations

import re
from typing import Iterable

ROLE_SWITCH = "switch"
ROLE_AP = "access_point"
ROLE_FIREWALL = "firewall"
ROLE_GATEWAY = "gateway"
ROLE_ROUTER = "router"
ROLE_PHONE = "phone"
ROLE_CAMERA = "camera"
ROLE_SERVER = "server"
ROLE_PRINTER = "printer"
ROLE_CONTROLLER = "controller"
ROLE_UPS = "ups"
ROLE_UNKNOWN = "unknown"

SWITCH_HINTS = [
    "switch", "icx", "ruckus icx", "procurve", "aruba", "aos-cx", "cisco ios",
    "catalyst", "extremexos", "extreme networks", "tp-link", "jetstream", "j9", "j985", "j914"
]
AP_HINTS = ["wireless ap", "ruckus h", "ruckus r", "zoneflex", "unleashed", "access point", "ap/sw", "wifi", "802.11"]
FIREWALL_HINTS = ["watchguard", "fortinet", "fortigate", "pfsense", "juniper srx", "palo alto", "firewall"]
GATEWAY_HINTS = ["nomadix", "gateway", "gw0", "gw1", "gw-"]
ROUTER_HINTS = ["router", "mikrotik", "cisco isr", "juniper mx", "edge router"]
PHONE_HINTS = ["phone", "polycom", "yealink", "mitel", "avaya", "cisco ip phone", "voip"]
CAMERA_HINTS = ["camera", "axis", "hikvision", "dahua", "cctv", "nvr"]
SERVER_HINTS = ["esxi", "vmware", "idrac", "ilo", "server", "poweredge", "proliant"]
PRINTER_HINTS = ["printer", "xerox", "hp laser", "canon"]
UPS_HINTS = ["ups", "apc", "eaton", "tripp lite"]
CONTROLLER_HINTS = ["smartzone", "controller", "wlc"]


def _contains_any(text: str, hints: Iterable[str]) -> bool:
    text = (text or "").lower()
    return any(h.lower() in text for h in hints)


def classify_lldp_neighbor(system_name: str = "", description: str = "", port_description: str = "", capabilities: Iterable[str] | None = None) -> str:
    blob = " ".join([system_name or "", description or "", port_description or "", " ".join(capabilities or [])]).lower()
    caps = {str(c).lower() for c in (capabilities or [])}

    # A remote port description of eth0 is a strong clue for APs, but not absolute.
    if re.fullmatch(r"eth\d+", (port_description or "").strip().lower()) and _contains_any(blob, AP_HINTS):
        return ROLE_AP
    if _contains_any(blob, AP_HINTS):
        return ROLE_AP
    if "bridge" in caps and "wlan" not in blob and _contains_any(blob, SWITCH_HINTS):
        return ROLE_SWITCH
    if _contains_any(blob, SWITCH_HINTS):
        return ROLE_SWITCH
    if _contains_any(blob, FIREWALL_HINTS):
        return ROLE_FIREWALL
    if _contains_any(blob, GATEWAY_HINTS):
        return ROLE_GATEWAY
    if _contains_any(blob, ROUTER_HINTS) or "router" in caps:
        return ROLE_ROUTER
    if _contains_any(blob, PHONE_HINTS) or "telephone" in caps:
        return ROLE_PHONE
    if _contains_any(blob, CAMERA_HINTS):
        return ROLE_CAMERA
    if _contains_any(blob, SERVER_HINTS):
        return ROLE_SERVER
    if _contains_any(blob, PRINTER_HINTS):
        return ROLE_PRINTER
    if _contains_any(blob, UPS_HINTS):
        return ROLE_UPS
    if _contains_any(blob, CONTROLLER_HINTS):
        return ROLE_CONTROLLER
    return ROLE_UNKNOWN


def role_is_visible(role: str, include_aps: bool = False, include_all_devices: bool = False) -> bool:
    if include_all_devices:
        return True
    if role == ROLE_SWITCH:
        return True
    if role == ROLE_AP and include_aps:
        return True
    return False
