"""Vendor detection helpers for supported switch families.

This package is the active `shared.vendors` import target.  Keep vendor
identification here so MAC Trace, Port Map, Switch Health, Compliance,
Evidence Pack, and future tools use the same detection rules.
"""

from __future__ import annotations

import re
from typing import Optional

from shared.models import Vendor, VendorDetection

try:
    from shared.hp_models import is_hp_aruba_model_text, enrich_from_text, observe_hp_model_text
except Exception:  # pragma: no cover
    def is_hp_aruba_model_text(_text: str) -> bool: return False
    def enrich_from_text(_text: str) -> dict: return {}
    def observe_hp_model_text(_text: str) -> None: return None

try:
    from shared.extreme_exos import detect as detect_extreme_exos
except Exception:  # pragma: no cover
    def detect_extreme_exos(_text: str) -> bool: return False

_HOSTNAME_PATTERNS = [
    re.compile(r"^\s*hostname\s+([A-Za-z0-9_.:-]+)", re.I | re.M),
    re.compile(r"^\s*System Name\s*[:=]\s*(\S+)", re.I | re.M),
    re.compile(r"^\s*SysName\s*[:=]\s*(\S+)", re.I | re.M),
    re.compile(r"^\s*Device Name\s*[:=]\s*(\S+)", re.I | re.M),
    re.compile(r"(?m)^\s*\*?\s*([A-Za-z0-9_.-]+)(?:\.\d+)?\s*[#>]\s*$"),
]


def _all_text(raw_text: str = "", *args, **kwargs) -> str:
    pieces = [raw_text or ""]
    pieces.extend(str(a) for a in args if a is not None)
    pieces.extend(str(v) for v in kwargs.values() if v is not None)
    return "\n".join(pieces)


def _looks_like_procurve_run_header(text: str) -> bool:
    s = text or ""
    return bool(
        re.search(r"(?im)^\s*;\s*(?:HP\s*)?J\d{4}[A-Z]\b.*Configuration Editor", s)
        or re.search(r"(?im)^\s*;\s*(?:HP\s*)?J\d{4}[A-Z]\b.*release\s+#?[A-Z]{1,3}\.\d+\.\d+", s)
        or re.search(r"(?im)^\s*;\s*Created on release\s+#?[A-Z]{1,3}\.\d+\.\d+", s)
        or is_hp_aruba_model_text(s)
    )


def _looks_like_procurve_show_system(text: str) -> bool:
    s = (text or "").lower()
    return (
        "status and counters - general system information" in s
        or ("software revision" in s and "rom version" in s)
        or ("allow v2 modules" in s and "mac age time" in s)
        or ("ip mgmt" in s and "pkts rx" in s and "pkts tx" in s)
        or is_hp_aruba_model_text(text)
    )


def detect_vendor(raw_text: str = "", *args, **kwargs) -> VendorDetection:
    text = _all_text(raw_text, *args, **kwargs)
    if not text:
        text = kwargs.get("version") or kwargs.get("text") or kwargs.get("raw_text") or ""
    lower = text.lower()

    detection = VendorDetection(raw_evidence=text[:5000])
    detection.hostname = extract_hostname(text)
    detection.version = extract_version(text)
    detection.model = extract_model(text)

    if detect_extreme_exos(text) or "extremexos" in lower or "switch engine" in lower or "extreme networks" in lower:
        detection.vendor = Vendor.EXTREME_EXOS
        detection.confidence = 0.96
    elif "ruckus networks" in lower or "brocade communications" in lower or re.search(r"\bicx\s*\d{4}\b", lower):
        detection.vendor = Vendor.RUCKUS_ICX
        detection.confidence = 0.95
    elif "aos-cx" in lower or "arubaos-cx" in lower or "service os version" in lower:
        detection.vendor = Vendor.ARUBA_CX
        detection.confidence = 0.95
    elif _looks_like_procurve_run_header(text) or _looks_like_procurve_show_system(text) or "procurve" in lower or "hewlett-packard company" in lower or re.search(r"\b(y[akb]|wc|kb)\.\d{2}\.\d{2}\.\d{4}\b", lower, re.I):
        detection.vendor = Vendor.PROCURVE
        detection.confidence = 0.92
    elif "cisco ios software" in lower or "catalyst" in lower or "cisco systems" in lower:
        detection.vendor = Vendor.CISCO_IOS
        detection.confidence = 0.95
    elif "tp-link" in lower or "tplink" in lower or "jetstream" in lower or "media converter" in lower:
        detection.vendor = Vendor.TPLINK_MEDIA_PANEL
        detection.confidence = 0.85
    else:
        detection.vendor = Vendor.UNKNOWN
        detection.confidence = 0.0

    if detection.vendor == Vendor.PROCURVE:
        try:
            observe_hp_model_text(text)
            info = enrich_from_text(text)
            if info and not detection.model:
                detection.model = info.get("model") or detection.model
        except Exception:
            pass

    detection.central_connected = detect_aruba_central_connected(text)
    return detection


def detect_aruba_central_connected(raw_text: str) -> Optional[bool]:
    lower = (raw_text or "").lower()
    if "central connection status" not in lower and "aruba central" not in lower:
        return None
    if re.search(r"central connection status\s*:\s*connected", lower):
        return True
    if re.search(r"central connection status\s*:\s*(disconnected|not connected|disabled)", lower):
        return False
    return None


def extract_hostname(raw_text: str) -> Optional[str]:
    for pattern in _HOSTNAME_PATTERNS:
        match = pattern.search(raw_text or "")
        if match:
            return match.group(1).strip().strip('"')
    return None


def extract_version(raw_text: str) -> Optional[str]:
    patterns = [
        r"ExtremeXOS\s+version\s+([\w.()_-]+)",
        r"Image\s*:\s*ExtremeXOS\s+version\s+([\w.()_-]+)",
        r"SW:\s*Version\s*([\w.()_-]+)",
        r"AOS-CX\s+Version\s+([\w.()_-]+)",
        r"Cisco IOS Software.*?Version\s+([^,\s]+)",
        r"Image stamp:\s*.*?([A-Z]{1,3}\.\d{2}\.\d{2}\.\d{4})",
        r"Software revision\s*[:=]\s*([\w.()_-]+)",
        r"release\s+#?([A-Z]{1,3}\.\d+\.\d+(?:\.\d+)?)",
        r"Version\s*[:=]?\s*([\w.()_-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, raw_text or "", re.I | re.S)
        if match:
            return match.group(1).strip()
    return None


def extract_model(raw_text: str) -> Optional[str]:
    patterns = [
        r"System Type\s*[:=]\s*([^\r\n]+)",
        r"\b(X\d{3,4}[A-Za-z0-9_-]*)\b",
        r"\b(ICX\s?\d{4}[A-Za-z0-9_-]*)\b",
        r"\b(J\d{4}[A-Z])\b",
        r"Model\s*[:=]\s*([^\r\n]+)",
        r"Product\s+Name\s*[:=]\s*([^\r\n]+)",
        r"cisco\s+([A-Z0-9-]+)\s+\(",
    ]
    for pattern in patterns:
        match = re.search(pattern, raw_text or "", re.I)
        if match:
            return match.group(1).strip()
    return None
