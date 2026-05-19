from __future__ import annotations
try:
    from shared.vendors import detect_vendor
except Exception:
    def detect_vendor(text: str) -> str:
        low=(text or '').lower()
        if 'ruckus' in low or 'brocade' in low or 'fastiron' in low: return 'ruckus_icx'
        if 'aos-cx' in low or 'arubaos-cx' in low: return 'aruba_cx'
        if 'procurve' in low or 'image stamp' in low: return 'procurve'
        if 'cisco ios' in low or 'catalyst' in low: return 'cisco_ios'
        if 'tp-link' in low: return 'tplink'
        return 'unknown'
