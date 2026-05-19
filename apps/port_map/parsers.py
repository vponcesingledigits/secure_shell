from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional

from .models import LldpNeighbor, MacEntry, PortRecord, SwitchScan

PORT_PATTERNS = {
    "ruckus": re.compile(r"^\s*(\d+/\d+/\d+)\s+(Up|Down|Disabled|.*?)(?:\s+|$)", re.I),
    "cxos": re.compile(r"^\s*(\d+/\d+/\d+)\s+(up|down|admin down|disabled|.*?)(?:\s+|$)", re.I),
    "cisco": re.compile(r"^\s*((?:Gi|Te|Fa|Eth|Po)\S+)\s+(.+?)\s+(connected|notconnect|disabled|err-disabled|up|down)\s+", re.I),
    "procurve": re.compile(r"^\s*([A-Z]?\d+|\d+/[A-Z]?\d+)\s+(.+)$", re.I),
}

PORT_TOKEN = r"(?:\d+/\d+/\d+|(?:Gi|Te|Fa|Eth|Po)\S+|[A-Z]?\d+|\d+/[A-Z]?\d+)"


def normalize_vendor(vendor: str) -> str:
    v = (vendor or "").lower()
    if "ruckus" in v or "icx" in v or "brocade" in v:
        return "ruckus"
    if "cx" in v or "aos-cx" in v or "aruba cx" in v:
        return "cxos"
    if "procurve" in v or "hewlett" in v or "hpe" in v:
        return "procurve"
    if "cisco" in v or "ios" in v:
        return "cisco"
    return v or "unknown"


def parse_interface_table(text: str, vendor: str) -> List[Dict[str, str]]:
    """Best-effort parser that only returns ports found in the interface table.

    No synthetic ports are generated. That rule is intentionally enforced here.
    """
    vendor = normalize_vendor(vendor)
    rows: List[Dict[str, str]] = []
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip() or re.search(r"^(port|interface|----|status|name)\b", line, re.I):
            continue
        m = PORT_PATTERNS.get(vendor, PORT_PATTERNS["procurve"]).match(line)
        if not m:
            continue
        if vendor == "cisco":
            port, desc, status = m.group(1), m.group(2).strip(), m.group(3)
            speed = _find_speed(line)
            duplex = _find_duplex(line)
        else:
            port = m.group(1)
            status = m.group(2).strip().split()[0] if m.group(2).strip() else ""
            desc = _find_description(line, port)
            speed = _find_speed(line)
            duplex = _find_duplex(line)
        rows.append({"port": port, "status": status, "description": desc, "speed": speed, "duplex": duplex, "raw": raw})
    return _dedupe_ports(rows)


def _find_speed(line: str) -> str:
    m = re.search(r"\b(10G|10000|1G|1000|100|10)\b", line, re.I)
    return m.group(1) if m else ""


def _find_duplex(line: str) -> str:
    m = re.search(r"\b(full|half|auto)\b", line, re.I)
    return m.group(1) if m else ""


def _find_description(line: str, port: str) -> str:
    # Safe fallback: keep descriptions only when a quoted/name-ish tail exists.
    quoted = re.search(r'"([^"]+)"', line)
    if quoted:
        return quoted.group(1).strip()
    parts = line.split()
    return ""


def _dedupe_ports(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen = set()
    out = []
    for row in rows:
        p = row["port"]
        if p in seen:
            continue
        seen.add(p)
        out.append(row)
    return out


def parse_lldp(text: str, vendor: str = "") -> Dict[str, LldpNeighbor]:
    neighbors: Dict[str, LldpNeighbor] = {}
    current: Optional[LldpNeighbor] = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        local = _extract_field(line, ("Local Port", "Local Intf", "Local Interface", "Port"))
        if local and re.fullmatch(PORT_TOKEN, local, re.I):
            current = neighbors.setdefault(local, LldpNeighbor(local_port=local))
            current.raw += raw + "\n"
            continue
        table_match = re.match(rf"^({PORT_TOKEN})\s+(.+?)\s+({PORT_TOKEN}|\S+)$", line, re.I)
        if table_match and not current:
            local_port = table_match.group(1)
            name = table_match.group(2).strip()
            current = neighbors.setdefault(local_port, LldpNeighbor(local_port=local_port, system_name=name, confidence=_confidence(name)))
            current.raw += raw + "\n"
            continue
        if current:
            current.raw += raw + "\n"
            value = _extract_field(line, ("System Name", "SysName", "Device ID", "Chassis Name"))
            if value:
                current.system_name = clean_neighbor_name(value)
                current.confidence = _confidence(current.system_name)
            value = _extract_field(line, ("Port ID", "Remote Port", "Port id", "Neighbor Port"))
            if value:
                current.port_id = value.strip()
            value = _extract_field(line, ("Port Description", "PortDesc"))
            if value:
                current.port_description = value.strip()
            value = _extract_field(line, ("Management Address", "Management IP", "Mgmt IP", "IP address"))
            if value:
                current.management_ip = value.strip()
            value = _extract_field(line, ("Capabilities", "System Capabilities"))
            if value:
                current.capabilities = [v.strip() for v in re.split(r"[, ]+", value) if v.strip()]
    return neighbors


def _extract_field(line: str, names: Iterable[str]) -> str:
    for name in names:
        m = re.match(rf"^{re.escape(name)}\s*[:=]\s*(.+)$", line, re.I)
        if m:
            return m.group(1).strip()
    return ""


def clean_neighbor_name(value: str) -> str:
    value = value.strip().strip('"')
    # Ruckus AP LLDP sometimes leaks firmware/version-like tokens; do not treat those as device names.
    if re.search(r"\b(\d+\.\d+\.\d+|SPR|SPS|ZoneFlex|firmware|version)\b", value, re.I) and not re.search(r"[A-Za-z]{2,}[-_][A-Za-z0-9]", value):
        return ""
    return value[:128]


def _confidence(name: str) -> str:
    if not name:
        return "low"
    if re.match(r"^[A-Za-z][A-Za-z0-9_.-]{2,}$", name) and not re.match(r"^(unknown|none|null|n/a)$", name, re.I):
        return "high"
    return "low"


def parse_mac_table(text: str) -> List[MacEntry]:
    entries: List[MacEntry] = []
    mac_re = re.compile(r"([0-9a-f]{4}[.:-][0-9a-f]{4}[.:-][0-9a-f]{4}|[0-9a-f]{2}(?::[0-9a-f]{2}){5})", re.I)
    for raw in (text or "").splitlines():
        m = mac_re.search(raw)
        if not m:
            continue
        vlan = ""
        vlan_m = re.search(r"\b(?:vlan\s*)?(\d{1,4})\b", raw, re.I)
        if vlan_m:
            vlan = vlan_m.group(1)
        entries.append(MacEntry(mac=m.group(1), vlan=vlan, raw=raw))
    return entries


def merge_scan(ip: str, hostname: str, vendor: str, interface_text: str, lldp_text: str = "", mac_by_port: Optional[Dict[str, str]] = None) -> SwitchScan:
    vendor_norm = normalize_vendor(vendor)
    port_rows = parse_interface_table(interface_text, vendor_norm)
    neighbors = parse_lldp(lldp_text, vendor_norm)
    scan = SwitchScan(switch_id=hostname or ip, ip=ip, hostname=hostname or ip, vendor=vendor_norm)
    for row in port_rows:
        p = row["port"]
        macs = parse_mac_table((mac_by_port or {}).get(p, ""))
        scan.ports.append(PortRecord(
            switch_id=scan.switch_id,
            switch_name=scan.hostname,
            switch_ip=scan.ip,
            vendor=vendor_norm,
            port=p,
            status=row.get("status", ""),
            speed=row.get("speed", ""),
            duplex=row.get("duplex", ""),
            description=row.get("description", ""),
            lldp=neighbors.get(p),
            macs=macs,
            raw={"interface_line": row.get("raw", "")},
        ))
    return scan
