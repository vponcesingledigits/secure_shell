"""Reusable parsers for command output normalization."""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional

from shared.models import PortInfo, Vendor

_MORE_RE = re.compile(r"--More--|More:|Press any key to continue|\x1b\[[0-9;]*[A-Za-z]", re.I)
ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def clean_output(output: str) -> str:
    text = ANSI_RE.sub("", output or "")
    text = _MORE_RE.sub("", text)
    text = text.replace("\r", "")
    lines = [line.rstrip() for line in text.split("\n")]
    return "\n".join(lines).strip()


def mask_secret(value: Optional[str], visible: int = 2) -> str:
    if not value:
        return ""
    if len(value) <= visible:
        return "*" * len(value)
    return value[:visible] + "*" * max(4, len(value) - visible)


def redact_sensitive(text: str, secrets: Iterable[str] = ()) -> str:
    from shared.security.redaction import redact_text
    return redact_text(text or "", secrets)


def parse_interface_brief(vendor: Vendor, output: str) -> List[PortInfo]:
    text = clean_output(output)
    if vendor == Vendor.RUCKUS_ICX:
        return _parse_ruckus_interface_brief(text)
    if vendor == Vendor.CISCO_IOS:
        return _parse_cisco_interface_status(text)
    if vendor == getattr(Vendor, "EXTREME_EXOS", None):
        return _parse_extreme_ports(text)
    if vendor in (Vendor.ARUBA_CX, Vendor.PROCURVE):
        return _parse_aruba_interface_brief(text)
    return _parse_generic_ports(text)


def _parse_ruckus_interface_brief(text: str) -> List[PortInfo]:
    ports: List[PortInfo] = []
    for line in text.splitlines():
        parts = line.split()
        if parts and re.match(r"^(?:\d+/\d+/\d+|mgmt\d+)$", parts[0]) and len(parts) >= 2:
            port = parts[0]
            status = parts[1]
            speed = None
            duplex = None
            untagged_vlan = None
            description = None
            if len(parts) > 4:
                speed = parts[4]
            if len(parts) > 5:
                duplex = parts[5]
            if len(parts) > 7:
                untagged_vlan = parts[7]
            if len(parts) > 10:
                description = " ".join(parts[10:]).strip('"') or None
            ports.append(PortInfo(port=port, status=status, speed=speed, duplex=duplex, untagged_vlan=untagged_vlan, description=description))
            continue
        match = re.match(r"^\s*(\d+/\d+/\d+)\s+(Up|Down|Disabled|None|Err-DIS)\s+(\S+)?\s*(\S+)?", line, re.I)
        if match:
            ports.append(PortInfo(port=match.group(1), status=match.group(2), speed=match.group(3), duplex=match.group(4)))
    return ports


def _parse_cisco_interface_status(text: str) -> List[PortInfo]:
    ports: List[PortInfo] = []
    for line in text.splitlines():
        match = re.match(r"^\s*(Gi\S+|Te\S+|Fa\S+|Eth\S+)\s+(.*?)\s{2,}(connected|notconnect|disabled|err-disabled)\s+(\S+)\s+(\S+)\s+(\S+)", line, re.I)
        if match:
            ports.append(PortInfo(port=match.group(1), description=match.group(2).strip(), status=match.group(3), untagged_vlan=match.group(4), duplex=match.group(5), speed=match.group(6)))
    return ports


def _parse_aruba_interface_brief(text: str) -> List[PortInfo]:
    ports: List[PortInfo] = []
    for line in text.splitlines():
        match = re.match(r"^\s*(\d+/\d+/\d+|[A-Z]+\d+|\d+)\s+(up|down|disabled|administratively down)\s+(\S+)?\s*(\S+)?\s*(.*)$", line, re.I)
        if match:
            ports.append(PortInfo(port=match.group(1), status=match.group(2), speed=match.group(3), duplex=match.group(4), description=match.group(5).strip() or None))
    return ports



def _parse_extreme_ports(text: str) -> List[PortInfo]:
    try:
        from shared.extreme_exos import parse_ports_no_refresh
        rows = parse_ports_no_refresh(text)
        return [
            PortInfo(
                port=str(row.get("port", "")),
                status=str(row.get("link_state") or row.get("port_state") or ""),
                speed=str(row.get("speed")) if row.get("speed") is not None else None,
                duplex=row.get("duplex"),
                description=row.get("display_string") or None,
            )
            for row in rows if row.get("port")
        ]
    except Exception:
        return _parse_generic_ports(text)

def _parse_generic_ports(text: str) -> List[PortInfo]:
    ports: List[PortInfo] = []
    for line in text.splitlines():
        match = re.match(r"^\s*([A-Za-z]*\d+(?:/\d+){0,3})\s+(up|down|enabled|disabled|connected|notconnect)\b", line, re.I)
        if match:
            ports.append(PortInfo(port=match.group(1), status=match.group(2)))
    return ports


def parse_lldp_neighbors(output: str) -> List[Dict[str, Optional[str]]]:
    text = clean_output(output)
    neighbors: List[Dict[str, Optional[str]]] = []
    current: Dict[str, Optional[str]] = {}
    field_patterns = {
        "local_port": r"(?:Local Port|Local Intf|Port)\s*[:=]\s*(.+)",
        "neighbor_name": r"(?:System Name|Chassis Name|Device ID)\s*[:=]\s*(.+)",
        "neighbor_port": r"(?:Port ID|Remote Port|PortDescr|Port Description)\s*[:=]\s*(.+)",
        "neighbor_ip": r"(?:Management Address|Mgmt Address|IP Address)\s*[:=]\s*((?:\d{1,3}\.){3}\d{1,3})",
    }
    for line in text.splitlines():
        if re.match(r"^-{3,}$", line.strip()) and current:
            neighbors.append(current)
            current = {}
            continue
        for key, pattern in field_patterns.items():
            match = re.search(pattern, line, re.I)
            if match:
                current[key] = match.group(1).strip()
    if current:
        neighbors.append(current)
    return neighbors
