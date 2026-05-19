"""Shared LLDP parsers for Single Digits shell switchport tools.

The parser returns normalized neighbor dictionaries keyed by local port. It is
vendor-aware but intentionally tolerant of mixed command output where command
echoes, headers, and paging artifacts are present.
"""
from __future__ import annotations

import re
from typing import Any

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_RE = re.compile(r"(?P<port>(?:Gi|Gig|GigabitEthernet|Te|Ten|TenGigabitEthernet|Fa|Eth|ethernet|Po|Port-channel)\s*\d+(?:/\d+){0,2}|\d+/\d+/\d+|\d+/\d+|\d+)", re.I)


def normalize_port(port: str) -> str:
    value = (port or "").strip().replace(" ", "")
    value = re.sub(r"^GigabitEthernet", "Gi", value, flags=re.I)
    value = re.sub(r"^TenGigabitEthernet", "Te", value, flags=re.I)
    value = re.sub(r"^ethernet", "Eth", value, flags=re.I)
    return value


def sanitize(value: str, max_len: int = 80) -> str:
    value = (value or "").strip().strip('"')
    value = re.sub(r"\s+", "_", value)
    value = re.sub(r"[^A-Za-z0-9_.:\-/]+", "", value)
    return value[:max_len]


def _grab(text: str, patterns: list[str]) -> str:
    for pat in patterns:
        m = re.search(pat, text or "", flags=re.I | re.M)
        if m:
            return m.group(1).strip()
    return ""


def _skip_line(line: str) -> bool:
    low = line.strip().lower()
    return not low or low.startswith((
        "show ", "sh ", "neighbors", "neighbor", "local port", "local intf",
        "lldp", "---", "===", "total", "device id", "capability", "port id",
        "chassis", "management address subtype"
    ))


def _is_macish(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{2,4}(?:[.:-][0-9a-f]{2,4})+", value or "", flags=re.I))


def _merge(out: dict[str, dict[str, Any]], local: str, **kwargs: Any) -> None:
    local = normalize_port(local)
    if not local:
        return
    row = out.setdefault(local, {"local_port": local, "remote_hostname": "", "remote_ip": "", "remote_port": "", "raw_evidence": ""})
    for key, val in kwargs.items():
        if val and key != "raw_evidence" and not row.get(key):
            row[key] = sanitize(str(val), 80 if key != "remote_port" else 40)
        elif key == "raw_evidence" and val:
            row[key] = (row.get(key, "") + "\n" + str(val).strip()[:1200]).strip()


def parse_lldp_neighbors(vendor: str, text: str) -> dict[str, dict[str, Any]]:
    vendor = (vendor or "unknown").lower()
    if vendor == "ruckus":
        return parse_ruckus(text)
    if vendor == "aruba_cx":
        return parse_aruba_cx(text)
    if vendor == "hp_procurve":
        return parse_procurve(text)
    if vendor == "cisco_ios":
        return parse_cisco(text)
    if vendor == "tplink":
        return parse_tplink(text)
    if vendor == "extreme_exos":
        return parse_extreme(text)
    return parse_generic(text)


def parse_ruckus(text: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    # Full detail: Local port: 1/1/2, System name, Mgmt address, Port description.
    for block in re.split(r"(?im)^\s*(?=Local\s+port\s*:)", text or ""):
        local = _grab(block, [r"Local\s+port\s*:\s*(\S+)"])
        if not local:
            continue
        name = _grab(block, [r"System\s+name\s*:\s*\"?(.+?)\"?\s*$"])
        ip = _grab(block, [r"Management\s+address\s*\(IPv4\)\s*:\s*(\d+\.\d+\.\d+\.\d+)", r"Management\s+Address\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)"])
        rport = _grab(block, [r"Port\s+description\s*:\s*\"?(.+?)\"?\s*$", r"Port\s+ID.*?:\s*(.+?)\s*$"])
        _merge(out, local, remote_hostname=name, remote_ip=ip, remote_port=rport, raw_evidence=block)
    # Summary: 1/1/2 chassis portid portdesc system-name
    for line in (text or "").splitlines():
        raw = line.strip()
        if _skip_line(raw):
            continue
        parts = raw.split()
        if len(parts) >= 5 and re.match(r"^\d+/\d+/\d+$", parts[0]):
            name = parts[-1]
            if name and not _is_macish(name):
                _merge(out, parts[0], remote_hostname=name, remote_port=parts[-2], raw_evidence=raw)
    return out


def parse_aruba_cx(text: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for block in re.split(r"(?im)^\s*(?=(?:Local\s+Port|Local\s+Interface)\s*[:=])", text or ""):
        local = _grab(block, [r"Local\s+(?:Port|Interface)\s*[:=]\s*(\S+)"])
        if not local:
            continue
        name = _grab(block, [r"System\s+Name\s*[:=]\s*\"?(.+?)\"?\s*$", r"Neighbor\s+Name\s*[:=]\s*(.+?)\s*$"])
        ip = _grab(block, [r"Management\s+Address\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)"])
        rport = _grab(block, [r"Port\s+ID\s*[:=]\s*(.+?)\s*$", r"Port\s+Description\s*[:=]\s*(.+?)\s*$"])
        _merge(out, local, remote_hostname=name, remote_ip=ip, remote_port=rport, raw_evidence=block)
    for line in (text or "").splitlines():
        raw = line.strip()
        if _skip_line(raw):
            continue
        parts = raw.split()
        if len(parts) >= 5 and re.match(r"^\d+/\d+/\d+$", parts[0]):
            name = parts[-1]
            if not _is_macish(name):
                _merge(out, parts[0], remote_hostname=name, remote_port=parts[-2], raw_evidence=raw)
    return out


def parse_procurve(text: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for block in re.split(r"(?im)^\s*(?=Local\s+Port\s*[:=])", text or ""):
        local = _grab(block, [r"Local\s+Port\s*[:=]\s*(\S+)"])
        if not local:
            continue
        name = _grab(block, [r"System\s+Name\s*[:=]\s*\"?(.+?)\"?\s*$", r"SysName\s*[:=]\s*(.+?)\s*$"])
        ip = _grab(block, [r"Management\s+Address\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)"])
        rport = _grab(block, [r"Port\s+Id\s*[:=]\s*(.+?)\s*$", r"Port\s+Description\s*[:=]\s*(.+?)\s*$"])
        _merge(out, local, remote_hostname=name, remote_ip=ip, remote_port=rport, raw_evidence=block)
    for line in (text or "").splitlines():
        raw = line.strip()
        if _skip_line(raw):
            continue
        parts = raw.split()
        if len(parts) >= 4 and re.match(r"^\d+(?:/\d+){0,2}$", parts[0]):
            name = parts[-1]
            if not _is_macish(name):
                _merge(out, parts[0], remote_hostname=name, remote_port=parts[-2], raw_evidence=raw)
    return out


def parse_cisco(text: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for block in re.split(r"(?im)^-{8,}\s*$", text or ""):
        local = _grab(block, [r"Interface\s*:\s*(\S+),\s*Port\s+ID", r"Local\s+Intf\s*[:=]\s*(\S+)"])
        name = _grab(block, [r"Device\s+ID\s*[:=]\s*(.+?)\s*$", r"System\s+Name\s*[:=]\s*(.+?)\s*$"])
        if not local or not name:
            continue
        ip = _grab(block, [r"IP\s+address\s*:\s*(\d+\.\d+\.\d+\.\d+)", r"Management\s+Address\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)"])
        rport = _grab(block, [r"Port\s+ID\s*\(outgoing port\)\s*:\s*(.+?)\s*$", r"Port\s+ID\s*[:=]\s*(.+?)\s*$"])
        _merge(out, local, remote_hostname=name, remote_ip=ip, remote_port=rport, raw_evidence=block)
    # Cisco summary: Device ID Local Intf Hold-time Capability Port ID
    for line in (text or "").splitlines():
        raw = line.strip()
        if _skip_line(raw):
            continue
        parts = raw.split()
        if len(parts) >= 5:
            # Find first token after hostname that looks like a local interface.
            for idx in range(1, min(len(parts), 4)):
                if re.match(r"^(?:Gi|Fa|Te|Eth|Po)\d", parts[idx], flags=re.I):
                    _merge(out, parts[idx], remote_hostname=parts[0], remote_port=parts[-1], raw_evidence=raw)
                    break
    return out


def parse_tplink(text: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for block in re.split(r"(?im)^\s*(?=(?:Local\s+(?:Port|Interface)|Interface)\s*[:=])", text or ""):
        local = _grab(block, [r"Local\s+(?:Port|Interface)\s*[:=]\s*(\S+)", r"Interface\s*[:=]\s*(\S+)"])
        if not local:
            continue
        name = _grab(block, [r"System\s+Name\s*[:=]\s*(.+?)\s*$", r"Neighbor\s+Name\s*[:=]\s*(.+?)\s*$", r"Device\s+ID\s*[:=]\s*(.+?)\s*$"])
        ip = _grab(block, [r"Management\s+Address\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)", r"IP\s+Address\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)"])
        rport = _grab(block, [r"Port\s+ID\s*[:=]\s*(.+?)\s*$", r"Port\s+Description\s*[:=]\s*(.+?)\s*$"])
        _merge(out, local, remote_hostname=name, remote_ip=ip, remote_port=rport, raw_evidence=block)
    for line in (text or "").splitlines():
        raw = line.strip()
        if _skip_line(raw):
            continue
        parts = raw.split()
        if len(parts) >= 4 and re.match(r"^(?:Gi|GigabitEthernet|Eth|GE|TG|\d+/\d+/\d+|\d+/\d+|\d+)", parts[0], flags=re.I):
            name = parts[-1]
            if not _is_macish(name):
                _merge(out, parts[0], remote_hostname=name, remote_port=parts[-2], raw_evidence=raw)
    return out


def parse_extreme(text: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for block in re.split(r"(?im)^\s*(?=(?:Local\s+Port|Port)\s*[:=])", text or ""):
        local = _grab(block, [r"Local\s+Port\s*[:=]\s*(\S+)", r"Port\s*[:=]\s*(\S+)"])
        if not local:
            continue
        name = _grab(block, [r"System\s+Name\s*[:=]\s*\"?(.+?)\"?\s*$"])
        ip = _grab(block, [r"Management\s+Address\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)"])
        rport = _grab(block, [r"Port\s+ID\s*[:=]\s*(.+?)\s*$", r"Port\s+Description\s*[:=]\s*(.+?)\s*$"])
        _merge(out, local, remote_hostname=name, remote_ip=ip, remote_port=rport, raw_evidence=block)
    return out


def parse_generic(text: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for block in re.split(r"\n(?=\s*(?:Local\s+(?:Port|Intf|Interface)|Interface|Device\s+ID))", text or "", flags=re.I):
        local = _grab(block, [r"Local\s+(?:Port|Intf|Interface)\s*[:=]?\s*(\S+)", r"Interface\s*[:=]\s*(\S+)"])
        name = _grab(block, [r"System\s+Name\s*[:=]\s*\"?(.+?)\"?\s*$", r"Device\s+ID\s*[:=]\s*(.+?)\s*$"])
        if not local or not name:
            continue
        ip = _grab(block, [r"Management\s+Address\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)", r"IP\s+address\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)"])
        rport = _grab(block, [r"Port\s+ID\s*[:=]\s*(.+?)\s*$", r"Port\s+Description\s*[:=]\s*(.+?)\s*$"])
        _merge(out, local, remote_hostname=name, remote_ip=ip, remote_port=rport, raw_evidence=block)
    return out
