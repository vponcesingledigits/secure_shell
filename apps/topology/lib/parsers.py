from __future__ import annotations

import re
from typing import Dict, Iterable, List

from .classification import classify_lldp_neighbor
from .models import LLDPNeighbor, SwitchPort


def parse_mstp_priority(output: str) -> str:
    """Extract an MSTP/STP priority from common 'show run | include priority' style output."""
    if not output:
        return ""
    patterns = [
        r"spanning-tree\s+priority\s+(\d+)",
        r"spanning-tree\s+mst\s+\S+\s+priority\s+(\d+)",
        r"priority\s+(\d+)",
    ]
    for line in output.splitlines():
        low = line.lower()
        if "priority" not in low:
            continue
        for pat in patterns:
            m = re.search(pat, low, re.I)
            if m:
                return m.group(1)
    return ""


def parse_ruckus_filtered_lldp(output: str, local_device: str = "", local_ip: str = "") -> List[LLDPNeighbor]:
    """Parse Ruckus filtered LLDP output:
    show lldp neigh det | i Local|name|address|Desc
    """
    neighbors: List[LLDPNeighbor] = []
    current: Dict[str, str] = {}
    raw_lines: List[str] = []

    def flush() -> None:
        nonlocal current, raw_lines
        if not current:
            return
        name = clean_quoted(current.get("system_name", ""))
        desc = clean_quoted(current.get("system_description", ""))
        port_desc = clean_quoted(current.get("port_description", ""))
        role = classify_lldp_neighbor(name, desc, port_desc, [])
        neighbors.append(LLDPNeighbor(
            local_device=local_device,
            local_ip=local_ip,
            local_port=current.get("local_port", ""),
            remote_hostname=name,
            remote_ip=current.get("management_ip", ""),
            remote_port=port_desc,
            remote_description=desc,
            role=role,
            raw="\n".join(raw_lines),
        ))
        current = {}
        raw_lines = []

    for line in output.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.lower().startswith("local port:"):
            flush()
            current["local_port"] = s.split(":", 1)[1].strip()
            raw_lines = [line]
            continue
        if not current:
            continue
        raw_lines.append(line)
        m = re.search(r"system\s+name\s*:\s*(.*)$", s, re.I)
        if m:
            current["system_name"] = m.group(1).strip()
            continue
        m = re.search(r"system\s+description\s*:\s*(.*)$", s, re.I)
        if m:
            current["system_description"] = m.group(1).strip()
            continue
        m = re.search(r"management\s+address(?:\s*\([^)]*\))?\s*:\s*([0-9a-fA-F:.]+)", s, re.I)
        if m:
            current["management_ip"] = m.group(1).strip()
            continue
        m = re.search(r"port\s+description\s*:\s*(.*)$", s, re.I)
        if m:
            current["port_description"] = m.group(1).strip()
            continue
    flush()
    return neighbors


def parse_generic_lldp(output: str, local_device: str = "", local_ip: str = "") -> List[LLDPNeighbor]:
    """Best-effort parser for common full LLDP detail outputs."""
    if "Local port:" in output and ("System name" in output or "Management address" in output):
        return parse_ruckus_filtered_lldp(output, local_device, local_ip)

    blocks = re.split(r"\n(?=(?:Local\s+Port|Local\s+Interface|Interface|Port)\s*[:\s])", output, flags=re.I)
    neighbors: List[LLDPNeighbor] = []
    for block in blocks:
        if not block.strip():
            continue
        local_port = first_match(block, [
            r"Local\s+Port\s*:\s*(\S+)",
            r"Local\s+Interface\s*:\s*(\S+)",
            r"Interface\s*:\s*(\S+)",
        ])
        name = clean_quoted(first_match(block, [
            r"System\s+Name\s*:\s*(.+)",
            r"System\s+name\s*:\s*(.+)",
            r"SysName\s*:\s*(.+)",
        ]))
        ip = first_match(block, [
            r"Management\s+Address(?:\s*\([^)]*\))?\s*:\s*([0-9a-fA-F:.]+)",
            r"Management\s+address(?:\s*\([^)]*\))?\s*:\s*([0-9a-fA-F:.]+)",
            r"Mgmt\s+IP\s*:\s*([0-9.]+)",
        ])
        remote_port = clean_quoted(first_match(block, [
            r"Port\s+description\s*:\s*(.+)",
            r"Port\s+Description\s*:\s*(.+)",
            r"Port\s+ID\s*:\s*(.+)",
            r"Remote\s+Port\s*:\s*(.+)",
        ]))
        desc = clean_quoted(first_match(block, [
            r"System\s+Description\s*:\s*(.+)",
            r"System\s+description\s*:\s*(.+)",
            r"Description\s*:\s*(.+)",
        ]))
        caps = []
        caps_line = first_match(block, [r"Capabilities\s*:\s*(.+)", r"System\s+Capabilities\s*:\s*(.+)"])
        if caps_line:
            caps = [x.strip() for x in re.split(r"[,/ ]+", caps_line) if x.strip()]
        if local_port or name or ip:
            role = classify_lldp_neighbor(name, desc, remote_port, caps)
            neighbors.append(LLDPNeighbor(local_device=local_device, local_ip=local_ip, local_port=local_port, remote_hostname=name, remote_ip=ip, remote_port=remote_port, remote_description=desc, remote_capabilities=caps, role=role, raw=block.strip()))
    return neighbors


def parse_interface_inventory(output: str, switch_name: str) -> List[SwitchPort]:
    """Best-effort real-port inventory parser for Ruckus/ProCurve/Cisco/CX/Extreme outputs.
    The goal is not link health; it is a logical port documentation row for every real port.
    """
    ports: Dict[str, SwitchPort] = {}
    for line in output.splitlines():
        raw = line.rstrip()
        s = raw.strip()
        if not s or s.lower().startswith(("port ", "----", "====", "interface", "show ")):
            continue
        port = ""
        name = ""
        # Ruckus/ICX: 1/1/1 Up ... name may be rightmost in wide output.
        m = re.match(r"^(\d+/\d+/\d+|\d+/\d+|[A-Za-z]+\S*\d[\w/.-]*)\s+(.+)$", s)
        if m:
            port = m.group(1)
            rest = m.group(2).strip()
            name = extract_likely_description(rest)
        # Extreme: 1 (0206) E R or 2 (0206) E A 1000 FULL; no name from show ports.
        m2 = re.match(r"^(\d+)\s+\([^)]*\)\s+[DEFL]\s+[ARNPLD]\b", s)
        if m2:
            port = m2.group(1)
            name = ""
        if port and is_real_port(port):
            ports.setdefault(port, SwitchPort(switch_name=switch_name, local_port_id=port, local_port_name=name))
    return sorted(ports.values(), key=lambda p: natural_port_key(p.local_port_id))


def merge_lldp_into_ports(ports: List[SwitchPort], neighbors: Iterable[LLDPNeighbor]) -> List[SwitchPort]:
    by_port = {p.local_port_id: p for p in ports}
    for n in neighbors:
        if not n.local_port:
            continue
        row = by_port.setdefault(n.local_port, SwitchPort(switch_name=n.local_device or "", local_port_id=n.local_port))
        row.remote_hostname = n.remote_hostname or ""
        row.remote_ip = n.remote_ip or ""
        row.remote_port = n.remote_port or ""
        row.remote_role = n.role or "unknown"
        row.suggested_port_name = n.remote_hostname or row.local_port_name or ""
    for p in by_port.values():
        p.patch_panel_port = ""
        if not p.suggested_port_name:
            p.suggested_port_name = p.remote_hostname or p.local_port_name or ""
    return sorted(by_port.values(), key=lambda p: natural_port_key(p.local_port_id))


def clean_quoted(value: str) -> str:
    value = (value or "").strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1].strip()
    return value


def first_match(text: str, patterns: Iterable[str]) -> str:
    for pat in patterns:
        m = re.search(pat, text, re.I | re.M)
        if m:
            return m.group(1).strip()
    return ""


def extract_likely_description(rest: str) -> str:
    # Strip common status/speed/admin columns and retain text-ish tail when present.
    tokens = rest.split()
    if not tokens:
        return ""
    status_words = {"up", "down", "disabled", "connected", "notconnect", "err-disabled", "forward", "blocking", "a", "r", "e", "d", "full", "half", "auto", "yes", "no"}
    idx = 0
    while idx < len(tokens):
        low = tokens[idx].lower()
        if low in status_words or re.fullmatch(r"\d+(?:m|g|mbps|gbps)?", low) or re.fullmatch(r"\d+", low):
            idx += 1
        else:
            break
    desc = " ".join(tokens[idx:]).strip()
    if desc.lower() in {"--", "none", "empty", "n/a"}:
        return ""
    return desc


def is_real_port(port: str) -> bool:
    low = port.lower()
    if low.startswith(("vlan", "ve", "loopback", "lag", "po", "port-channel", "mgmt", "management")):
        return False
    return bool(re.search(r"\d", port))


def natural_port_key(port: str):
    return [int(x) if x.isdigit() else x.lower() for x in re.split(r"(\d+)", port)]
