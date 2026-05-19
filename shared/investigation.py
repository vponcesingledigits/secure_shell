"""
Shared investigation engine for Single Digits Engineering Platform.

Purpose:
- One common MAC/IP location and path-building method for MAC Trace and Traffic Analyzer.
- MAC Trace uses mode="mac_trace_quick" for fast location and quick health.
- Traffic Analyzer uses mode="traffic_quick" or mode="traffic_deep" for deeper evidence.

This file is intentionally adapter-friendly. It does not create SSH sessions itself.
Callers pass a command runner callable:

    def runner(target_ip: str, commands: list[str], vendor: str | None = None) -> dict[str, str]:
        ...

The runner should normally be backed by shared/ssh.py and shared/commands.py.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple


class PortRole(str, Enum):
    ENDPOINT = "endpoint"
    AP = "ap"
    GATEWAY = "gateway"
    SWITCH = "switch"
    UPLINK = "uplink"
    TRUNK = "trunk"
    DOWNSTREAM = "downstream"
    PORT_CHANNEL = "port_channel"
    UNKNOWN = "unknown"


@dataclass
class TraceTarget:
    raw: str = ""
    mac: str = ""
    ip: str = ""
    vlan: str = ""
    interface: str = ""


@dataclass
class PortHealthSummary:
    severity: str = "info"
    speed: str = ""
    duplex: str = ""
    admin_state: str = ""
    link_state: str = ""
    input_errors: int = 0
    crc_errors: int = 0
    output_errors: int = 0
    input_discards: int = 0
    output_discards: int = 0
    broadcast_packets: int = 0
    multicast_packets: int = 0
    stp_change_indicator: str = ""
    log_indicator: str = ""
    finding_summary: List[str] = field(default_factory=list)


@dataclass
class TrafficFinding:
    severity: str
    finding_type: str
    switch_ip: str = ""
    switch_hostname: str = ""
    interface: str = ""
    evidence: str = ""
    recommendation: str = ""


@dataclass
class TraceHop:
    hop_number: int
    switch_ip: str
    switch_hostname: str = ""
    vendor: str = ""
    local_port: str = ""
    port_description: str = ""
    port_role: str = PortRole.UNKNOWN.value
    neighbor_name: str = ""
    neighbor_ip: str = ""
    neighbor_port: str = ""
    vlan: str = ""
    native_vlan: str = ""
    tagged_vlans: List[str] = field(default_factory=list)
    mac_seen: bool = False
    mac_count_on_port: int = 0
    speed: str = ""
    duplex: str = ""
    admin_state: str = ""
    link_state: str = ""
    input_errors: int = 0
    crc_errors: int = 0
    output_errors: int = 0
    input_discards: int = 0
    output_discards: int = 0
    broadcast_packets: int = 0
    multicast_packets: int = 0
    stp_change_indicator: str = ""
    log_indicator: str = ""
    finding_summary: List[str] = field(default_factory=list)
    raw_evidence_keys: List[str] = field(default_factory=list)


@dataclass
class TracePath:
    target: TraceTarget
    mode: str = "mac_trace_quick"
    resolved_mac: str = ""
    resolved_ip: str = ""
    resolved_vlan: str = ""
    final_switch_ip: str = ""
    final_switch_hostname: str = ""
    final_port: str = ""
    final_role: str = PortRole.UNKNOWN.value
    status: str = "not_found"
    hops: List[TraceHop] = field(default_factory=list)
    findings: List[TrafficFinding] = field(default_factory=list)
    visited_switches: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    raw_outputs: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


CommandRunner = Callable[[str, Sequence[str], Optional[str]], Dict[str, str]]
VendorDetector = Callable[[str, Dict[str, str]], str]


INTERFACE_REPLACEMENTS = {
    "TwentyFiveGigE": "Twe",
    "TwentyFiveGigabitEthernet": "Twe",
    "HundredGigE": "Hu",
    "HundredGigabitEthernet": "Hu",
    "FortyGigabitEthernet": "Fo",
    "TenGigabitEthernet": "Te",
    "GigabitEthernet": "Gi",
    "FastEthernet": "Fa",
    "Ethernet": "Et",
    "Port-channel": "Po",
    "Port-Channel": "Po",
    "port-channel": "Po",
    "Trk": "Trk",
    "lag": "lag",
}


def normalize_interface(name: str) -> str:
    value = (name or "").strip().strip(",")
    if not value:
        return ""
    for long, short in INTERFACE_REPLACEMENTS.items():
        if value.startswith(long):
            return value.replace(long, short, 1)
    return value


def normalize_mac(value: str) -> str:
    """Return xxxx.xxxx.xxxx. Empty string means invalid/absent."""
    if not value:
        return ""
    raw = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(raw) != 12:
        return ""
    raw = raw.lower()
    return f"{raw[0:4]}.{raw[4:8]}.{raw[8:12]}"


def normalize_ip(value: str) -> str:
    if not value:
        return ""
    candidate = value.strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except Exception:
        return ""


def parse_target(raw: str = "", mac: str = "", ip: str = "", vlan: str = "", interface: str = "") -> TraceTarget:
    raw = (raw or "").strip()
    mac_value = normalize_mac(mac or raw)
    ip_value = normalize_ip(ip or raw)
    return TraceTarget(raw=raw, mac=mac_value, ip=ip_value, vlan=str(vlan or "").strip(), interface=normalize_interface(interface))


TRAFFIC_COMMAND_PROFILES: Dict[str, Dict[str, List[str]]] = {
    "cisco_ios": {
        "mac_trace_quick": [
            "terminal length 0",
            "show version",
            "show hostname",
            "show interfaces status",
            "show mac address-table dynamic",
            "show ip arp",
            "show cdp neighbors detail",
            "show lldp neighbors detail",
            "show interfaces counters errors",
        ],
        "traffic_quick": [
            "terminal length 0",
            "show version",
            "show hostname",
            "show interfaces status",
            "show interfaces",
            "show interfaces counters",
            "show interfaces counters errors",
            "show interfaces trunk",
            "show vlan brief",
            "show mac address-table dynamic",
            "show ip arp",
            "show cdp neighbors detail",
            "show lldp neighbors detail",
        ],
        "traffic_deep": [
            "terminal length 0",
            "show version",
            "show hostname",
            "show interfaces status",
            "show interfaces",
            "show interfaces counters",
            "show interfaces counters errors",
            "show interfaces trunk",
            "show vlan brief",
            "show mac address-table dynamic",
            "show ip arp",
            "show spanning-tree",
            "show spanning-tree detail",
            "show etherchannel summary",
            "show logging",
            "show cdp neighbors detail",
            "show lldp neighbors detail",
            "show ip interface brief",
            "show processes cpu sorted",
            "show processes memory sorted",
            "show storm-control",
        ],
        "targeted_port_followup": [
            "show run interface {port}",
            "show interfaces {port}",
            "show mac address-table interface {port}",
            "show cdp neighbors {port} detail",
            "show lldp neighbors {port} detail",
            "show spanning-tree interface {port} detail",
        ],
    },
    "ruckus_icx": {
        "mac_trace_quick": [
            "skip-page-display",
            "show version",
            "show interfaces brief wide",
            "show mac-address",
            "show arp",
            "show lldp neighbors detail",
            "show statistics ethernet",
        ],
        "traffic_quick": [
            "skip-page-display",
            "show version",
            "show chassis",
            "show interfaces brief wide",
            "show interfaces",
            "show statistics ethernet",
            "show mac-address",
            "show arp",
            "show vlan brief",
            "show lldp neighbors detail",
            "show spanning-tree",
            "show logging",
        ],
        "traffic_deep": [
            "skip-page-display",
            "show version",
            "show chassis",
            "show interfaces brief wide",
            "show interfaces",
            "show statistics ethernet",
            "show mac-address",
            "show arp",
            "show vlan brief",
            "show lldp neighbors detail",
            "show spanning-tree",
            "show logging",
            "show inline power",
            "show inline power detail",
        ],
        "targeted_port_followup": [
            "show lldp neighbor detail port eth {port} | include name|add|desc",
            "show vlan brief eth {port} | include Untagged",
            "show interfaces ethernet {port}",
            "show statistics ethernet {port}",
        ],
    },
    "aruba_cx": {
        "mac_trace_quick": [
            "terminal length 1000",
            "show version",
            "show system",
            "show interface brief",
            "show mac-address-table",
            "show arp",
            "show lldp neighbor-info",
            "show interface statistics",
        ],
        "traffic_quick": [
            "terminal length 1000",
            "show version",
            "show system",
            "show interface brief",
            "show interface",
            "show interface statistics",
            "show mac-address-table",
            "show arp",
            "show vlan",
            "show lldp neighbor-info",
            "show spanning-tree",
            "show logging",
            "show lacp interfaces",
        ],
        "traffic_deep": [
            "terminal length 1000",
            "show version",
            "show system",
            "show interface brief",
            "show interface",
            "show interface statistics",
            "show interface transceiver",
            "show mac-address-table",
            "show arp",
            "show vlan",
            "show lldp neighbor-info",
            "show spanning-tree",
            "show logging",
            "show lacp interfaces",
            "show aruba-central",
        ],
        "targeted_port_followup": [
            "show lldp neighbor-info {port}",
            "show run interface {port}",
            "show interface {port}",
            "show interface {port} statistics",
        ],
    },
    "aruba_procurve": {
        "mac_trace_quick": [
            "no page",
            "show version",
            "show system",
            "show interfaces brief",
            "show mac-address",
            "show arp",
            "show lldp info remote-device",
            "show name",
        ],
        "traffic_quick": [
            "no page",
            "show version",
            "show system",
            "show interfaces brief",
            "show interfaces",
            "show interfaces all",
            "show mac-address",
            "show arp",
            "show vlans",
            "show lldp info remote-device",
            "show spanning-tree",
            "show logging",
            "show trunks",
            "show lacp",
            "show name",
        ],
        "traffic_deep": [
            "no page",
            "show version",
            "show system",
            "show interfaces brief",
            "show interfaces",
            "show interfaces all",
            "show interfaces display",
            "show interfaces transceiver",
            "show mac-address",
            "show arp",
            "show vlans",
            "show lldp info remote-device",
            "show spanning-tree",
            "show logging",
            "show trunks",
            "show lacp",
            "show name",
        ],
        "targeted_port_followup": [
            "show lldp info remote-device {port}",
            "show interfaces {port}",
            "show name {port}",
            "show run interface {port}",
        ],
    },
    "extreme_exos": {
        "mac_trace_quick": [
            "disable clipaging",
            "show switch",
            "show version",
            "show ports no-refresh",
            "show fdb",
            "show iparp",
            "show lldp neighbors detailed",
            "show ports rxerrors no-refresh",
            "show ports txerrors no-refresh port-number",
        ],
        "traffic_quick": [
            "disable clipaging",
            "show switch",
            "show version",
            "show system",
            "show ports no-refresh",
            "show ports statistics no-refresh",
            "show ports rxerrors no-refresh",
            "show ports txerrors no-refresh port-number",
            "show fdb",
            "show iparp",
            "show vlan",
            "show lldp neighbors detailed",
            "show stpd",
            "show log",
        ],
        "traffic_deep": [
            "disable clipaging",
            "show switch",
            "show version",
            "show system",
            "show ports no-refresh",
            "show ports statistics no-refresh",
            "show ports rxerrors no-refresh",
            "show ports txerrors no-refresh port-number",
            "show fdb",
            "show iparp",
            "show vlan",
            "show lldp neighbors detailed",
            "show stpd",
            "show stpd detail",
            "show log",
            "show sharing",
        ],
        "targeted_port_followup": [
            "show port {port} information detail",
            "show configuration ports {port}",
        ],
    },
    "tplink": {
        "mac_trace_quick": [
            "show system-info",
            "show interface status",
            "show mac address-table",
            "show arp",
            "show lldp neighbor-information",
        ],
        "traffic_quick": [
            "show system-info",
            "show interface status",
            "show interface counters",
            "show mac address-table",
            "show arp",
            "show vlan",
            "show lldp neighbor-information",
            "show logging",
        ],
        "traffic_deep": [
            "show system-info",
            "show running-config",
            "show interface status",
            "show interface counters",
            "show mac address-table",
            "show arp",
            "show vlan",
            "show lldp neighbor-information",
            "show logging",
        ],
        "targeted_port_followup": [
            "show cable-diagnostics interface gigabitEthernet {port}",
        ],
    },
}


VENDOR_ALIASES = {
    "cisco": "cisco_ios",
    "cisco_iosxe": "cisco_ios",
    "ios": "cisco_ios",
    "ios_xe": "cisco_ios",
    "ruckus": "ruckus_icx",
    "icx": "ruckus_icx",
    "aruba_procurve": "aruba_procurve",
    "procurve": "aruba_procurve",
    "hp_procurve": "aruba_procurve",
    "hp": "aruba_procurve",
    "cx": "aruba_cx",
    "aruba_cxos": "aruba_cx",
    "extreme": "extreme_exos",
    "exos": "extreme_exos",
    "switch_engine": "extreme_exos",
    "tp-link": "tplink",
    "tp_link": "tplink",
}


def canonical_vendor(vendor: str) -> str:
    v = (vendor or "").strip().lower().replace(" ", "_").replace("-", "_")
    return VENDOR_ALIASES.get(v, v or "cisco_ios")


def get_command_profile(vendor: str, mode: str) -> List[str]:
    vendor_key = canonical_vendor(vendor)
    profiles = TRAFFIC_COMMAND_PROFILES.get(vendor_key) or TRAFFIC_COMMAND_PROFILES["cisco_ios"]
    return list(profiles.get(mode) or profiles.get("mac_trace_quick") or [])


def _safe_int(value: str) -> int:
    try:
        return int(str(value).replace(",", ""))
    except Exception:
        return 0


def _first_existing(outputs: Dict[str, str], candidates: Iterable[str]) -> str:
    for key in candidates:
        if key in outputs:
            return outputs.get(key) or ""
    # tolerate shell runners that key output by base command or slightly varied command
    for key, value in outputs.items():
        low = key.lower()
        for candidate in candidates:
            if candidate.lower() in low or low in candidate.lower():
                return value or ""
    return ""


def parse_hostname(outputs: Dict[str, str], fallback_ip: str = "") -> str:
    show_host = _first_existing(outputs, ["show hostname"])
    m = re.search(r"(?:Hostname|hostname)\s*[: ]\s*(\S+)", show_host)
    if m:
        return m.group(1).strip()
    for out in outputs.values():
        m = re.search(r"(?:^|\n)\s*(?:sysName|SysName|System Name|Switch name)\s*[:=]\s*(\S+)", out or "")
        if m:
            return m.group(1).strip().strip('"')
    for out in outputs.values():
        m = re.search(r"\n\s*\*?\s*([A-Za-z0-9_.-]+)(?:\.\d+)?\s*[#>]\s*$", out or "")
        if m:
            return m.group(1).strip()
    return fallback_ip


def parse_arp_records(output: str) -> Dict[str, str]:
    """Return mac -> ip from common Cisco/Ruckus/Aruba/Extreme/ProCurve ARP outputs."""
    result: Dict[str, str] = {}
    for line in (output or "").splitlines():
        ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        mac_match = re.search(r"\b([0-9a-fA-F]{4}[.:-][0-9a-fA-F]{4}[.:-][0-9a-fA-F]{4}|[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}|[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\b", line)
        if ip_match and mac_match:
            ip = normalize_ip(ip_match.group(1))
            mac = normalize_mac(mac_match.group(1))
            if ip and mac:
                result[mac] = ip
    return result


def parse_mac_records(output: str) -> List[Dict[str, str]]:
    records: List[Dict[str, str]] = []
    for line in (output or "").splitlines():
        mac_match = re.search(r"\b([0-9a-fA-F]{4}[.:-][0-9a-fA-F]{4}[.:-][0-9a-fA-F]{4}|[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}|[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\b", line)
        if not mac_match:
            continue
        mac = normalize_mac(mac_match.group(1))
        parts = line.split()
        vlan = ""
        for part in parts:
            if re.fullmatch(r"\d{1,4}", part):
                vlan = part
                break
        # Last token is usually the port in Cisco/Ruckus/Aruba/Extreme fdb style output.
        port = ""
        for token in reversed(parts):
            if re.search(r"(?:Gi|Te|Fa|Eth|Et|Po|Trk|lag|Lag|\d+/\d+|\d+:\d+|ethernet|GigabitEthernet|TenGigabitEthernet)", token, re.I):
                port = normalize_interface(token)
                break
        if mac and port:
            records.append({"mac": mac, "vlan": vlan, "port": port, "raw": line.strip()})
    return records


def macs_by_port(mac_records: List[Dict[str, str]]) -> Dict[str, List[str]]:
    by_port: Dict[str, List[str]] = {}
    for rec in mac_records:
        by_port.setdefault(rec["port"], []).append(rec["mac"])
    return {port: sorted(set(macs)) for port, macs in by_port.items()}


def find_mac_in_records(mac_records: List[Dict[str, str]], mac: str, vlan: str = "") -> Optional[Dict[str, str]]:
    norm = normalize_mac(mac)
    for rec in mac_records:
        if rec.get("mac") == norm and (not vlan or rec.get("vlan") == str(vlan)):
            return rec
    return None


def parse_interface_status(output: str) -> Dict[str, Dict[str, str]]:
    status: Dict[str, Dict[str, str]] = {}
    for line in (output or "").splitlines():
        raw = line.rstrip()
        if not raw or raw.lower().startswith(("port", "interface", "---", "name")):
            continue
        parts = raw.split()
        if len(parts) < 2:
            continue
        port = normalize_interface(parts[0])
        if not port:
            continue
        # Cisco show interfaces status: Port Name Status Vlan Duplex Speed Type
        if len(parts) >= 6 and re.search(r"connected|notconnect|disabled|err-disabled|sfp|auto|full|half|a-full|a-half", raw, re.I):
            status[port] = {
                "link_state": parts[-5] if len(parts) >= 6 else "",
                "vlan": parts[-4] if len(parts) >= 6 else "",
                "duplex": parts[-3] if len(parts) >= 6 else "",
                "speed": parts[-2] if len(parts) >= 6 else "",
                "description": " ".join(parts[1:-5]) if len(parts) > 6 else "",
                "admin_state": "",
            }
            continue
        # Extreme show ports no-refresh compact line: 2 (...) E A 1000 FULL
        if len(parts) >= 4 and re.fullmatch(r"\d+(?::\d+)?", parts[0]):
            admin = parts[2] if len(parts) > 2 else ""
            link = parts[3] if len(parts) > 3 else ""
            speed = parts[4] if len(parts) > 4 else ""
            duplex = parts[5] if len(parts) > 5 else ""
            status[port] = {"admin_state": admin, "link_state": link, "speed": speed, "duplex": duplex, "vlan": "", "description": ""}
    return status


def parse_interface_rates_and_errors(output: str) -> Dict[str, Dict[str, int]]:
    data: Dict[str, Dict[str, int]] = {}
    current = ""
    for line in (output or "").splitlines():
        m = re.match(r"^(\S+(?:Ethernet|GigE|channel|Channel)\S*|[A-Za-z]+\d+(?:[/.:]\d+)+|\d+(?:[:/]\d+)*) is ", line)
        if m:
            current = normalize_interface(m.group(1))
            data.setdefault(current, {})
            continue
        if not current:
            continue
        m = re.search(r"input rate\s+(\d+)\s+bits/sec,\s+(\d+)\s+packets/sec", line, re.I)
        if m:
            data[current]["input_bps"] = _safe_int(m.group(1)); data[current]["input_pps"] = _safe_int(m.group(2))
        m = re.search(r"output rate\s+(\d+)\s+bits/sec,\s+(\d+)\s+packets/sec", line, re.I)
        if m:
            data[current]["output_bps"] = _safe_int(m.group(1)); data[current]["output_pps"] = _safe_int(m.group(2))
        m = re.search(r"(\d+)\s+input errors,\s+(\d+)\s+CRC", line, re.I)
        if m:
            data[current]["input_errors"] = _safe_int(m.group(1)); data[current]["crc_errors"] = _safe_int(m.group(2))
        m = re.search(r"(\d+)\s+output errors", line, re.I)
        if m:
            data[current]["output_errors"] = _safe_int(m.group(1))
        m = re.search(r"(\d+)\s+input packets with dribble|\s+(\d+)\s+input discards", line, re.I)
        if m:
            data[current]["input_discards"] = _safe_int(m.group(1) or m.group(2))
        m = re.search(r"(\d+)\s+output drops|Total output drops:\s+(\d+)", line, re.I)
        if m:
            data[current]["output_discards"] = _safe_int(m.group(1) or m.group(2))
        m = re.search(r"(\d+)\s+broadcasts.*?(\d+)\s+multicasts", line, re.I)
        if m:
            data[current]["broadcast_packets"] = _safe_int(m.group(1)); data[current]["multicast_packets"] = _safe_int(m.group(2))
    return data


def parse_counter_errors_table(output: str) -> Dict[str, Dict[str, int]]:
    data: Dict[str, Dict[str, int]] = {}
    for line in (output or "").splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[0].lower() in {"port", "interface"}:
            continue
        port = normalize_interface(parts[0])
        nums = [_safe_int(x) for x in parts[1:] if re.fullmatch(r"[\d,]+", x)]
        if not nums:
            continue
        # Cisco order often: Align-Err FCS-Err Xmit-Err Rcv-Err UnderSize OutDiscards
        rec = data.setdefault(port, {})
        if len(nums) >= 2:
            rec["crc_errors"] = max(rec.get("crc_errors", 0), nums[1])
        if len(nums) >= 4:
            rec["input_errors"] = max(rec.get("input_errors", 0), nums[3])
        if len(nums) >= 3:
            rec["output_errors"] = max(rec.get("output_errors", 0), nums[2])
        if len(nums) >= 6:
            rec["output_discards"] = max(rec.get("output_discards", 0), nums[5])
    return data


def parse_neighbors(output: str) -> Dict[str, Dict[str, str]]:
    neighbors: Dict[str, Dict[str, str]] = {}
    # CDP blocks
    for block in re.split(r"\n\s*-{5,}\s*\n|\nDevice ID:", output or ""):
        b = block if block.strip().startswith("Device ID:") else "Device ID:" + block
        dev = ""; local = ""; remote = ""; mgmt = ""; platform = ""; proto = ""
        m = re.search(r"Device ID:\s*(.+)", b)
        if m: dev = m.group(1).strip()
        m = re.search(r"System Name:\s*\"?([^\"\n]+)\"?", b)
        if m: dev = m.group(1).strip()
        m = re.search(r"Interface:\s*(\S+),\s*Port ID \(outgoing port\):\s*(.+)", b)
        if m:
            local = normalize_interface(m.group(1)); remote = normalize_interface(m.group(2).strip()); proto = "CDP"
        m = re.search(r"Local (?:Intf|Interface)\s*:?\s*(\S+)", b, re.I)
        if m and not local:
            local = normalize_interface(m.group(1)); proto = "LLDP"
        m = re.search(r"Port id:\s*(.+)|Port ID\s*:\s*(.+)|Port Description:\s*(.+)", b, re.I)
        if m and not remote:
            remote = normalize_interface(next(g for g in m.groups() if g).strip())
        for ip in re.findall(r"(?:Management Address|IP address|IP):\s*(\d+\.\d+\.\d+\.\d+)", b, flags=re.I):
            if normalize_ip(ip):
                mgmt = ip; break
        m = re.search(r"Platform:\s*([^,\n]+)", b)
        if m: platform = m.group(1).strip()
        if dev and local:
            neighbors[local] = {"neighbor_name": dev, "neighbor_ip": mgmt, "neighbor_port": remote, "protocol": proto or "LLDP/CDP", "platform": platform}
    return neighbors


def merge_port_data(port: str, status: Dict[str, Dict[str, str]], rates: Dict[str, Dict[str, int]], errors: Dict[str, Dict[str, int]]) -> PortHealthSummary:
    s = status.get(port, {})
    r = rates.get(port, {})
    e = errors.get(port, {})
    summary = PortHealthSummary(
        speed=s.get("speed", ""),
        duplex=s.get("duplex", ""),
        admin_state=s.get("admin_state", ""),
        link_state=s.get("link_state", ""),
        input_errors=max(r.get("input_errors", 0), e.get("input_errors", 0)),
        crc_errors=max(r.get("crc_errors", 0), e.get("crc_errors", 0)),
        output_errors=max(r.get("output_errors", 0), e.get("output_errors", 0)),
        input_discards=max(r.get("input_discards", 0), e.get("input_discards", 0)),
        output_discards=max(r.get("output_discards", 0), e.get("output_discards", 0)),
        broadcast_packets=r.get("broadcast_packets", 0),
        multicast_packets=r.get("multicast_packets", 0),
    )
    findings: List[str] = []
    severity = "info"
    duplex = (summary.duplex or "").lower()
    speed = (summary.speed or "").lower()
    if "half" in duplex or duplex in {"a-half", "half"}:
        severity = "critical"; findings.append("Half-duplex link detected.")
    if speed in {"10", "100", "a-10", "a-100", "10m", "100m"}:
        severity = "warning" if severity == "info" else severity; findings.append("Link speed is below expected gigabit/uplink speed.")
    if summary.crc_errors or summary.input_errors:
        severity = "critical" if summary.crc_errors > 100 or summary.input_errors > 100 else "warning"
        findings.append(f"Input/CRC errors present: input={summary.input_errors}, crc={summary.crc_errors}.")
    if summary.output_discards or summary.output_errors:
        severity = "critical" if summary.output_discards > 1000 or summary.output_errors > 100 else "warning"
        findings.append(f"Output errors/discards present: output_errors={summary.output_errors}, output_discards={summary.output_discards}.")
    if summary.broadcast_packets > 100000:
        severity = "warning" if severity == "info" else severity; findings.append("High broadcast packet count seen in snapshot.")
    if summary.multicast_packets > 100000:
        severity = "warning" if severity == "info" else severity; findings.append("High multicast packet count seen in snapshot.")
    summary.severity = severity
    summary.finding_summary = findings
    return summary


def classify_port_role(port: str, neighbor: Dict[str, str], mac_count: int, vlan: str = "", tagged_vlans: Optional[List[str]] = None) -> str:
    p = (port or "").lower()
    name = (neighbor.get("neighbor_name") or "").lower() if neighbor else ""
    platform = (neighbor.get("platform") or "").lower() if neighbor else ""
    tagged_count = len(tagged_vlans or [])
    if p.startswith(("po", "trk", "lag")):
        return PortRole.PORT_CHANNEL.value
    if neighbor:
        if re.search(r"\bap\b|ruckus|r[0-9]{3}|h[0-9]{3}|t[0-9]{3}|e[0-9]{3}|access.?point", name + " " + platform):
            return PortRole.AP.value
        if re.search(r"\bgw\b|gateway|nomadix|router|firewall|watchguard", name + " " + platform):
            return PortRole.GATEWAY.value
        if re.search(r"\bsw\b|switch|cisco|ruckus|icx|aruba|procurve|cx|extreme|exos", name + " " + platform):
            return PortRole.SWITCH.value
        return PortRole.DOWNSTREAM.value
    if tagged_count > 1 or str(vlan).lower() == "trunk":
        return PortRole.TRUNK.value
    if mac_count >= 20:
        return PortRole.UPLINK.value
    if mac_count > 1:
        return PortRole.DOWNSTREAM.value
    if mac_count == 1:
        return PortRole.ENDPOINT.value
    return PortRole.UNKNOWN.value


def analyze_switch_outputs(target_ip: str, vendor: str, outputs: Dict[str, str], target: TraceTarget) -> Tuple[Optional[TraceHop], List[TrafficFinding]]:
    hostname = parse_hostname(outputs, target_ip)
    mac_output = _first_existing(outputs, ["show mac address-table dynamic", "show mac address-table", "show mac-address", "show fdb", "show mac-address-table"])
    arp_output = _first_existing(outputs, ["show ip arp", "show arp", "show iparp"])
    status_output = _first_existing(outputs, ["show interfaces status", "show interface brief", "show interfaces brief", "show ports no-refresh", "show interface status"])
    interfaces_output = _first_existing(outputs, ["show interfaces", "show interface", "show ports statistics no-refresh"])
    error_output = _first_existing(outputs, ["show interfaces counters errors", "show ports rxerrors no-refresh", "show ports txerrors no-refresh port-number", "show interface counters"])
    neighbor_output = "\n".join([
        _first_existing(outputs, ["show cdp neighbors detail"]),
        _first_existing(outputs, ["show lldp neighbors detail", "show lldp neighbor-info", "show lldp info remote-device", "show lldp neighbors detailed", "show lldp neighbor-information"]),
    ])

    mac_records = parse_mac_records(mac_output)
    arp_records = parse_arp_records(arp_output)
    resolved_mac = target.mac
    if not resolved_mac and target.ip:
        for mac, ip in arp_records.items():
            if ip == target.ip:
                resolved_mac = mac
                break
    if not resolved_mac:
        return None, []

    mac_record = find_mac_in_records(mac_records, resolved_mac, target.vlan)
    if not mac_record:
        return None, []

    port = normalize_interface(mac_record.get("port", ""))
    status = parse_interface_status(status_output)
    rates = parse_interface_rates_and_errors(interfaces_output)
    errors = parse_counter_errors_table(error_output)
    neighbors = parse_neighbors(neighbor_output)
    by_port = macs_by_port(mac_records)
    health = merge_port_data(port, status, rates, errors)
    neighbor = neighbors.get(port, {})
    mac_count = len(by_port.get(port, []))
    role = classify_port_role(port, neighbor, mac_count, mac_record.get("vlan", ""), [])

    s = status.get(port, {})
    hop = TraceHop(
        hop_number=0,
        switch_ip=target_ip,
        switch_hostname=hostname,
        vendor=canonical_vendor(vendor),
        local_port=port,
        port_description=s.get("description", ""),
        port_role=role,
        neighbor_name=neighbor.get("neighbor_name", ""),
        neighbor_ip=neighbor.get("neighbor_ip", ""),
        neighbor_port=neighbor.get("neighbor_port", ""),
        vlan=mac_record.get("vlan", "") or target.vlan,
        native_vlan=s.get("vlan", ""),
        tagged_vlans=[],
        mac_seen=True,
        mac_count_on_port=mac_count,
        speed=health.speed,
        duplex=health.duplex,
        admin_state=health.admin_state,
        link_state=health.link_state,
        input_errors=health.input_errors,
        crc_errors=health.crc_errors,
        output_errors=health.output_errors,
        input_discards=health.input_discards,
        output_discards=health.output_discards,
        broadcast_packets=health.broadcast_packets,
        multicast_packets=health.multicast_packets,
        stp_change_indicator=health.stp_change_indicator,
        log_indicator=health.log_indicator,
        finding_summary=health.finding_summary,
        raw_evidence_keys=list(outputs.keys()),
    )

    findings = []
    for msg in health.finding_summary:
        findings.append(TrafficFinding(
            severity=health.severity,
            finding_type="port_health",
            switch_ip=target_ip,
            switch_hostname=hostname,
            interface=port,
            evidence=msg,
            recommendation="Run Traffic Analyzer deep mode for logs/STP/trunk context if this port is in the affected path.",
        ))
    return hop, findings


def default_vendor_detector(target_ip: str, outputs: Dict[str, str]) -> str:
    blob = "\n".join(outputs.values()).lower()
    if "extremexos" in blob or "extreme networks" in blob:
        return "extreme_exos"
    if "aos-cx" in blob or "arubaos-cx" in blob:
        return "aruba_cx"
    if "procurve" in blob or re.search(r"\b(j\d{4}a|ya\.\d+|kb\.\d+|wc\.\d+)\b", blob):
        return "aruba_procurve"
    if "ruckus" in blob or "brocade" in blob or "icx" in blob:
        return "ruckus_icx"
    if "tp-link" in blob or "tplink" in blob:
        return "tplink"
    if "cisco ios" in blob or "ios-xe" in blob or "cisco" in blob:
        return "cisco_ios"
    return "cisco_ios"


def trace_mac_path(
    seed_targets: Sequence[str],
    runner: CommandRunner,
    target: Optional[TraceTarget] = None,
    mac: str = "",
    ip: str = "",
    vlan: str = "",
    mode: str = "mac_trace_quick",
    max_hops: int = 8,
    vendor_detector: VendorDetector = default_vendor_detector,
    known_vendors: Optional[Dict[str, str]] = None,
) -> TracePath:
    """Locate a MAC/IP and follow downstream switch neighbors using one shared method.

    The runner must return command outputs keyed by command string.
    """
    trace_target = target or parse_target(mac=mac, ip=ip, vlan=vlan)
    path = TracePath(target=trace_target, mode=mode)
    queue: List[Tuple[str, int]] = [(x.strip(), 0) for x in seed_targets if x.strip()]
    visited: Set[str] = set()
    resolved_mac = trace_target.mac

    while queue and len(path.hops) < max_hops:
        switch_ip, depth = queue.pop(0)
        if switch_ip in visited:
            continue
        visited.add(switch_ip)
        path.visited_switches.append(switch_ip)

        bootstrap_outputs = runner(switch_ip, ["show version"], None)
        vendor = canonical_vendor((known_vendors or {}).get(switch_ip, "") or vendor_detector(switch_ip, bootstrap_outputs))
        commands = get_command_profile(vendor, mode)
        outputs = dict(bootstrap_outputs)
        outputs.update(runner(switch_ip, commands, vendor))
        path.raw_outputs[switch_ip] = outputs

        # If IP-only target, try to resolve on every hop.
        if not resolved_mac and trace_target.ip:
            arp_output = _first_existing(outputs, ["show ip arp", "show arp", "show iparp"])
            for candidate_mac, candidate_ip in parse_arp_records(arp_output).items():
                if candidate_ip == trace_target.ip:
                    resolved_mac = candidate_mac
                    path.resolved_mac = candidate_mac
                    path.resolved_ip = trace_target.ip
                    break
        local_target = TraceTarget(
            raw=trace_target.raw,
            mac=resolved_mac or trace_target.mac,
            ip=trace_target.ip,
            vlan=trace_target.vlan,
            interface=trace_target.interface,
        )
        hop, findings = analyze_switch_outputs(switch_ip, vendor, outputs, local_target)
        if not hop:
            continue
        hop.hop_number = len(path.hops) + 1
        path.hops.append(hop)
        path.findings.extend(findings)
        path.resolved_mac = local_target.mac
        path.resolved_ip = local_target.ip
        path.resolved_vlan = hop.vlan
        path.final_switch_ip = hop.switch_ip
        path.final_switch_hostname = hop.switch_hostname
        path.final_port = hop.local_port
        path.final_role = hop.port_role
        path.status = "found"

        # Follow only switch-like downstream neighbors for identical MAC/IP location workflow.
        if hop.neighbor_ip and hop.port_role in {PortRole.SWITCH.value, PortRole.DOWNSTREAM.value, PortRole.UPLINK.value, PortRole.TRUNK.value, PortRole.PORT_CHANNEL.value}:
            if hop.neighbor_ip not in visited and all(hop.neighbor_ip != item[0] for item in queue):
                queue.append((hop.neighbor_ip, depth + 1))
        else:
            break

    if path.status != "found":
        path.notes.append("Target MAC/IP was not found in the collected MAC/ARP tables.")
    elif path.final_role in {PortRole.AP.value, PortRole.GATEWAY.value, PortRole.ENDPOINT.value}:
        path.notes.append("Trace stopped at a likely final attachment point.")
    else:
        path.notes.append("Trace stopped before a clearly classified endpoint; run Traffic Analyzer deep mode for more evidence.")
    return path


def analyze_path_health(path: TracePath, mode: str = "mac_trace_quick") -> List[TrafficFinding]:
    findings = list(path.findings)
    if path.status == "found" and mode == "mac_trace_quick":
        findings.append(TrafficFinding(
            severity="info",
            finding_type="next_step",
            switch_ip=path.final_switch_ip,
            switch_hostname=path.final_switch_hostname,
            interface=path.final_port,
            evidence="MAC/IP path located using quick investigation profile.",
            recommendation="Use Traffic Analyzer for deep counters, logs, STP, trunk, and storm analysis if the target is having problems.",
        ))
    return findings


def render_path_summary(path: TracePath) -> str:
    if not path.hops:
        return "No path found."
    pieces = []
    for hop in path.hops:
        label = hop.switch_hostname or hop.switch_ip
        pieces.append(f"{label} {hop.local_port} ({hop.port_role})")
    return " -> ".join(pieces)
