"""
Single Digits Engineering Platform - Extreme EXOS / Switch Engine support
RC0.1

This module is intentionally standalone so it can be dropped into the shell under shared/
and then imported by MAC Trace, Switch Health, Port Map, Topology, Compliance, and Evidence Pack.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional

VENDOR_KEY = "extreme_exos"
VENDOR_LABEL = "Extreme EXOS / Switch Engine"

# EXOS prompts observed: "* VASHILMDFCoresw.1 #", "VASHILMDFCoresw.37 #"
PROMPT_RE = re.compile(r"(?m)^\s*\*?\s*[A-Za-z0-9_.-]+(?:\.\d+)?\s*[#>]\s*$")
PRIVILEGED_PROMPT_RE = re.compile(r"(?m)^\s*\*?\s*[A-Za-z0-9_.-]+(?:\.\d+)?\s*#\s*$")

LOGIN_BANNER_MARKERS = (
    "ExtremeXOS",
    "Press the <tab> or '?' key at any time for completions.",
    "Remember to save your configuration changes.",
)

CAPABILITIES = {
    "supports_nested_ssh": False,
    "supports_lldp_mgmt_ip": True,
    "preferred_neighbor_access": "direct_from_shell",
    "disable_paging": "disable clipaging",
}

COMMANDS: Dict[str, List[str]] = {
    "disable_paging": ["disable clipaging"],
    "identity": ["show system", "show version"],
    "environment": ["show temperature", "show power", "show fans", "show odometers"],
    "ports": ["show ports no-refresh"],
    "rx_errors": ["show ports rxerrors"],
    "tx_errors": ["show ports txerrors no-refresh port-number"],
    "lldp_summary": ["show lldp neighbors"],
    "lldp_detail": ["show lldp neighbors detailed"],
    "lldp_quick_name_ip": ["show lldp neighbors detailed | include Name|Address"],
    "mac_lookup": ["show fdb {mac}"],
    "mac_table": ["show fdb"],
    "mac_table_vlan": ["show fdb vlan {vlan}"],
    "vlans": ["show vlan"],
    "logs": ["show log"],
    "poe": ["show inline-power"],
}

PORT_STATE = {
    "D": "disabled",
    "E": "enabled",
    "F": "disabled_link_flap_detection",
    "L": "disabled_licensing",
}

LINK_STATE = {
    "A": "active",
    "R": "ready",
    "NP": "not_present",
    "L": "loopback",
    "D": "elsm_enabled_not_up",
    "d": "ethernet_oam_enabled_not_up",
}

FDB_RE = re.compile(
    r"^\s*(?P<mac>[0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+"
    r"(?P<vlan_name>.+?)\((?P<vlan_tag>\d+)\)\s+"
    r"(?P<age>\d+)\s+"
    r"(?P<flags>[A-Za-z\s]+?)\s+"
    r"(?P<port>[A-Za-z0-9:/.,\-\s]+)\s*$",
    re.IGNORECASE,
)

# Display String is currently captured as optional/non-greedy. Blank display strings are common.
PORT_RE = re.compile(
    r"^\s*(?P<port>\d+)\s+"
    r"(?:(?P<display_string>.*?)\s+)?"
    r"(?P<vlan_summary>\(\d+\)|\S+)\s+"
    r"(?P<port_state>[DEFL])\s+"
    r"(?P<link_state>NP|[ARDLd])"
    r"(?:\s+(?P<speed>\S+)\s+(?P<duplex>\S+))?\s*$"
)

RXERROR_RE = re.compile(
    r"^\s*(?P<port>\d+)\s+"
    r"(?P<link_state>NP|[ARL])\s+"
    r"(?P<rx_crc>\d+)\s+"
    r"(?P<rx_over>\d+)\s+"
    r"(?P<rx_under>\d+)\s+"
    r"(?P<rx_frag>\d+)\s+"
    r"(?P<rx_jabber>\d+)\s+"
    r"(?P<rx_align>\d+)\s+"
    r"(?P<rx_lost>\d+)\s*$"
)

TXERROR_RE = re.compile(
    r"^\s*(?P<port>\d+)\s+"
    r"(?P<link_state>NP|[ARL])\s+"
    r"(?P<tx_coll>\d+)\s+"
    r"(?P<tx_late_coll>\d+)\s+"
    r"(?P<tx_deferred>\d+)\s+"
    r"(?P<tx_errors>\d+)\s+"
    r"(?P<tx_lost>\d+)\s+"
    r"(?P<tx_parity>\d+)\s*$"
)

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_COLON_RE = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", re.I)


def detect(output: str) -> bool:
    text = output or ""
    return any(marker in text for marker in ("ExtremeXOS", "Extreme Networks", "Switch Engine"))


def normalize_mac(mac: str) -> str:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(cleaned) != 12:
        return mac.strip().lower()
    return ":".join(cleaned[i:i+2] for i in range(0, 12, 2)).lower()


def _to_int(value: Optional[str]) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _strip_quotes(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def parse_fdb(output: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in (output or "").splitlines():
        match = FDB_RE.match(line)
        if not match:
            continue
        data = match.groupdict()
        rows.append({
            "mac": normalize_mac(data["mac"]),
            "vlan_name": data["vlan_name"].strip(),
            "vlan_tag": int(data["vlan_tag"]),
            "age": int(data["age"]),
            "flags": " ".join(data["flags"].split()),
            "port": data["port"].strip(),
            "vendor": VENDOR_KEY,
        })
    return rows


def parse_ports_no_refresh(output: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in (output or "").splitlines():
        match = PORT_RE.match(line)
        if not match:
            continue
        data = match.groupdict()
        display = (data.get("display_string") or "").strip()
        rows.append({
            "port": data["port"],
            "display_string": display,
            "vlan_summary": data["vlan_summary"],
            "port_state_code": data["port_state"],
            "port_state": PORT_STATE.get(data["port_state"], data["port_state"]),
            "link_state_code": data["link_state"],
            "link_state": LINK_STATE.get(data["link_state"], data["link_state"]),
            "speed": _to_int(data.get("speed")),
            "duplex": data.get("duplex"),
            "vendor": VENDOR_KEY,
        })
    return rows


def parse_rxerrors(output: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in (output or "").splitlines():
        match = RXERROR_RE.match(line)
        if not match:
            continue
        data = match.groupdict()
        rows.append({
            "port": data["port"],
            "link_state_code": data["link_state"],
            "link_state": LINK_STATE.get(data["link_state"], data["link_state"]),
            "rx_crc": int(data["rx_crc"]),
            "rx_over": int(data["rx_over"]),
            "rx_under": int(data["rx_under"]),
            "rx_frag": int(data["rx_frag"]),
            "rx_jabber": int(data["rx_jabber"]),
            "rx_align": int(data["rx_align"]),
            "rx_lost": int(data["rx_lost"]),
            "vendor": VENDOR_KEY,
        })
    return rows


def parse_txerrors(output: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in (output or "").splitlines():
        match = TXERROR_RE.match(line)
        if not match:
            continue
        data = match.groupdict()
        rows.append({
            "port": data["port"],
            "link_state_code": data["link_state"],
            "link_state": LINK_STATE.get(data["link_state"], data["link_state"]),
            "tx_collisions": int(data["tx_coll"]),
            "tx_late_collisions": int(data["tx_late_coll"]),
            "tx_deferred": int(data["tx_deferred"]),
            "tx_errors": int(data["tx_errors"]),
            "tx_lost": int(data["tx_lost"]),
            "tx_parity": int(data["tx_parity"]),
            "vendor": VENDOR_KEY,
        })
    return rows


def classify_neighbor(name: Optional[str], description: Optional[str], capabilities: Iterable[str]) -> str:
    text = f"{name or ''} {description or ''} {' '.join(capabilities or [])}".lower()
    if "router" in text or "mikrotik" in text or "nomadix" in text or "gateway" in text or "gw" in (name or "").lower():
        return "gateway_router"
    if "bridge" in text or "switch" in text or "ruckus" in text or "aruba" in text or "hp " in text or "extreme" in text:
        return "switch"
    if "access point" in text or "ap" in text:
        return "access_point"
    return "unknown"


def parse_lldp_neighbors_detailed(output: str) -> List[Dict[str, Any]]:
    neighbors: List[Dict[str, Any]] = []
    current_port: Optional[str] = None
    current: Optional[Dict[str, Any]] = None
    last_field: Optional[str] = None

    def flush() -> None:
        nonlocal current
        if current:
            caps = current.get("capabilities") or []
            current["classification"] = classify_neighbor(
                current.get("neighbor_name"), current.get("neighbor_description"), caps
            )
            current["vendor"] = VENDOR_KEY
            neighbors.append(current)
            current = None

    for raw in (output or "").splitlines():
        line = raw.rstrip()
        port_match = re.search(r"LLDP Port\s+(?P<port>\S+)\s+detected", line)
        if port_match:
            flush()
            current_port = port_match.group("port")
            last_field = None
            continue

        neigh_match = re.search(r"Neighbor:\s*(?P<chassis>[^/\s]+)/(?P<port_id>.*?),\s*age\s+(?P<age>\d+)", line)
        if neigh_match:
            flush()
            current = {
                "local_port": current_port,
                "neighbor_chassis_id": normalize_mac(neigh_match.group("chassis")),
                "neighbor_port_id": _strip_quotes(neigh_match.group("port_id").strip()),
                "age_seconds": int(neigh_match.group("age")),
            }
            last_field = None
            continue

        if current is None:
            continue

        if "Chassis ID" in line and ":" in line and "type" not in line:
            value = line.split(":", 1)[1].strip()
            current["neighbor_chassis_id"] = normalize_mac(value)
            last_field = None
        elif "Port ID" in line and ":" in line and "type" not in line:
            value = line.split(":", 1)[1].strip()
            current["neighbor_port_id"] = _strip_quotes(value)
            last_field = None
        elif "System Name" in line and ":" in line:
            current["neighbor_name"] = _strip_quotes(line.split(":", 1)[1].strip())
            last_field = None
        elif "System Description" in line and ":" in line:
            value = _strip_quotes(line.split(":", 1)[1].strip().rstrip("\\"))
            current["neighbor_description"] = value or ""
            last_field = "neighbor_description"
        elif last_field == "neighbor_description" and line.strip():
            continuation = line.strip().rstrip("\\")
            current["neighbor_description"] = (current.get("neighbor_description") or "") + continuation
        elif "Management Address" in line and ":" in line and "Subtype" not in line:
            value = line.split(":", 1)[1].strip()
            ip_match = IPV4_RE.search(value)
            if ip_match:
                current["neighbor_mgmt_ip"] = ip_match.group(0)
            last_field = None
        elif "System Capabilities" in line and ":" in line:
            value = _strip_quotes(line.split(":", 1)[1].strip()) or ""
            current["capabilities"] = [x.strip() for x in value.split(",") if x.strip()]
            last_field = None
        elif "Enabled Capabilities" in line and ":" in line:
            value = _strip_quotes(line.split(":", 1)[1].strip()) or ""
            current["enabled_capabilities"] = [x.strip() for x in value.split(",") if x.strip()]
            last_field = None
        elif "Operational MAU Type" in line and ":" in line:
            current["mau_type"] = line.split(":", 1)[1].strip()
            last_field = None
        elif "Port VLAN Identifier" in line and ":" in line:
            current["port_vlan_id"] = _to_int(line.split(":", 1)[1].strip())
            last_field = None

    flush()
    return neighbors


def parse_lldp_neighbors_summary(output: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in (output or "").splitlines():
        if not re.match(r"^\s*\d+\s+", line):
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        rows.append({
            "local_port": parts[0],
            "neighbor_chassis_id": normalize_mac(parts[1]),
            "neighbor_port_id": parts[2],
            "ttl": _to_int(parts[3]),
            "age_seconds": _to_int(parts[4]),
            "neighbor_name": " ".join(parts[5:]),
            "vendor": VENDOR_KEY,
        })
    return rows


def parse_show_system(output: str) -> Dict[str, Any]:
    text = output or ""
    data: Dict[str, Any] = {"vendor": VENDOR_KEY}

    key_map = {
        "SysName": "sys_name",
        "SysLocation": "sys_location",
        "SysContact": "sys_contact",
        "System MAC": "system_mac",
        "System Type": "system_type",
        "SysHealth check": "sys_health",
        "Current State": "current_state",
        "Image Selected": "image_selected",
        "Image Booted": "image_booted",
        "Config Selected": "config_selected",
        "Config Booted": "config_booted",
        "System UpTime": "uptime",
        "Boot Count": "boot_count",
    }
    for label, key in key_map.items():
        m = re.search(rf"^{re.escape(label)}:\s*(.+)$", text, re.M)
        if m:
            val = m.group(1).strip()
            data[key] = int(val) if key == "boot_count" and val.isdigit() else val

    primary = re.search(r"^Primary ver:\s*(\S+)\s*(?:\n\s+(patch\S+))?", text, re.M)
    if primary:
        data["primary_version"] = " ".join(x for x in primary.groups() if x)
    secondary = re.search(r"^Secondary ver:\s*(\S+)\s*(?:\n\s+(patch\S+))?", text, re.M)
    if secondary:
        data["secondary_version"] = " ".join(x for x in secondary.groups() if x)

    switch_line = re.search(r"^Switch\s+:\s*(?P<part>\S+)\s+(?P<serial>\S+)\s+Rev\s+(?P<rev>\S+)\s+BootROM:\s*(?P<bootrom>\S+)\s+IMG:\s*(?P<img>\S+)", text, re.M)
    if switch_line:
        data.update({
            "switch_part": switch_line.group("part"),
            "switch_serial": switch_line.group("serial"),
            "switch_rev": switch_line.group("rev"),
            "bootrom": switch_line.group("bootrom"),
            "image": switch_line.group("img"),
        })

    image_line = re.search(r"Image\s+:\s*ExtremeXOS version\s+(?P<version>\S+)\s+(?P<patch>\S+)", text)
    if image_line:
        data["exos_version"] = image_line.group("version")
        data["exos_patch"] = image_line.group("patch")

    temp = re.search(r"^Switch\s+:\s*(?P<model>\S+)\s+(?P<temp>[0-9.]+)\s+(?P<status>\S+)\s+(?P<min>\S+)\s+(?P<normal>\S+)\s+(?P<max>\S+)", text, re.M)
    if temp:
        data["temperature"] = {
            "model": temp.group("model"),
            "temp_c": float(temp.group("temp")),
            "status": temp.group("status"),
            "min": temp.group("min"),
            "normal_range": temp.group("normal"),
            "max": temp.group("max"),
        }

    psus = []
    for psu in re.finditer(r"PowerSupply\s+(?P<num>\d+)\s+information:\s*\n\s*State\s+:\s*(?P<state>.+)", text):
        psus.append({"psu": psu.group("num"), "state": psu.group("state").strip()})
    if psus:
        data["power_supplies"] = psus

    fans = []
    for fan in re.finditer(r"Fan-(?P<num>\d+):\s+(?P<state>Operational|Failed|Unknown)(?:\s+at\s+(?P<rpm>\d+)\s+RPM)?", text):
        fans.append({"fan": f"Fan-{fan.group('num')}", "state": fan.group("state"), "rpm": _to_int(fan.group("rpm"))})
    if fans:
        data["fans"] = fans

    odo = re.search(r"^Switch\s+:\s*(?P<model>\S+)\s+(?P<days>\d+)\s+(?P<date>[A-Za-z]+-\d+-\d{4})", text, re.M)
    if odo:
        data["odometer"] = {"model": odo.group("model"), "service_days": int(odo.group("days")), "first_recorded_start_date": odo.group("date")}

    return data


def summarize_health(parsed: Dict[str, Any], ports: Optional[List[Dict[str, Any]]] = None,
                     rx: Optional[List[Dict[str, Any]]] = None,
                     tx: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    sys_health = (parsed or {}).get("sys_health", "")
    current_state = (parsed or {}).get("current_state", "")
    if current_state and current_state.upper() != "OPERATIONAL":
        findings.append({"severity": "critical", "title": "Extreme switch not operational", "detail": current_state})
    if sys_health and "normal" not in sys_health.lower():
        findings.append({"severity": "critical", "title": "Extreme SysHealth not normal", "detail": sys_health})
    temp = (parsed or {}).get("temperature") or {}
    if temp and str(temp.get("status", "")).lower() != "normal":
        findings.append({"severity": "critical", "title": "Extreme temperature status not normal", "detail": str(temp)})
    for fan in (parsed or {}).get("fans", []) or []:
        if fan.get("state") != "Operational":
            findings.append({"severity": "critical", "title": "Extreme fan not operational", "detail": str(fan)})
    for row in ports or []:
        if row.get("port_state_code") == "F":
            findings.append({"severity": "warning", "title": f"Port {row['port']} disabled by link-flap detection", "detail": str(row)})
        if row.get("link_state") == "active" and row.get("duplex") and row.get("duplex") != "FULL":
            findings.append({"severity": "warning", "title": f"Port {row['port']} not full duplex", "detail": str(row)})
    for row in rx or []:
        if row.get("link_state") == "active" and any(row.get(k, 0) > 0 for k in ["rx_crc", "rx_frag", "rx_jabber", "rx_align", "rx_lost"]):
            findings.append({"severity": "info", "title": f"Port {row['port']} has RX errors", "detail": str(row)})
    for row in tx or []:
        if row.get("link_state") == "active" and any(row.get(k, 0) > 0 for k in ["tx_late_collisions", "tx_errors", "tx_lost", "tx_parity"]):
            findings.append({"severity": "warning", "title": f"Port {row['port']} has TX errors", "detail": str(row)})
    return findings
