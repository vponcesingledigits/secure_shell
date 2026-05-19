"""Vendor-aware command catalogs and paging commands."""

from __future__ import annotations

from typing import Dict, List

from .models import Vendor


DETECTION_COMMANDS: List[str] = [
    "show version",
]

PAGING_DISABLE_COMMANDS: Dict[Vendor, List[str]] = {
    Vendor.RUCKUS_ICX: ["skip-page-display", "terminal length 0"],
    Vendor.ARUBA_CX: ["no page", "terminal length 1000"],
    Vendor.PROCURVE: ["no page"],
    Vendor.CISCO_IOS: ["terminal length 0", "terminal width 511"],
    Vendor.TPLINK_MEDIA_PANEL: ["terminal length 0", "no clipaging"],
    Vendor.EXTREME_EXOS: ["disable clipaging"],
    Vendor.UNKNOWN: ["terminal length 0", "no page"],
}

CENTRAL_DETECTION_COMMANDS: Dict[Vendor, List[str]] = {
    Vendor.ARUBA_CX: ["show aruba-central"],
}

BASELINE_COMMANDS: Dict[Vendor, List[str]] = {
    Vendor.RUCKUS_ICX: [
        "show version",
        "show chassis",
        "show int br",
        "show vlan brief",
        "show lldp neighbors",
        "show inline power",
        "show log",
    ],
    Vendor.ARUBA_CX: [
        "show version",
        "show system",
    "show run | include ;",
        "show interface brief",
        "show vlan",
        "show lldp neighbor-info",
        "show aruba-central",
        "show logging -r",
    ],
    Vendor.PROCURVE: [
        "show version",
        "show system-information",
        "show interfaces brief",
        "show vlan",
        "show lldp info remote-device",
        "show logging -r",
    ],
    Vendor.CISCO_IOS: [
        "show version",
        "show interfaces status",
        "show vlan brief",
        "show lldp neighbors detail",
        "show logging",
    ],
    Vendor.TPLINK_MEDIA_PANEL: [
        "show system-info",
        "show interface status",
        "show vlan",
        "show lldp neighbor-information",
    ],
    Vendor.EXTREME_EXOS: [
        "show system",
        "show ports no-refresh",
        "show ports txerrors no-refresh port-number",
        "show lldp neighbors detailed",
        "show fdb",
        "show log",
    ],
    Vendor.UNKNOWN: ["show version"],
}


def get_paging_disable_commands(vendor: Vendor) -> List[str]:
    return PAGING_DISABLE_COMMANDS.get(vendor, PAGING_DISABLE_COMMANDS[Vendor.UNKNOWN])


def get_baseline_commands(vendor: Vendor) -> List[str]:
    return BASELINE_COMMANDS.get(vendor, BASELINE_COMMANDS[Vendor.UNKNOWN])


# ---------------------------------------------------------------------------
# MAC Trace targeted command catalog
# ---------------------------------------------------------------------------
# These helpers are shared so MAC Trace, Port Map, Topology, Switch Health, and
# future diagnostics can use the same vendor-aware command patterns instead of
# carrying separate command lists in each app.

def _mac_formats_for_trace(mac: str) -> dict:
    from shared.security.validators import mac_formats
    return mac_formats(mac)


def _vendor_text(vendor) -> str:
    value = getattr(vendor, "value", vendor)
    return str(value or "").lower()


def get_mac_trace_lookup_commands(vendor, mac: str) -> list[str]:
    """Return strict vendor-specific single-MAC lookup commands.

    Format policy:
    - ProCurve / ArubaOS-Switch: 123456-123456 only.
    - Ruckus / Cisco / TP-Link: 1234.1234.1234.
    - Aruba CX: colon primary with dotted include fallback.
    """
    f = _mac_formats_for_trace(mac)
    dot = f.get("dot", mac)
    colon = f.get("colon", mac)
    dash6 = f.get("dash6", mac)
    v = _vendor_text(vendor)

    if "procurve" in v or "aruba_procurve" in v or "arubaos-switch" in v:
        return [
            f"show mac-address | includ {dash6}",
            f"show mac-address {dash6}",
        ]

    if "ruckus" in v or "icx" in v or "brocade" in v:
        return [f"show mac-address {dot}"]

    if "tp-link" in v or "tplink" in v or "tp_link" in v:
        return [
            f"show mac address-table address {dot}",
            f"show mac-address {dot}",
        ]

    if "cisco" in v or "ios" in v:
        return [
            f"show mac address-table address {dot}",
            f"show mac address-table | include {dot}",
        ]

    if "cx" in v or "aruba_cx" in v or "aos-cx" in v:
        return [
            f"show mac-address-table address {colon}",
            f"show mac-address-table | include {colon}",
            f"show mac-address-table | include {dot}",
        ]

    if "extreme" in v or "exos" in v or "switch_engine" in v:
        return [
            f"show fdb {colon}",
            f"show fdb | include {colon}",
            f"show fdb | include {dot}",
        ]

    return [
        f"show mac-address {dot}",
        f"show mac-address {dash6}",
    ]

def get_mac_trace_port_detail_commands(vendor, port: str | None) -> list[str]:
    """Return LLDP + minimal health commands scoped only to the learned source port.

    Fast LLDP identity patterns:
    - ProCurve: compatible single-field filters because some versions reject
      multi-pattern grep.
    - Ruckus ICX: filtered LLDP detail can return name/address/description
      without dumping the full detail block.
    """
    if not port:
        return []

    from shared.security.validators import validate_port_token
    p = validate_port_token(port)
    v = _vendor_text(vendor)

    if "procurve" in v or "aruba_procurve" in v or "arubaos-switch" in v or "hp_aruba_procurve" in v:
        cmds = [
            f"sh lldp inf rem {p} | i SysName",
            f"sh lldp inf rem {p} | i Desc",
            f"sh lldp inf rem {p} | i Add",
            f"sh int custom {p} speed | i 1",
            f"show interfaces brief | include {p}",
            f"show interfaces {p}",
            f"show log -r | i {p}",
        ]
    elif "ruckus" in v or "icx" in v or "brocade" in v:
        cmds = [
            f"show lldp neighbor detail port eth {p} | include name|add|desc",
            f"show interface brief | include {p}",
            f"show interface ethernet {p}",
            f"show statistics ethernet {p}",
            f"show logging | include {p} | exclude OPTICAL",
        ]
    elif "cx" in v or "aruba_cx" in v or "aos-cx" in v:
        cmds = [
            f"show lldp neighbor-info {p} detail",
            f"show interface brief | include {p}",
            f"show interface {p}",
            f"show events | include {p}",
        ]
    elif "cisco" in v or "ios" in v:
        cmds = [
            f"show lldp neighbors interface {p} detail",
            f"show interfaces status | include {p}",
            f"show interfaces {p}",
            f"show logging | include {p}",
        ]
    elif "tp-link" in v or "tplink" in v or "tp_link" in v:
        cmds = [
            f"show lldp neighbor-information interface {p}",
            f"show interface status | include {p}",
            f"show interface {p}",
        ]
    elif "extreme" in v or "exos" in v or "switch_engine" in v:
        cmds = [
            "show lldp neighbors detailed | include Name|Address",
            "show lldp neighbors detailed",
            "show ports no-refresh",
            "show ports txerrors no-refresh port-number",
            f"show log | include {p}",
        ]
    else:
        cmds = [
            f"show lldp info remote-device {p}",
            f"sh lldp inf rem {p} | i SysName",
            f"sh lldp inf rem {p} | i Desc",
            f"sh lldp inf rem {p} | i Add",
            f"show lldp neighbor detail port eth {p} | include name|add|desc",
            f"show interface brief | include {p}",
            f"show interfaces brief | include {p}",
            f"show interface {p}",
            f"show interfaces {p}",
        ]

    return list(dict.fromkeys(cmds))

def mac_trace_clean_mac(mac):
    from shared.security.validators import normalize_mac_strict
    return normalize_mac_strict(mac)

def mac_trace_formats(mac):
    from shared.security.validators import mac_formats
    return mac_formats(mac)

def mac_trace_vendor_lookup_commands(vendor, mac):
    f = mac_trace_formats(mac)
    v = str(getattr(vendor, "value", vendor) or "").lower()

    if "procurve" in v or "hp_aruba_procurve" in v or "aruba_procurve" in v or "arubaos-switch" in v:
        return [
            f"show mac-address | includ {f['dash6']}",
            f"show mac-address {f['dash6']}",
        ]

    if "ruckus" in v or "icx" in v or "tp-link" in v or "tplink" in v or "tp_link" in v:
        return [f"show mac-address {f['dot']}"]

    if "cisco" in v or "ios" in v:
        return [
            f"show mac address-table address {f['dot']}",
            f"show mac address-table | include {f['dot']}",
        ]

    if "aruba_cx" in v or "aos-cx" in v or "cxos" in v:
        return [
            f"show mac-address-table address {f['colon']}",
            f"show mac-address-table | include {f['colon']}",
            f"show mac-address-table | include {f['dot']}",
        ]

    return [f"show mac-address {f['dot']}", f"show mac-address {f['dash6']}"]
# --- End MAC Trace shared vendor MAC commands ---

def get_mac_trace_ap_power_commands(vendor, port: str | None) -> list[str]:
    """Return PoE commands only after the traced port is identified as AP-facing."""
    if not port:
        return []

    p = str(port).strip()
    v = _vendor_text(vendor)

    if "procurve" in v or "aruba_procurve" in v or "arubaos-switch" in v:
        return [f"show power-over-ethernet br {p}"]

    if "ruckus" in v or "icx" in v or "brocade" in v:
        return [f"show inline power {p}", f"show inline power detail | include {p}"]

    if "cx" in v or "aruba_cx" in v or "aos-cx" in v:
        return [f"show power-over-ethernet {p}"]

    if "cisco" in v or "ios" in v:
        return [f"show power inline {p}"]

    if "tp-link" in v or "tplink" in v or "tp_link" in v:
        return [f"show power inline {p}", f"show poe interface {p}"]

    if "extreme" in v or "exos" in v or "switch_engine" in v:
        return ["show inline-power"]

    return []



# ---------------------------------------------------------------------------
# Shared command set helpers used across shell modules
# ---------------------------------------------------------------------------
# Keep multi-tool command choices here. Modules can still keep local parsers/UI,
# but command selection should be centralized so new vendor support reaches every
# tool consistently.

def normalize_vendor_key(vendor) -> str:
    v = str(getattr(vendor, "value", vendor) or "").lower().replace("-", "_").replace(" ", "_")
    if "extreme" in v or "exos" in v or "switch_engine" in v:
        return "extreme_exos"
    if "ruckus" in v or "icx" in v or "brocade" in v:
        return "ruckus"
    if "aruba_cx" in v or "aos_cx" in v or "cxos" in v:
        return "aruba_cx"
    if "procurve" in v or "arubaos_switch" in v or "hp_aruba" in v:
        return "procurve"
    if "cisco" in v or "ios" in v:
        return "cisco_ios"
    if "tplink" in v or "tp_link" in v or "tp-link" in v:
        return "tplink"
    return v or "unknown"


def get_interface_inventory_command(vendor) -> str:
    return {
        "ruckus": "show interfaces brief wide",
        "aruba_cx": "show interface brief",
        "procurve": "show interface brief",
        "cisco_ios": "show interfaces status",
        "tplink": "show interface status",
        "extreme_exos": "show ports no-refresh",
    }.get(normalize_vendor_key(vendor), "show interface brief")


def get_lldp_detail_command(vendor, port: str | None = None) -> str:
    from shared.security.validators import validate_port_token
    p = validate_port_token(port)
    key = normalize_vendor_key(vendor)
    if key == "ruckus":
        return f"show lldp neighbor detail port eth {p}" if p else "show lldp neighbors detail"
    if key == "aruba_cx":
        return f"show lldp neighbor-info {p} detail" if p else "show lldp neighbor-info detail"
    if key == "procurve":
        return f"show lldp info remote-device {p}" if p else "show lldp info remote-device"
    if key == "cisco_ios":
        return f"show lldp neighbors interface {p} detail" if p else "show lldp neighbors detail"
    if key == "tplink":
        return f"show lldp neighbor-information interface {p}" if p else "show lldp neighbor-information"
    if key == "extreme_exos":
        return "show lldp neighbors detailed"
    return "show lldp neighbors detail"


def get_port_mac_command(vendor, port: str) -> str:
    from shared.security.validators import validate_port_token
    p = validate_port_token(port)
    key = normalize_vendor_key(vendor)
    if key == "procurve":
        return f"show mac-add {p}"
    if key == "aruba_cx":
        return f"show mac-address-table interface {p}"
    if key == "ruckus":
        return f"show mac-add ether {p}"
    if key == "cisco_ios":
        return f"show mac address-table dynamic interface {p}"
    if key == "tplink":
        return f"show mac address-table interface {p}"
    if key == "extreme_exos":
        return f"show fdb ports {p}"
    return ""


def sanitize_port_name(name: str, max_len: int = 64) -> str:
    from shared.security.validators import sanitize_cli_label
    return sanitize_cli_label(name, max_len=max_len)


def get_port_rename_commands(vendor, port: str, name: str) -> list[str]:
    safe = sanitize_port_name(name)
    key = normalize_vendor_key(vendor)
    if key == "procurve":
        return ["config", f"port {port} name {safe}", "end", "write memory"]
    if key == "ruckus":
        return ["config t", f"interface eth {port}", f"port-name {safe}", "end", "write mem"]
    if key == "aruba_cx":
        return ["configure terminal", f"interface {port}", f"description {safe}", "end", "write memory"]
    if key == "cisco_ios":
        return ["configure terminal", f"interface {port}", f"description {safe}", "end", "write memory"]
    if key == "extreme_exos":
        return ["configure", f"configure ports {port} display-string {safe}", "save configuration"]
    return []


SWITCH_HEALTH_BASE_COMMANDS = {
    "ruckus": [
        "show version", "show stack", "show interfaces brief wide", "show statistics ethernet",
        "show logging", "show inline power", "show inline power detail", "show inline power emesg", "show chassis",
    ],
    "aruba_cx": [
        "show system", "show system resource-utilization", "show environment", "show environment temperature",
        "show interface brief", "show events", "show power-over-ethernet", "show lldp neighbor-info", "show lldp neighbor-info detail",
    ],
    "procurve": [
        "show system", "show system-information", "show run | include ;", "show interface brief", "show interfaces brief",
        "show log", "show lldp info remote-device",
    ],
    "cisco_ios": [
        "show version", "show interfaces status", "show logging", "show lldp neighbors", "show lldp neighbors detail", "show environment all",
    ],
    "extreme_exos": [
        "show system", "show ports no-refresh", "show ports txerrors no-refresh port-number",
        "show lldp neighbors detailed", "show log", "show temperature", "show power", "show fans",
    ],
    "unknown": ["show version", "show system", "show interface brief", "show logging"],
}

SHOW_TECH_COMMANDS_SHARED = {
    "ruckus": ["show tech"],
    "aruba_cx": ["show tech"],
    "procurve": ["show tech all"],
    "cisco_ios": ["show tech-support"],
    "extreme_exos": ["show tech-support"],
}

CABLE_TRIGGER_COMMANDS_SHARED = {
    "ruckus": ("phy cable-diagnostics tdr {port}", "show cable-diagnostics tdr {port}"),
}


def get_switch_health_commands(vendor, show_tech: bool = False) -> list[str]:
    key = normalize_vendor_key(vendor)
    commands = list(SWITCH_HEALTH_BASE_COMMANDS.get(key, SWITCH_HEALTH_BASE_COMMANDS["unknown"]))
    if show_tech:
        commands.extend(SHOW_TECH_COMMANDS_SHARED.get(key, []))
    return list(dict.fromkeys(commands))


def get_cable_diagnostic_commands(vendor, port: str) -> list[str]:
    pair = CABLE_TRIGGER_COMMANDS_SHARED.get(normalize_vendor_key(vendor))
    if not pair:
        return []
    return [cmd.format(port=port) for cmd in pair]


# ---------------------------------------------------------------------------
# Monitoring / Down Device Troubleshooter command catalog
# ---------------------------------------------------------------------------

def get_monitoring_status_commands(vendor) -> list[str]:
    """Return read-only port status/name commands for monitoring workflows."""
    v = _vendor_text(vendor)
    if "ruckus" in v or "icx" in v or "brocade" in v:
        return ["show int brief", "show interface brief"]
    if "cisco" in v or "ios" in v:
        return ["show interface status", "show interfaces status"]
    if "cx" in v or "aruba_cx" in v or "aos-cx" in v:
        return ["show interface brief"]
    if "procurve" in v or "hp_aruba" in v or "arubaos-switch" in v:
        return ["show name", "show interfaces brief"]
    if "tp-link" in v or "tplink" in v or "tp_link" in v:
        return ["show interface status"]
    if "extreme" in v or "exos" in v or "switch_engine" in v:
        return ["show ports no-refresh"]
    return ["show interface brief", "show interfaces brief", "show interface status", "show name"]


def get_monitoring_detail_commands(vendor, port: str | None, mac: str = "", ip: str = "") -> list[str]:
    """Return read-only scoped evidence commands for one candidate port."""
    if not port:
        return []
    p = str(port).strip()
    v = _vendor_text(vendor)
    cmds: list[str]
    if "ruckus" in v or "icx" in v or "brocade" in v:
        cmds = [
            f"show interfaces eth {p}",
            f"show statistics ethernet {p}",
            f"show lldp neighbors detail port eth {p}",
            f"show lldp neighbor detail port eth {p} | include name|add|desc",
            f"show vlan brief eth {p}",
            f"show logging | include {p} | exclude OPTICAL",
        ]
    elif "cisco" in v or "ios" in v:
        cmds = [
            f"show interfaces {p}",
            f"show lldp neighbors interface {p} detail",
            f"show run interface {p}",
            f"show logging | include {p}",
        ]
    elif "cx" in v or "aruba_cx" in v or "aos-cx" in v:
        cmds = [
            f"show interface {p}",
            f"show lldp neighbor-info {p} detail",
            f"show run interface {p}",
            f"show events | include {p}",
        ]
    elif "procurve" in v or "hp_aruba" in v or "arubaos-switch" in v:
        cmds = [
            f"show interfaces {p}",
            f"show lldp info remote-device {p}",
            f"show lldp inf rem {p} | i SysName",
            f"show lldp inf rem {p} | i Desc",
            f"show lldp inf rem {p} | i Add",
            f"show log -r | i {p}",
        ]
    elif "tp-link" in v or "tplink" in v or "tp_link" in v:
        cmds = [
            f"show interface {p}",
            f"show lldp neighbor-information interface {p}",
        ]
    elif "extreme" in v or "exos" in v or "switch_engine" in v:
        cmds = [
            "show ports no-refresh",
            "show ports txerrors no-refresh port-number",
            "show lldp neighbors detailed | include Name|Address",
            "show lldp neighbors detailed",
            f"show log | include {p}",
        ]
    else:
        cmds = [f"show interface {p}", f"show interfaces {p}", f"show lldp info remote-device {p}"]
    # Optional MAC/IP evidence hooks, vendor format handling is kept in MAC Trace for now.
    if mac:
        try:
            cmds.extend(get_mac_trace_lookup_commands(vendor, mac))
        except Exception:
            pass
    return list(dict.fromkeys(cmds))

# ---------------------------------------------------------------------------
# Unified command profile API - Alpha 0.7.5 normalization pass
# ---------------------------------------------------------------------------
# New and existing apps should import these helpers instead of maintaining
# isolated command catalogs.  The older helper names above are retained for
# compatibility.

COMMAND_SET_LABELS_SHARED = {
    "system": "System / Version",
    "resources": "Resource Utilization",
    "environment": "Environmental",
    "ports": "Port / Link Health",
    "poe": "PoE / Power",
    "logs": "Logs / Events",
    "lldp": "LLDP Neighbors",
    "stp": "STP / Loop Signals",
    "vlans": "VLANs",
    "mac": "MAC Table",
    "inventory": "Inventory / Chassis",
    "transceivers": "Optics / Transceivers",
    "arp": "ARP / IP Neighbors",
}

DEFAULT_SWITCH_HEALTH_SETS_SHARED = ["system", "resources", "environment", "ports", "poe", "logs", "lldp", "stp", "vlans"]

UNIFIED_COMMANDS_BY_SET = {
    "ruckus": {
        "system": ["show version", "show stack"],
        "resources": ["show cpu", "show memory"],
        "environment": ["show chassis"],
        "ports": ["show interfaces brief wide", "show statistics ethernet"],
        "poe": ["show inline power", "show inline power detail", "show inline power emesg"],
        "logs": ["show logging", "show log"],
        "lldp": ["show lldp neighbor", "show lldp neighbor detail"],
        "stp": ["show spanning-tree", "show spanning-tree detail"],
        "vlans": ["show vlan brief"],
        "mac": ["show mac-address"],
        "inventory": ["show media", "show module"],
        "transceivers": ["show media"],
        "arp": ["show arp"],
    },
    "aruba_cx": {
        "system": ["show system"],
        "resources": ["show system resource-utilization"],
        "environment": ["show environment", "show environment temperature"],
        "ports": ["show interface brief"],
        "poe": ["show power-over-ethernet"],
        "logs": ["show events", "show logging -r"],
        "lldp": ["show lldp neighbor-info", "show lldp neighbor-info detail"],
        "stp": ["show spanning-tree", "show spanning-tree detail"],
        "vlans": ["show vlan"],
        "mac": ["show mac-address-table"],
        "inventory": ["show inventory"],
        "transceivers": ["show interface transceiver"],
        "arp": ["show arp"],
    },
    "procurve": {
        "system": ["show system", "show system-information", "show version", "show run | include ;"],
        "resources": ["show cpu", "show memory"],
        "environment": ["show system-information"],
        "ports": ["show interface brief", "show interfaces brief", "show name"],
        "poe": ["show power-over-ethernet", "show power-over-ethernet brief"],
        "logs": ["show log", "show logging -r"],
        "lldp": ["show lldp info remote-device"],
        "stp": ["show spanning-tree", "show spanning-tree detail"],
        "vlans": ["show vlans", "show vlan"],
        "mac": ["show mac-address"],
        "inventory": ["show modules", "show system-information"],
        "transceivers": ["show interfaces transceiver"],
        "arp": ["show arp"],
    },
    "cisco_ios": {
        "system": ["show version"],
        "resources": ["show processes cpu", "show memory statistics"],
        "environment": ["show environment all"],
        "ports": ["show interfaces status", "show interfaces counters errors"],
        "poe": ["show power inline", "show power inline detail"],
        "logs": ["show logging"],
        "lldp": ["show lldp neighbors", "show lldp neighbors detail"],
        "stp": ["show spanning-tree", "show spanning-tree detail"],
        "vlans": ["show vlan brief"],
        "mac": ["show mac address-table"],
        "inventory": ["show inventory"],
        "transceivers": ["show interfaces transceiver detail"],
        "arp": ["show ip arp"],
    },
    "tplink": {
        "system": ["show system-info", "show version"],
        "resources": [],
        "environment": [],
        "ports": ["show interface status", "show interface configuration"],
        "poe": ["show power inline"],
        "logs": ["show logging"],
        "lldp": ["show lldp neighbor-information", "show lldp local-information"],
        "stp": ["show spanning-tree"],
        "vlans": ["show vlan"],
        "mac": ["show mac address-table"],
        "inventory": ["show system-info"],
        "transceivers": [],
        "arp": ["show arp"],
    },
    "extreme_exos": {
        "system": ["show system"],
        "resources": ["show cpu-monitoring", "show memory"],
        "environment": ["show temperature", "show power", "show fans", "show odometers"],
        "ports": ["show ports no-refresh", "show ports txerrors no-refresh port-number"],
        "poe": ["show inline-power", "show inline-power stats"],
        "logs": ["show log"],
        "lldp": ["show lldp neighbors", "show lldp neighbors detailed"],
        "stp": ["show stpd", "show stpd detail"],
        "vlans": ["show vlan"],
        "mac": ["show fdb"],
        "inventory": ["show switch", "show version"],
        "transceivers": ["show ports transceiver information"],
        "arp": ["show iparp"],
    },
    "unknown": {
        "system": ["show version", "show system", "show system-information"],
        "resources": [],
        "environment": [],
        "ports": ["show interface brief", "show interfaces brief", "show interfaces status", "show interface status"],
        "poe": ["show inline power", "show power inline", "show power-over-ethernet"],
        "logs": ["show logging", "show log", "show events"],
        "lldp": ["show lldp neighbors", "show lldp neighbor-info", "show lldp info remote-device"],
        "stp": ["show spanning-tree"],
        "vlans": ["show vlan", "show vlan brief", "show vlans"],
        "mac": ["show mac-address", "show mac address-table", "show mac-address-table"],
        "inventory": ["show inventory", "show chassis"],
        "transceivers": [],
        "arp": ["show arp", "show ip arp"],
    },
}

SWITCHPORT_COLLECTION_PROFILES = {
    "ruckus": {
        "detect": ["show version"],
        "ports": ["show interfaces brief wide", "show interfaces brief"],
        "names": ["show interfaces brief wide", "show running-config | include port-name"],
        "lldp": ["show lldp neighbors", "show lldp neighbors detail"],
        "lldp_port_filtered": "show lldp neighbor detail port eth {port} | include name|add|desc",
    },
    "aruba_cx": {
        "detect": ["show version"],
        "ports": ["show interface brief"],
        "names": ["show interface brief", "show running-config interface"],
        "lldp": ["show lldp neighbor-info", "show lldp neighbor-info detail"],
        "lldp_port_filtered": "show lldp neighbor-info {port}",
    },
    "procurve": {
        "detect": ["show system", "show version", "show run | include ;"],
        "ports": ["show interfaces brief", "show name"],
        "names": ["show name"],
        "lldp": ["show lldp info remote-device", "show lldp info remote-device detail"],
        "lldp_port_filtered": "show lldp info remote-device {port}",
    },
    "cisco_ios": {
        "detect": ["show version"],
        "ports": ["show interfaces status", "show interface status"],
        "names": ["show interfaces status", "show running-config | include ^interface|description"],
        "lldp": ["show lldp neighbors", "show lldp neighbors detail"],
        "lldp_port_filtered": "show lldp neighbors interface {port} detail",
    },
    "tplink": {
        "detect": ["show system-info", "show version"],
        "ports": ["show interface status", "show interfaces status"],
        "names": ["show interface status", "show running-config | include description"],
        "lldp": ["show lldp neighbor-information", "show lldp neighbors", "show lldp neighbor-information detail"],
        "lldp_port_filtered": "show lldp neighbor-information interface {port}",
    },
    "extreme_exos": {
        "detect": ["show system"],
        "ports": ["show ports no-refresh"],
        "names": ["show ports description"],
        "lldp": ["show lldp neighbors", "show lldp neighbors detailed"],
        "lldp_port_filtered": "show lldp neighbors detailed ports {port}",
    },
}
SWITCHPORT_COLLECTION_PROFILES["hp_procurve"] = SWITCHPORT_COLLECTION_PROFILES["procurve"]


def dedupe_commands(commands: list[str]) -> list[str]:
    return list(dict.fromkeys([c for c in commands if c]))


def get_commands_for_sets(vendor, selected_sets: list[str] | None = None) -> list[str]:
    key = normalize_vendor_key(vendor)
    selected = selected_sets or DEFAULT_SWITCH_HEALTH_SETS_SHARED
    catalog = UNIFIED_COMMANDS_BY_SET.get(key, UNIFIED_COMMANDS_BY_SET["unknown"])
    out: list[str] = []
    for set_key in selected:
        out.extend(catalog.get(set_key, []))
    return dedupe_commands(out)


def get_available_command_sets() -> list[dict[str, object]]:
    return [
        {"key": key, "label": label, "default": key in DEFAULT_SWITCH_HEALTH_SETS_SHARED}
        for key, label in COMMAND_SET_LABELS_SHARED.items()
    ]


def get_switchport_collection_profile(vendor) -> dict:
    key = normalize_vendor_key(vendor)
    return SWITCHPORT_COLLECTION_PROFILES.get(key, SWITCHPORT_COLLECTION_PROFILES.get("procurve", {}))


def get_switchport_collection_commands(vendor, intents: list[str] | None = None) -> list[str]:
    profile = get_switchport_collection_profile(vendor)
    intents = intents or ["detect", "ports", "names", "lldp"]
    out: list[str] = []
    for intent in intents:
        value = profile.get(intent, [])
        if isinstance(value, list):
            out.extend(value)
        elif isinstance(value, str):
            out.append(value)
    return dedupe_commands(out)


def get_config_session_commands(vendor) -> dict[str, str]:
    """Return canonical config-mode enter/exit/save commands for write-capable tools."""
    key = normalize_vendor_key(vendor)
    if key == "procurve":
        return {"enter": "config", "exit": "end", "save": "write memory"}
    if key == "ruckus":
        return {"enter": "config t", "exit": "end", "save": "write mem"}
    if key in {"aruba_cx", "cisco_ios"}:
        return {"enter": "configure terminal", "exit": "end", "save": "write memory"}
    if key == "tplink":
        return {"enter": "configure", "exit": "exit", "save": "copy running-config startup-config"}
    if key == "extreme_exos":
        return {"enter": "configure", "exit": "exit", "save": "save configuration"}
    return {"enter": "configure terminal", "exit": "end", "save": "write memory"}


def get_running_config_command(vendor) -> str:
    key = normalize_vendor_key(vendor)
    if key == "extreme_exos":
        return "show configuration"
    return "show running-config"


def get_hostname_command(vendor) -> str:
    key = normalize_vendor_key(vendor)
    if key == "aruba_cx":
        return "show hostname"
    if key == "procurve":
        return "show system-information"
    if key == "extreme_exos":
        return "show system"
    return "show running-config | include hostname"


def get_forescout_collection_commands(vendor) -> dict[str, str]:
    session = get_config_session_commands(vendor)
    commands = {
        "run": get_running_config_command(vendor),
        "hostname": get_hostname_command(vendor),
        "remediate_enter": session["enter"],
        "remediate_exit": session["exit"],
        "save": session["save"],
    }
    if normalize_vendor_key(vendor) == "aruba_cx":
        commands["central"] = "show aruba-central"
    return commands


# Replace earlier local switch-health helper output with the unified catalog while
# preserving the public function name used by older modules.
def get_switch_health_commands(vendor, show_tech: bool = False) -> list[str]:  # type: ignore[no-redef]
    commands = get_commands_for_sets(vendor, DEFAULT_SWITCH_HEALTH_SETS_SHARED)
    if show_tech:
        commands.extend(SHOW_TECH_COMMANDS_SHARED.get(normalize_vendor_key(vendor), []))
    return dedupe_commands(commands)


# Strengthen rename helper for TP-Link while preserving older behavior.
def get_port_rename_commands(vendor, port: str, name: str) -> list[str]:  # type: ignore[no-redef]
    safe = sanitize_port_name(name)
    key = normalize_vendor_key(vendor)
    if key == "procurve":
        return ["config", f"port {port} name {safe}", "end", "write memory"]
    if key == "ruckus":
        return ["config t", f"interface eth {port}", f"port-name {safe}", "end", "write mem"]
    if key == "aruba_cx":
        return ["configure terminal", f"interface {port}", f"description {safe}", "end", "write memory"]
    if key == "cisco_ios":
        return ["configure terminal", f"interface {port}", f"description {safe}", "end", "write memory"]
    if key == "tplink":
        return ["configure", f"interface gigabitEthernet {port}", f"description {safe}", "exit", "exit", "copy running-config startup-config"]
    if key == "extreme_exos":
        return ["configure", f"configure ports {port} display-string {safe}", "save configuration"]
    return []
