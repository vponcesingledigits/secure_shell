"""Shared switchport collection command profiles for shell modules.

Used by Switchport Name Normalizer, and safe for Topology / Port Map / LLDP Renamer
adoption. Commands are intentionally grouped by intent so modules can collect only
what they need.
"""

COMMAND_PROFILES = {
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
    "hp_procurve": {
        "detect": ["show system", "show version"],
        "ports": ["show interfaces brief", "show name"],
        "names": ["show name"],
        "lldp": ["show lldp info remote-device", "show lldp info remote-device detail"],
        "lldp_port_filtered": "show lldp info remote-device {port}",
    },
    "cisco_ios": {
        "detect": ["show version"],
        "ports": ["show interface status", "show interfaces status"],
        "names": ["show interface status", "show running-config | include ^interface|description"],
        "lldp": ["show lldp neighbors", "show lldp neighbors detail"],
        "lldp_port_filtered": "show lldp neighbors {port} detail",
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
