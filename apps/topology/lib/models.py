from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class LLDPNeighbor:
    local_device: str = ""
    local_ip: str = ""
    local_port: str = ""
    remote_hostname: str = ""
    remote_ip: str = ""
    remote_port: str = ""
    remote_description: str = ""
    remote_capabilities: List[str] = field(default_factory=list)
    role: str = "unknown"
    vendor_hint: str = ""
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SwitchPort:
    switch_name: str
    local_port_id: str
    local_port_name: str = ""
    patch_panel_port: str = ""  # intentionally blank by default
    remote_hostname: str = ""
    remote_ip: str = ""
    remote_port: str = ""
    remote_role: str = ""
    suggested_port_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["patch_panel_port"] = ""  # enforce blank export rule
        return data


@dataclass
class DeviceRecord:
    local_id: str
    name: str
    role: str = "unknown"
    management_ip: str = ""
    ssh_target_ip: str = ""
    vendor: str = "unknown"
    model: str = ""
    serial_number: str = ""
    software_version: str = ""
    mstp_priority: str = ""
    discovered_from: str = ""
    source: str = "lldp"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LinkRecord:
    local_id: str
    source_device: str
    source_ip: str = ""
    source_port: str = ""
    target_device: str = ""
    target_ip: str = ""
    target_port: str = ""
    target_role: str = "unknown"
    source: str = "lldp"

    def canonical_key(self) -> tuple[str, str, str, str]:
        left = (self.source_device or self.source_ip or "").lower()
        right = (self.target_device or self.target_ip or "").lower()
        lp = self.source_port or ""
        rp = self.target_port or ""
        if left <= right:
            return (left, lp, right, rp)
        return (right, rp, left, lp)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TopologyProject:
    schema: str = "single_digits.topology_asbuilt.v1"
    generated_at: str = field(default_factory=utc_now)
    site: Dict[str, Any] = field(default_factory=dict)
    scan_settings: Dict[str, Any] = field(default_factory=dict)
    devices: List[Dict[str, Any]] = field(default_factory=list)
    links: List[Dict[str, Any]] = field(default_factory=list)
    ports: List[Dict[str, Any]] = field(default_factory=list)
    raw_neighbors: List[Dict[str, Any]] = field(default_factory=list)
    topology_tree: List[Dict[str, Any]] = field(default_factory=list)
    isp_circuits: List[Dict[str, Any]] = field(default_factory=list)
    manual_firewalls: List[Dict[str, Any]] = field(default_factory=list)
    manual_gateways: List[Dict[str, Any]] = field(default_factory=list)
    manual_esxi_hosts: List[Dict[str, Any]] = field(default_factory=list)
    manual_pga_interfaces: List[Dict[str, Any]] = field(default_factory=list)
    manual_rpm_vms: List[Dict[str, Any]] = field(default_factory=list)
    vlans: List[Dict[str, Any]] = field(default_factory=list)
    manual_links: List[Dict[str, Any]] = field(default_factory=list)
    documentation_checklist: Dict[str, Any] = field(default_factory=dict)
    revision_history: List[Dict[str, Any]] = field(default_factory=list)
    exports: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
