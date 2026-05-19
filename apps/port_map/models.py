from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional


INFRA_KEYWORDS = (
    "switch", "sw", "core", "dist", "distribution", "gateway", "gw", "firewall",
    "router", "rtr", "watchguard", "nomadix", "mx", "fortigate", "palo", "uplink",
)
AP_KEYWORDS = ("ruckus", "ap", "access point", "h510", "r510", "r550", "r650", "r750", "zf", "r7")


@dataclass
class MacEntry:
    mac: str
    vlan: str = ""
    type: str = "dynamic"
    raw: str = ""


@dataclass
class LldpNeighbor:
    local_port: str
    system_name: str = ""
    hostname: str = ""
    chassis_id: str = ""
    port_id: str = ""
    port_description: str = ""
    management_ip: str = ""
    capabilities: List[str] = field(default_factory=list)
    raw: str = ""
    confidence: str = "low"

    @property
    def confident_name(self) -> str:
        if self.confidence == "high":
            return self.system_name or self.hostname
        return ""

    @property
    def display_name(self) -> str:
        return self.system_name or self.hostname or self.management_ip or self.chassis_id or "Unknown neighbor"


@dataclass
class PortRecord:
    switch_id: str
    switch_name: str
    switch_ip: str
    vendor: str
    port: str
    status: str = ""
    speed: str = ""
    duplex: str = ""
    description: str = ""
    vlan: str = ""
    tagged_vlans: List[str] = field(default_factory=list)
    lldp: Optional[LldpNeighbor] = None
    macs: List[MacEntry] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def confident_device(self) -> str:
        return self.lldp.confident_name if self.lldp else ""

    @property
    def category(self) -> str:
        name = " ".join([
            self.description or "",
            self.confident_device or "",
            self.lldp.display_name if self.lldp else "",
        ]).lower()
        caps = " ".join(self.lldp.capabilities).lower() if self.lldp else ""
        if any(k in name for k in INFRA_KEYWORDS) or any(k in caps for k in ("bridge", "router")):
            return "infrastructure"
        if any(k in name for k in AP_KEYWORDS) or "wlan" in caps:
            return "ap"
        if self.lldp:
            return "endpoint"
        if self.macs:
            return "edge"
        return "empty"

    @property
    def rename_suggestion(self) -> str:
        if self.confident_device:
            remote_port = self.lldp.port_id if self.lldp else ""
            return f"{self.confident_device} {remote_port}".strip()[:64]
        return ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category
        d["confident_device"] = self.confident_device
        d["rename_suggestion"] = self.rename_suggestion
        d["mac_count"] = len(self.macs)
        return d


@dataclass
class SwitchScan:
    switch_id: str
    ip: str
    hostname: str
    vendor: str
    ports: List[PortRecord] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "switch_id": self.switch_id,
            "ip": self.ip,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "ports": [p.to_dict() for p in self.ports],
            "raw": self.raw,
        }
