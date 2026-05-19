"""Shared data models for the Single Digits Engineering Platform shell."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class Vendor(str, Enum):
    UNKNOWN = "unknown"
    RUCKUS_ICX = "ruckus_icx"
    ARUBA_CX = "aruba_cxos"
    PROCURVE = "hp_aruba_procurve"
    CISCO_IOS = "cisco_ios"
    TPLINK_MEDIA_PANEL = "tplink_media_panel"
    EXTREME_EXOS = "extreme_exos"


class AuthMethod(str, Enum):
    USER_PROVIDED = "user_provided"
    TPLINK_ADMIN_ADMIN = "tplink_admin_admin"
    TPLINK_LEGACY_FALLBACK = "tplink_legacy_fallback"


@dataclass(frozen=True)
class SwitchTarget:
    host: str
    port: int = 22
    label: Optional[str] = None

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class Credentials:
    username: str
    password: str

    def __repr__(self) -> str:
        return f"Credentials(username={self.username!r}, password='[REDACTED]')"


@dataclass
class SSHOptions:
    timeout: int = 12
    banner_timeout: int = 15
    auth_timeout: int = 15
    command_timeout: int = 25
    look_for_keys: bool = False
    allow_agent: bool = False
    debug: bool = False
    default_port: int = 22
    concurrency: int = 10
    max_concurrency: int = 25
    old_kex: bool = True

    def normalized_concurrency(self) -> int:
        return max(1, min(int(self.concurrency or 10), int(self.max_concurrency or 25)))


@dataclass
class CommandResult:
    command: str
    output: str
    ok: bool = True
    error: Optional[str] = None


@dataclass
class VendorDetection:
    vendor: Vendor = Vendor.UNKNOWN
    hostname: Optional[str] = None
    version: Optional[str] = None
    model: Optional[str] = None
    raw_evidence: str = ""
    confidence: float = 0.0
    central_connected: Optional[bool] = None


@dataclass
class SSHSessionResult:
    target: SwitchTarget
    ok: bool
    vendor: Vendor = Vendor.UNKNOWN
    hostname: Optional[str] = None
    auth_method: AuthMethod = AuthMethod.USER_PROVIDED
    non_standard_password_note: Optional[str] = None
    prompt: Optional[str] = None
    detection: Optional[VendorDetection] = None
    command_results: List[CommandResult] = field(default_factory=list)
    error: Optional[str] = None
    debug_log: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["vendor"] = self.vendor.value if isinstance(self.vendor, Vendor) else self.vendor
        data["auth_method"] = self.auth_method.value if isinstance(self.auth_method, AuthMethod) else self.auth_method
        data["target"] = asdict(self.target)
        if self.detection:
            data["detection"]["vendor"] = self.detection.vendor.value
        return data


@dataclass
class PortInfo:
    port: str
    status: Optional[str] = None
    speed: Optional[str] = None
    duplex: Optional[str] = None
    description: Optional[str] = None
    untagged_vlan: Optional[str] = None
    tagged_vlans: List[str] = field(default_factory=list)
    mac_addresses: List[str] = field(default_factory=list)
    neighbor_name: Optional[str] = None
    neighbor_port: Optional[str] = None
    neighbor_ip: Optional[str] = None


@dataclass
class ScanJobConfig:
    raw_targets: str
    credentials: Credentials
    ssh_options: SSHOptions = field(default_factory=SSHOptions)
    commands: List[str] = field(default_factory=list)
