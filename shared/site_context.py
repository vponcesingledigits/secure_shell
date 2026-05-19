from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

APP_NAME = "SingleDigitsEngineeringPlatform"


def _base_dir() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if local:
        return Path(local) / APP_NAME
    return Path.home() / f".{APP_NAME}"


DATA_DIR = _base_dir()
SITE_PROFILE_PATH = DATA_DIR / "site_profile.json"


@dataclass
class SiteProfile:
    site_name: str = ""
    site_code: str = ""
    brand: str = "Generic / NonBranded"
    deployment_model: str = "Standard"
    address_1: str = ""
    address_2: str = ""
    city: str = ""
    state: str = ""
    postal_code: str = ""
    country: str = "US"
    property_contact: str = ""
    property_phone: str = ""
    marsha_code: str = ""
    hyatt_code: str = ""
    notes: str = ""
    default_switch_ip_start: str = "10.0.3.130"
    default_switch_mask: str = "255.255.255.128"
    default_switch_gateway: str = "10.0.3.129"
    default_mgmt_vlan: str = "100"
    default_ap_mgmt_vlan: str = "101"


def load_site_profile() -> SiteProfile:
    try:
        if SITE_PROFILE_PATH.exists():
            raw: dict[str, Any] = json.loads(SITE_PROFILE_PATH.read_text(encoding="utf-8"))
            allowed = {field for field in SiteProfile.__dataclass_fields__.keys()}
            return SiteProfile(**{k: v for k, v in raw.items() if k in allowed})
    except Exception:
        pass
    return SiteProfile()


def save_site_profile(profile: SiteProfile | dict[str, Any]) -> SiteProfile:
    if isinstance(profile, dict):
        allowed = {field for field in SiteProfile.__dataclass_fields__.keys()}
        profile = SiteProfile(**{k: str(v or "") for k, v in profile.items() if k in allowed})
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SITE_PROFILE_PATH.write_text(json.dumps(asdict(profile), indent=2), encoding="utf-8")
    return profile


def site_context_summary(profile: SiteProfile | None = None) -> dict[str, str]:
    profile = profile or load_site_profile()
    return asdict(profile)
