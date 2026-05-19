from __future__ import annotations

import io
import json
import re
import tempfile
import time
from datetime import datetime
import secrets
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple
from zipfile import ZipFile

MODULE_DIR = Path(__file__).resolve().parent
MODEL_DIR = MODULE_DIR / "model"

# Full config-aware pull list. The old six-file pull was only a partial baseline.
CORE_REQUIRED_FILES = [
    "current.txt",
    "nseconf.txt",
    "wanconf.txt",
    "ifmonitor.txt",
    "RoomFileV2.txt",
    "inatconf.txt",
    "mfilter.txt",
    "netconf.txt",
    "lbstate.txt",
    "subnets.txt",
    "routeConf.txt",
]
CORE_OPTIONAL_FILES = [
    "subuicfg.txt",
    "pppoeconf.txt",
]
CERTIFICATE_RELATED_FILES = [
    "server.pem",
    "cacert.pem",
    "cakey.pem",
    "ndxcas.pem",
    "ndxacsca.epm",
]
PRESERVE_ONLY_FILES = [
    "factory.txt",
    "nsefactr.txt",
    "AuthFile.dat",
    "radFile.dat",
    "radhist.rad",
    "radXmlQ.txt",
    "pmsXmlQ.txt",
    "currFile.dat",
    "dhcplease.txt",
]
CONFIG_PULL_FILES = CORE_REQUIRED_FILES + CORE_OPTIONAL_FILES
SENSITIVE_PULL_FILES = CERTIFICATE_RELATED_FILES

CONFIG_MANAGED_FILES = {
    "current.txt": "AAA/XML/common key-value settings, DNS compatibility fields, HA current state preservation",
    "nseconf.txt": "AAA, portal, RADIUS, MAC auth, DHCP, ACL, SNMP, passthrough, time/NTP, watchdog, migration",
    "wanconf.txt": "Full WAN page: IP/mask/gateway, DNS table, bandwidth, VLAN tagging, IPv6, NAT count",
    "ifmonitor.txt": "Interface monitor/role/address mirror for WAN and ports",
    "RoomFileV2.txt": "Detailed Port/Location/VLAN table rows",
    "inatconf.txt": "Interface NAT/role table",
    "mfilter.txt": "MAC filtering table, preserve unless explicitly managed",
    "netconf.txt": "Legacy/simple WAN compatibility fields",
    "lbstate.txt": "Load-balance interface state, preserve unless explicitly managed",
    "subnets.txt": "Subnet/subinterface related data, preserve unless explicitly managed",
    "routeConf.txt": "Route control/static route state, preserve unless explicitly managed",
    "subuicfg.txt": "IWS UI config, optional preserve-only for now",
    "pppoeconf.txt": "PPPoE config, optional preserve-only for now",
}

WRITE_PLAN_BY_FEATURE = {
    "main_site_info": ["current.txt", "nseconf.txt"],
    "aaa_xml_portal": ["current.txt", "nseconf.txt"],
    "external_web_server_safety": ["nseconf.txt"],
    "radius_profiles": ["nseconf.txt"],
    "radius_client": ["nseconf.txt"],
    "mac_authentication": ["nseconf.txt"],
    "snmp_simple": ["nseconf.txt"],
    "passthrough": ["nseconf.txt"],
    "access_control_acl": ["nseconf.txt"],
    "bandwidth_management": ["nseconf.txt"],
    "dhcp_pools": ["nseconf.txt"],
    "wan": ["wanconf.txt", "ifmonitor.txt", "netconf.txt", "current.txt"],
    "port_location_vlans": ["RoomFileV2.txt", "nseconf.txt"],
    "802_1q_port_location_mode": ["RoomFileV2.txt", "nseconf.txt"],
    "zone_migration": ["nseconf.txt", "current.txt"],
    "primary_wan_watchdog": ["nseconf.txt"],
    "time_ntp": ["nseconf.txt"],
}

IGNORE_PATH_PARTS = {".Trash-1000", "fpstate", "web", "ipseccrt"}
IGNORE_SUFFIXES = (".bk0", ".bk1", ".bk2", ".bk3", ".bk4", ".bk5", ".bk6", ".bk7", ".bk8", ".bk9", ".trashinfo", ".lnk", ".scr")
SECTION_RE = re.compile(r"BEGIN_SECTION:(.*?)\n(.*?)END_SECTION:\1", re.DOTALL)
RECORD_RE = re.compile(r"BEGIN_RECORD:(.*?)\n(.*?)END_RECORD:\1", re.DOTALL)
KV_RE = re.compile(r"^([^=\n]+)=(.*)$", re.MULTILINE)


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_model() -> Dict[str, Any]:
    profiles_dir = MODEL_DIR / "profiles"
    data_dir = MODEL_DIR / "data"
    docs_dir = MODEL_DIR / "docs"
    return {
        "common": _load_json(profiles_dir / "common.json"),
        "profiles": _load_json(profiles_dir / "profiles.json"),
        "clp_shared": _load_json(profiles_dir / "clp_shared.json"),
        "bap_shared": _load_json(profiles_dir / "bap_shared.json"),
        "sonesta_11os_shared": _load_json(profiles_dir / "sonesta_11os_shared.json"),
        "passthrough_profiles": _load_json(data_dir / "passthrough_profiles.json"),
        "acl_profiles": _load_json(data_dir / "acl_profiles.json"),
        "vlan_port_location_profiles": _load_json(data_dir / "vlan_port_location_profiles.json"),
        "dhcp_profiles": _load_json(data_dir / "dhcp_profiles.json"),
        "field_mapping": _load_json(docs_dir / "field_mapping.json"),
    }


def expected_file_manifest() -> Dict[str, Any]:
    return {
        "core_required": CORE_REQUIRED_FILES,
        "core_optional": CORE_OPTIONAL_FILES,
        "certificate_related_optional": CERTIFICATE_RELATED_FILES,
        "preserve_only_optional": PRESERVE_ONLY_FILES,
        "managed_files": CONFIG_MANAGED_FILES,
        "write_plan_by_feature": WRITE_PLAN_BY_FEATURE,
        "notes": [
            "current.txt/nseconf.txt/netconf.txt/inatconf.txt/mfilter.txt/subnets.txt alone are a partial baseline only.",
            "wanconf.txt is required for full WAN page fidelity.",
            "RoomFileV2.txt is required for Port/Location/VLAN rows.",
            "ifmonitor.txt should be kept consistent with wanconf.txt for interface address/role fields.",
            "Certificate/key files are optional and sensitive; pull only when needed for backup or certificate workflow.",
        ],
    }


def main_configuration_schema() -> Dict[str, Any]:
    """Data expected from the future Main Configuration Page.

    This is intentionally profile-neutral. Other shell apps should be able to read
    the same site object and generate their own config pages from it.
    """
    return {
        "site_info": {
            "property_code": "",
            "property_name": "",
            "brand": "Marriott|Hyatt|Sonesta|Other",
            "aaa_profile": "CLP|BAP|Sonesta-11OS|Other",
            "address1": "",
            "address2": "",
            "city": "",
            "state": "",
            "zip": "",
            "country": "USA",
            "timezone_region": "America",
            "timezone_city": "New_York",
        },
        "device_naming": {
            "pattern": "<sitecode><devicecode><sequence>-<floor>-<closet>",
            "device_code": "GW",
            "site_code": "",
            "floor": "03",
            "closet": "MDF",
            "examples": ["PVDLWGW01-03-MDF", "PVDLWGW02-03-MDF"],
        },
        "nomadix": {
            "configure_ha_pair": False,
            "remote_dir": "/flash",
            "primary": {
                "sequence": "01",
                "hostname": "",
                "wan_ip": "192.168.223.131",
                "wan_mac": "",
                "nas_id": "USER_REQUIRED_last_6_of_wan_mac_lowercase",
                "nse_id": "alias_of_nas_id",
            },
            "secondary": {
                "sequence": "02",
                "hostname": "",
                "wan_ip": "192.168.223.132",
                "wan_mac": "",
                "nas_id": "USER_REQUIRED_last_6_of_wan_mac_lowercase",
                "nse_id": "alias_of_nas_id",
            },
        },
        "wan": {
            "subnet_mask": "255.255.255.128",
            "gateway": "192.168.223.129",
            "gateway_arp_refresh_interval": "120",
            "dns_domain": "profile_default_or_user_override",
            "dns_server_1": "profile_default_or_user_override",
            "dns_server_2": "profile_default_or_user_override",
            "dns_server_3": "profile_default_or_user_override",
            "uplink_kbps": "1000000",
            "downlink_kbps": "1000000",
            "wan_vlan_tagging_enabled": False,
            "wan_vlan_id": "1",
            "additional_nat_ips": [],
        },
        "snmp": {
            "ro_string": "USER_REQUIRED",
            "rw_string": "USER_REQUIRED",
            "port": "161",
        },
        "certificates": {
            "radsec_certificate_bundle": "upload_required_for_clp",
            "certificate_install_later_uses_same_sftp_login": True,
        },
    }


def _pick_shared(aaa_family: str, model: Dict[str, Any]) -> Dict[str, Any]:
    if aaa_family == "CLP":
        return model["clp_shared"]
    if aaa_family == "BAP":
        return model["bap_shared"]
    if aaa_family in {"Sonesta", "11OS", "Sonesta-11OS"}:
        return model["sonesta_11os_shared"]
    return {}


def _count_list_profile(profile: Any) -> int:
    if isinstance(profile, list):
        return len(profile)
    if isinstance(profile, dict):
        return len(profile.get("records", [])) or len(profile.get("dns_names", [])) + len(profile.get("ipv4_addresses", [])) + len(profile.get("ipv6_addresses", []))
    return 0


def unresolved_mappings(model: Optional[Dict[str, Any]] = None) -> List[str]:
    if model is None:
        model = load_model()
    unresolved: List[str] = []
    zone = model.get("common", {}).get("global_rules", {}).get("zone_migration", {})
    unresolved.extend(zone.get("needs_key_confirmation", []))
    mapping = model.get("field_mapping", {})
    for key, value in mapping.items():
        if isinstance(value, dict):
            text = json.dumps(value).lower()
            if "not_confirmed" in text or "needs" in text:
                unresolved.append(key)
    # These are now reduced thanks to wanconf.txt and RoomFileV2.txt.
    unresolved.extend([
        "Destination HTTP Redirection detail table keys should be verified on full Sonesta/11OS pull before write-back.",
        "SNMP DAT trap interval key still needs exact write-back confirmation.",
        "Certificate install/import workflow is not implemented yet; CLP RadSec certs are still upload-required.",
    ])
    seen, out = set(), []
    for item in unresolved:
        item = str(item)
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def model_summary() -> Dict[str, Any]:
    model = load_model()
    profiles = model["profiles"]
    return {
        "module_engine_version": "0.7.0-alpha-shell-ready",
        "model_version": model["common"].get("model_version", "unknown"),
        "profile_count": len(profiles),
        "profiles": [
            {
                "id": pid,
                "status": p.get("status", ""),
                "aaa_family": p.get("aaa_family", ""),
                "brand_variant": p.get("brand_variant", ""),
                "requires_certificate_upload": bool(p.get("requires_certificate_upload", False)),
                "passthrough_profile": p.get("passthrough_profile", ""),
                "vlan_profile": p.get("vlan_profile", ""),
                "dhcp_profile": p.get("dhcp_profile", ""),
            }
            for pid, p in profiles.items()
        ],
        "profile_selector": model["common"].get("profile_selector", {}),
        "global_rules": model["common"].get("global_rules", {}),
        "expected_files": expected_file_manifest(),
        "main_configuration_schema": main_configuration_schema(),
        "counts": {
            "passthrough_profiles": {k: _count_list_profile(v) for k, v in model["passthrough_profiles"].items()},
            "acl_profiles": {k: _count_list_profile(v) for k, v in model["acl_profiles"].items()},
            "vlan_profiles": {k: _count_list_profile(v) for k, v in model["vlan_port_location_profiles"].items()},
            "dhcp_profiles": {k: _count_list_profile(v) for k, v in model["dhcp_profiles"].items()},
        },
        "unresolved_mappings": unresolved_mappings(model),
    }


def get_profile(profile_id: str) -> Dict[str, Any]:
    model = load_model()
    profiles = model["profiles"]
    if profile_id not in profiles:
        raise KeyError(profile_id)
    profile = profiles[profile_id]
    aaa_family = profile.get("aaa_family", "Other")
    passthrough_name = profile.get("passthrough_profile")
    vlan_name = profile.get("vlan_profile")
    dhcp_name = profile.get("dhcp_profile")
    acl_name = "Sonesta-11OS" if profile_id == "Sonesta-11OS" else "CLP-expanded"
    return {
        "profile_id": profile_id,
        "profile": profile,
        "shared": _pick_shared(aaa_family, model),
        "common_rules": model["common"].get("global_rules", {}),
        "common_aaa": model["common"].get("common_aaa", {}),
        "passthrough": model["passthrough_profiles"].get(passthrough_name, {}),
        "passthrough_profile": passthrough_name,
        "acl": model["acl_profiles"].get(acl_name, model["acl_profiles"].get("CLP-expanded", {})),
        "acl_profile": acl_name,
        "vlan_port_locations": model["vlan_port_location_profiles"].get(vlan_name, []),
        "vlan_profile": vlan_name,
        "dhcp": model["dhcp_profiles"].get(dhcp_name, []),
        "dhcp_profile": dhcp_name,
        "unresolved_mappings": unresolved_mappings(model),
    }


def _yn(value: bool) -> str:
    return "yes" if bool(value) else "no"


def _tf(value: bool) -> str:
    return "true" if bool(value) else "false"


def _normalize_nas_id(value: Any) -> str:
    raw = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
    if len(raw) >= 6:
        return raw[-6:].lower()
    return raw.lower()


def _resolve_nas_id(user_inputs: Dict[str, Any]) -> Tuple[str, str]:
    """Resolve NAS/NSE ID early. Prefer explicit NAS ID; otherwise infer from WAN MAC."""
    explicit = str(user_inputs.get("nas_id") or user_inputs.get("nse_id") or "").strip()
    if explicit:
        return _normalize_nas_id(explicit), "user_entered_nas_id"
    wan_mac = str(user_inputs.get("wan_mac") or "").strip()
    if wan_mac:
        inferred = _normalize_nas_id(wan_mac)
        if len(inferred) == 6:
            return inferred, "inferred_from_wan_mac"
    return "USER_REQUIRED", "missing_prompt_user"


def _build_gateway_hostname(site_code: str, sequence: str, floor: str, closet: str) -> str:
    site = re.sub(r"[^A-Za-z0-9]", "", str(site_code or "")).upper()
    seq = re.sub(r"[^0-9]", "", str(sequence or "01")) or "01"
    seq = seq.zfill(2)[-2:]
    fl = str(floor or "03").strip().upper()
    if fl and not fl.startswith("-"):
        fl = f"-{fl}"
    closet_val = re.sub(r"[^A-Za-z0-9]", "", str(closet or "MDF")).upper() or "MDF"
    return f"{site}GW{seq}{fl}-{closet_val}" if site else f"GW{seq}{fl}-{closet_val}"


def _resolve_ha_members(user_inputs: Dict[str, Any]) -> List[Dict[str, Any]]:
    configure_ha = bool(user_inputs.get("configure_ha_pair") or user_inputs.get("ha_pair"))
    site_code = str(user_inputs.get("site_code") or user_inputs.get("property_code") or "").strip()
    floor = str(user_inputs.get("floor") or "03").strip()
    closet = str(user_inputs.get("closet") or "MDF").strip()

    primary_ip = str(user_inputs.get("primary_wan_ip") or user_inputs.get("gw01_ip") or user_inputs.get("wan_ip") or user_inputs.get("ip_address") or "192.168.223.131").strip()
    secondary_ip = str(user_inputs.get("secondary_wan_ip") or user_inputs.get("gw02_ip") or "192.168.223.132").strip()

    primary_nas, primary_source = _resolve_nas_id({
        "nas_id": user_inputs.get("primary_nas_id") or user_inputs.get("gw01_nas_id") or user_inputs.get("nas_id"),
        "wan_mac": user_inputs.get("primary_wan_mac") or user_inputs.get("gw01_wan_mac") or user_inputs.get("wan_mac"),
    })
    secondary_nas, secondary_source = _resolve_nas_id({
        "nas_id": user_inputs.get("secondary_nas_id") or user_inputs.get("gw02_nas_id"),
        "wan_mac": user_inputs.get("secondary_wan_mac") or user_inputs.get("gw02_wan_mac"),
    })

    members = [
        {
            "member": "GW01",
            "sequence": "01",
            "hostname": user_inputs.get("primary_hostname") or user_inputs.get("gw01_hostname") or _build_gateway_hostname(site_code, "01", floor, closet),
            "wan_ip": primary_ip,
            "nas_id": primary_nas,
            "nas_id_source": primary_source,
            "wan_mac": user_inputs.get("primary_wan_mac") or user_inputs.get("gw01_wan_mac") or user_inputs.get("wan_mac", ""),
            "failover_sibling_ip": secondary_ip if configure_ha else "",
        }
    ]
    if configure_ha:
        members.append({
            "member": "GW02",
            "sequence": "02",
            "hostname": user_inputs.get("secondary_hostname") or user_inputs.get("gw02_hostname") or _build_gateway_hostname(site_code, "02", floor, closet),
            "wan_ip": secondary_ip,
            "nas_id": secondary_nas,
            "nas_id_source": secondary_source,
            "wan_mac": user_inputs.get("secondary_wan_mac") or user_inputs.get("gw02_wan_mac", ""),
            "failover_sibling_ip": primary_ip,
        })
    return members


def compose_desired_config(profile_id: str, user_inputs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Compose the desired config object and file write plan.

    This does not mutate an uploaded baseline yet. It is the single source of
    truth for what the eventual file patcher/API push should apply.
    """
    user_inputs = user_inputs or {}
    bundle = get_profile(profile_id)
    profile = bundle["profile"]
    ha_members = _resolve_ha_members(user_inputs)
    primary_member = ha_members[0]
    nas_id = primary_member["nas_id"]
    nas_id_source = primary_member["nas_id_source"]
    common_rules = bundle["common_rules"]
    shared = bundle["shared"]
    current_txt: Dict[str, Any] = {}
    nseconf: Dict[str, Any] = {}
    wanconf: Dict[str, Any] = {}
    ifmonitor: Dict[str, Any] = {}
    netconf: Dict[str, Any] = {}
    roomfile: Dict[str, Any] = {}

    # Common AAA fields.
    common_aaa = bundle.get("common_aaa", {})
    current_txt.update(common_aaa.get("current.txt", {}))
    nseconf.update(common_aaa.get("nseconf.txt", {}))

    # Profile DNS / WAN fundamentals. Profile DNS defaults can be overridden from Main Configuration Page.
    dns_defaults = profile.get("dns", {}) or {}
    current_txt.update(dns_defaults)
    wan_dns = {
        "dnsDomain": user_inputs.get("dns_domain", dns_defaults.get("dns_domain", "")),
        "primaryServer": user_inputs.get("dns_server_1", dns_defaults.get("dns_pri", "")),
        "secondaryServer": user_inputs.get("dns_server_2", dns_defaults.get("dns_sec", "")),
        "tertiaryServer": user_inputs.get("dns_server_3", dns_defaults.get("dns_ter", "")),
        "primaryIpv6Server": user_inputs.get("ipv6_dns_server_1", "::"),
        "secondaryIpv6Server": user_inputs.get("ipv6_dns_server_2", "::"),
        "tertiaryIpv6Server": user_inputs.get("ipv6_dns_server_3", "::"),
    }
    current_txt.update({
        "dns_domain": wan_dns["dnsDomain"],
        "dns_pri": wan_dns["primaryServer"],
        "dns_sec": wan_dns["secondaryServer"],
        "dns_ter": wan_dns["tertiaryServer"],
    })

    wan_ip = primary_member.get("wan_ip") or "192.168.223.131"
    wan_mask = user_inputs.get("wan_netmask") or user_inputs.get("subnet_mask") or "255.255.255.128"
    wan_gateway = user_inputs.get("wan_gateway") or user_inputs.get("gateway") or "192.168.223.129"
    uplink = str(user_inputs.get("uplink_kbps", "1000000"))
    downlink = str(user_inputs.get("downlink_kbps", "1000000"))
    additional_nat_ips = user_inputs.get("additional_nat_ips") or []
    if not isinstance(additional_nat_ips, list):
        additional_nat_ips = [str(additional_nat_ips)]

    wanconf["multiWanInterfaceCfgTbl.WAN"] = {
        "interfaceName": "WAN",
        "networkIpAddr": wan_ip,
        "networkMask": wan_mask,
        "gatewayIpAddr": wan_gateway,
        "gatewayArpRefreshInterval": str(user_inputs.get("gateway_arp_refresh_interval", "120")),
        "upLinkSpeed": uplink,
        "downLinkSpeed": downlink,
        "vlanTaggingEnable": "false",
        "vlanId": "1",
        "multNatIpEnable": _tf(bool(additional_nat_ips)),
        "numAdditionalNatIpAddrs": str(len(additional_nat_ips)),
        "cfgModeIpv6": user_inputs.get("ipv6_config_mode", "0"),
        "networkIpv6Addr": user_inputs.get("ipv6_address", "::"),
        "networkIpv6PrefixLen": str(user_inputs.get("ipv6_prefix_length", "0")),
        "subscriberIpv6Prefix": user_inputs.get("delegated_prefix", "::"),
        "subscriberIpv6PrefixLen": str(user_inputs.get("delegated_prefix_length", "60")),
        "ipv6DnsCfgMode": user_inputs.get("ipv6_dns_config_mode", "0"),
    }
    wanconf["dnsConfigTbl"] = wan_dns
    wanconf["additional_nat_ips"] = additional_nat_ips

    ifmonitor["wanInterfaceMonitoringTbl.WAN"] = {
        "interfaceName": "WAN",
        "interfaceRole": "2",  # observed WAN role in current full exports; preserve baseline if different later.
        "interfaceIpv4Enabled": "true",
        "interfaceAddr": wan_ip,
        "interfaceIpv6Enabled": "false",
        "interfaceIpv6Addr": "::",
    }
    netconf.update({
        "network_ip": wan_ip,
        "netmask": wan_mask,
        "gateway": wan_gateway,
        "gateway_arp_refresh_interval": str(user_inputs.get("gateway_arp_refresh_interval", "120")),
    })

    # Simple SNMP inputs.
    snmp = common_rules.get("snmp_inputs", {}).get("defaults", {}).copy()
    snmp.update({
        "getCommunity": user_inputs.get("snmp_ro", user_inputs.get("snmp_ro_string", "USER_REQUIRED")),
        "setCommunity": user_inputs.get("snmp_rw", user_inputs.get("snmp_rw_string", "USER_REQUIRED")),
        "snmpdPort": user_inputs.get("snmp_port", "161"),
    })

    # Profile-specific AAA/XML objects.
    if shared.get("xml_options"):
        x = shared["xml_options"]
        servers = x.get("xml_servers") or []
        current_txt.update({
            "nse_logout_ip0": x.get("logout_ip", ""),
            "xml_sender_ip": servers[0] if len(servers) > 0 else "",
            "xml_sender2_ip": servers[1] if len(servers) > 1 else "",
            "xml_sender3_ip": servers[2] if len(servers) > 2 else "",
            "xml_sender4_ip": servers[3] if len(servers) > 3 else "",
        })
        nseconf["aaa"] = {
            "authXmlViaCredentials": _tf(x.get("auth_via_xml_user_credentials", False)),
            "authXmlViaAddress": _tf(x.get("auth_via_ip_address", True)),
            "httpsRedirect": _tf(x.get("https_redirection", True)),
            "facebookLogin": "false",
            "portBasedBillingPolicies": "true",
        }
    if shared.get("internal_web_server"):
        iws = shared["internal_web_server"]
        current_txt.update({
            "aaa_ssl_on": _yn(iws.get("ssl_support", False)),
            "aaa_ssl_sens_only": _yn(iws.get("encrypt_only_sensitive_data", True)),
            "aaa_ssl_host_name": iws.get("certificate_dns_name", ""),
            "usg_portal_xml_post_url": iws.get("portal_xml_post_url", ""),
            "usg_portal_post_port": str(iws.get("portal_xml_post_port", "0")),
            "aaa_username_on": _yn(iws.get("usernames", True)),
            "aaa_new_subscribers_on": _yn(iws.get("new_subscribers", True)),
            "usg_portal_supports_gis_on": _yn(iws.get("supports_gis_clients", False)),
        })
        nseconf["portalPage.id_1"] = {
            "url": iws.get("portal_page_url", ""),
            "parameterPassing": _tf(iws.get("parameter_passing", True)),
            "method": "0",
            "signUI": "1" if iws.get("signed_parameters", {}).get("UI", False) else "0",
            "signMA": "1" if iws.get("signed_parameters", {}).get("MA", False) else "0",
            "signRN": "1" if iws.get("signed_parameters", {}).get("RN", False) else "0",
            "signPORT": "1" if iws.get("signed_parameters", {}).get("PORT", False) else "0",
            "signSIP": "1" if iws.get("signed_parameters", {}).get("SIP", False) else "0",
            "signQINQ": "1" if iws.get("signed_parameters", {}).get("QINQ", False) else "0",
        }

    # Safety standards.
    nseconf["portalPage.id_2"] = {"url": ""}
    nseconf["portalPage.id_3"] = {"url": ""}
    rad_client = dict(profile.get("radius_client", {}))
    rad_client["nasId"] = nas_id
    rad_client["nasIdOn"] = "true"
    nseconf["radClient"] = rad_client
    nseconf["radServProf"] = shared.get("radius_service_profile", {})
    nseconf["macAuth"] = profile.get("mac_auth", {})
    nseconf["snmpAgent"] = snmp
    nseconf["accCntrlGlobalConfig"] = common_rules.get("access_control_standard_clp_bap", {}) if profile_id != "Sonesta-11OS" else {**common_rules.get("access_control_standard_clp_bap", {}), "accCntrl_IP_Enable": "false"}
    nseconf["bwManagementGlobalCfg"] = common_rules.get("bandwidth_management", {})
    nseconf["timeNtpConfig"] = common_rules.get("time_ntp", {}).get("ntp", {})
    nseconf["primWanWdgParams"] = {"enabled": "false"}
    nseconf["portLocationGbl"] = {"concentratorType": "2", "etherTypeQinQ": "0x88a8", "numEntries": str(len(bundle["vlan_port_locations"]))}
    nseconf["hostPassthruTbl"] = {"profile": bundle["passthrough_profile"], "records": bundle["passthrough"]}
    nseconf["accessControl_IP"] = {"profile": bundle["acl_profile"], "records": bundle["acl"]}
    nseconf["dhcpServerPoolCfgTbl"] = {"profile": bundle["dhcp_profile"], "records": bundle["dhcp"]}

    # RoomFileV2 is the source of truth for detailed Port/Location/VLAN rows.
    roomfile["_portLocationTbl_ctrl"] = {"lastId": str(len(bundle["vlan_port_locations"]))}
    roomfile["portLocationTblV2"] = bundle["vlan_port_locations"]
    roomfile["rules"] = {
        "802_1q": "always enabled",
        "vlan_bandwidth_limits": "disabled_for_all_vlans",
        "exclude_stray_850": profile_id in {"CLP-Marriott", "BAP-Marriott"},
    }

    return {
        "profile_id": profile_id,
        "status": profile.get("status", ""),
        "requires_certificate_upload": profile.get("requires_certificate_upload", False),
        "source_of_truth": "profile_model_plus_main_configuration_page_inputs",
        "device_identity": {
            "configure_ha_pair": len(ha_members) > 1,
            "members": ha_members,
            "primary_hostname": primary_member.get("hostname", ""),
            "nas_id": nas_id,
            "nas_id_source": nas_id_source,
            "wan_mac": primary_member.get("wan_mac", ""),
            "naming_pattern": "<sitecode>GW<sequence>-<floor>-<closet>",
            "note": "NAS ID is the Nomadix NSE ID and should be the last six hex characters of the WAN MAC in lowercase.",
        },
        "desired_config": {
            "current.txt": current_txt,
            "nseconf.txt": nseconf,
            "wanconf.txt": wanconf,
            "ifmonitor.txt": ifmonitor,
            "netconf.txt": netconf,
            "RoomFileV2.txt": roomfile,
            "per_device_overrides": {
                member["member"]: {
                    "hostname": member["hostname"],
                    "wan_ip": member["wan_ip"],
                    "nas_id": member["nas_id"],
                    "failover_sibling_ip": member.get("failover_sibling_ip", ""),
                    "files": {
                        "current.txt": {"FailOverSiblingIP": member.get("failover_sibling_ip", "")},
                        "nseconf.txt": {"radClient.nasId": member["nas_id"]},
                        "wanconf.txt": {"multiWanInterfaceCfgTbl.WAN.networkIpAddr": member["wan_ip"]},
                        "ifmonitor.txt": {"wanInterfaceMonitoringTbl.WAN.interfaceAddr": member["wan_ip"]},
                        "netconf.txt": {"network_ip": member["wan_ip"]},
                    },
                }
                for member in ha_members
            },
            "inatconf.txt": {"behavior": "preserve baseline; update interface roles only if WAN/LAN role changed"},
            "mfilter.txt": {"behavior": "preserve baseline unless MAC filter editor is used"},
            "lbstate.txt": {"behavior": "preserve baseline unless load-balance editor is used"},
            "subnets.txt": {"behavior": "preserve baseline unless subnet editor is used"},
            "routeConf.txt": {"behavior": "preserve baseline unless route editor is used"},
            "passthrough_profile": bundle["passthrough_profile"],
            "acl_profile": bundle["acl_profile"],
            "vlan_profile": bundle["vlan_profile"],
            "dhcp_profile": bundle["dhcp_profile"],
        },
        "file_write_plan": WRITE_PLAN_BY_FEATURE,
        "warnings": warnings_for_profile(profile_id),
        "unresolved_mappings": bundle["unresolved_mappings"],
    }


def _safe_filename(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "nomadix")).strip("_")
    return value or "nomadix"


def _markdown_summary(export: Dict[str, Any]) -> str:
    profile_id = export.get("profile_id", "unknown")
    device = export.get("device_identity", {})
    desired = export.get("desired_config", {})
    warnings = export.get("warnings", [])
    unresolved = export.get("unresolved_mappings", [])
    lines = [
        f"# Nomadix Configuration Export - {profile_id}",
        "",
        "This export is generated from the Nomadix Configuration Builder working model.",
        "It is a reviewable configuration package, not an automatic live-device push.",
        "",
        "## Device Identity",
        f"- NAS ID / NSE ID: `{device.get('nas_id', '')}`",
        f"- NAS ID source: `{device.get('nas_id_source', '')}`",
        f"- WAN MAC: `{device.get('wan_mac', '')}`",
        f"- Configure HA Pair: `{device.get('configure_ha_pair', False)}`",
        "",
        "## HA / Device Members",
    ]
    for member in device.get("members", []):
        lines.append(f"- `{member.get('member')}` `{member.get('hostname')}` WAN `{member.get('wan_ip')}` NAS `{member.get('nas_id')}` sibling `{member.get('failover_sibling_ip', '')}`")
    lines.extend([
        "",
        "## Files represented in desired configuration",
    ])
    for fname in sorted(k for k in desired.keys() if k.endswith('.txt')):
        lines.append(f"- `{fname}`")
    lines.extend(["", "## Warnings"])
    if warnings:
        lines.extend([f"- {w}" for w in warnings])
    else:
        lines.append("- None")
    lines.extend(["", "## Unresolved / verify before live push"])
    if unresolved:
        lines.extend([f"- {u}" for u in unresolved])
    else:
        lines.append("- None")
    lines.extend([
        "",
        "## Next step",
        "Review `desired_config.json` and `overrides_by_file/` before using this package to build a text-file patch or push workflow.",
        "When baseline patching is enabled, this same desired configuration object will be applied to the active Nomadix text files.",
        "",
    ])
    return "\n".join(lines)


def create_config_export_zip(profile_id: str, user_inputs: Optional[Dict[str, Any]] = None) -> Path:
    """Create a downloadable export package for the composed desired config.

    This intentionally exports the desired config object and per-file overlays. It does
    not yet claim to be a fully patched Nomadix restore ZIP; that comes after the
    baseline patcher is validated against full Marriott/Hyatt/Sonesta pulls.
    """
    composed = compose_desired_config(profile_id, user_inputs or {})
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    nas_id = composed.get("device_identity", {}).get("nas_id", "")
    fname = f"nomadix_config_export_{_safe_filename(profile_id)}_{_safe_filename(nas_id)}_{stamp}.zip"
    out_dir = Path(tempfile.gettempdir()) / "nomadix_config_exports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / fname

    profile_snapshot = get_profile(profile_id)
    desired = composed.get("desired_config", {})
    with ZipFile(out_path, "w") as zf:
        zf.writestr("README.md", _markdown_summary(composed))
        zf.writestr("desired_config.json", json.dumps(composed, indent=2, sort_keys=True))
        zf.writestr("profile_snapshot.json", json.dumps(profile_snapshot, indent=2, sort_keys=True))
        zf.writestr("variables_entered.json", json.dumps(user_inputs or {}, indent=2, sort_keys=True))
        zf.writestr("file_write_plan.json", json.dumps(WRITE_PLAN_BY_FEATURE, indent=2, sort_keys=True))
        zf.writestr("warnings.txt", "\n".join(composed.get("warnings", [])) + "\n")
        zf.writestr("unresolved_mappings.txt", "\n".join(composed.get("unresolved_mappings", [])) + "\n")
        for key, value in desired.items():
            if key.endswith(".txt"):
                zf.writestr(f"overrides_by_file/{key}.json", json.dumps(value, indent=2, sort_keys=True))
        # These are useful to carry into Evidence Pack / History later.
        zf.writestr("metadata/export_type.txt", "reviewable_desired_config_export\n")
        zf.writestr("metadata/profile_id.txt", f"{profile_id}\n")
        zf.writestr("metadata/generated_utc.txt", f"{stamp}\n")
    return out_path


def warnings_for_profile(profile_id: str) -> List[str]:
    bundle = get_profile(profile_id)
    warnings = [
        "Expanded pull engine requires wanconf.txt and RoomFileV2.txt for full config fidelity.",
        "External Web Server URL will be forced blank.",
        "WAN VLAN tagging is disabled and VLAN ID is 1 because tagging is handled on the switch.",
        "SNMP RO/RW strings and SNMP port must be provided by the user.",
        "NAS ID/NSE ID is a required early device field. It should be the last six of the WAN MAC, lowercase; prompt user if not detected.",
        "Default WAN values are 192.168.223.131 / 255.255.255.128 / 192.168.223.129; HA secondary defaults to 192.168.223.132.",
    ]
    if bundle["profile"].get("requires_certificate_upload"):
        warnings.append("This profile requires CLP/RadSec certificate upload before final deployment.")
    if profile_id == "Sonesta-11OS":
        warnings.append("Sonesta/11OS uses ElevenOS RADIUS, MAC authentication disabled, and destination HTTP redirection enabled.")
    return warnings


def _is_ignored_member(name: str) -> bool:
    pp = PurePosixPath(name)
    parts = set(pp.parts)
    if parts & IGNORE_PATH_PARTS:
        return True
    base = pp.name
    if not base or name.endswith("/"):
        return True
    if base.endswith(IGNORE_SUFFIXES):
        return True
    if base.startswith("._"):
        return True
    return False


def _active_file_candidates(zf: ZipFile) -> Dict[str, Dict[str, str]]:
    """Return device/group -> basename -> zip member path.

    For a single SFTP pull, group is ''. For HA/customer zips, groups are parent
    directories such as 'GW01' or 'GW02'. Trash/backups are ignored.
    """
    wanted = set(CONFIG_PULL_FILES + SENSITIVE_PULL_FILES + PRESERVE_ONLY_FILES)
    groups: Dict[str, Dict[str, str]] = {}
    for name in zf.namelist():
        if _is_ignored_member(name):
            continue
        base = PurePosixPath(name).name
        if base not in wanted:
            continue
        parent = str(PurePosixPath(name).parent)
        # Use last folder as group label, unless this is a root-level/single directory dump.
        group = ""
        if parent not in {".", ""}:
            parts = PurePosixPath(parent).parts
            group = parts[-1] if parts else ""
            # For a single dump folder named Nomadix, normalize as one device.
            if group.lower() in {"nomadix", "flash"}:
                group = "default"
        groups.setdefault(group, {})[base] = name
    # If only one non-empty group exists and root has none, keep that group name; HA pairs preserve GW names.
    return groups


def _parse_sections(text: str) -> Dict[str, List[Dict[str, Any]]]:
    sections: Dict[str, List[Dict[str, Any]]] = {}
    for section_match in SECTION_RE.finditer(text):
        section_name = section_match.group(1).strip()
        body = section_match.group(2)
        records: List[Dict[str, Any]] = []
        for record_match in RECORD_RE.finditer(body):
            rtype = record_match.group(1).strip()
            rbody = record_match.group(2)
            values: Dict[str, List[str]] = {}
            for key, val in KV_RE.findall(rbody):
                values.setdefault(key.strip(), []).append(val.strip())
            records.append({"record_type": rtype, "values": values})
        sections[section_name] = records
    return sections


def _parse_ini(text: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        values[k.strip()] = v.strip()
    return values


def _first(records: List[Dict[str, Any]], key: str, default: str = "") -> str:
    if not records:
        return default
    vals = records[0].get("values", {}).get(key, [])
    return vals[0] if vals else default


def _section_count(sections: Dict[str, List[Dict[str, Any]]], name: str) -> int:
    return len(sections.get(name, []))


def _extract_device_summary(text_by_file: Dict[str, str], sections_by_file: Dict[str, Dict[str, List[Dict[str, Any]]]]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {"counts": {}, "wan": {}, "profile_indicators": {}, "ha": {}, "safety": {}}
    current = _parse_ini(text_by_file.get("current.txt", ""))
    if current:
        summary["ha"] = {
            "failover_on": current.get("FailOverOn"),
            "failover_sibling_ip": current.get("FailOverSiblingIP"),
            "failover_sibling_status": current.get("FailOverSiblingStatus"),
        }
        summary["profile_indicators"]["xml_post_url"] = current.get("usg_portal_xml_post_url")
        summary["profile_indicators"]["dns_pri"] = current.get("dns_pri")
        summary["profile_indicators"]["dns_sec"] = current.get("dns_sec")
    for fname, s in sections_by_file.items():
        summary["counts"].update({
            f"{fname}:hostPassthruTbl": _section_count(s, "hostPassthruTbl"),
            f"{fname}:accessControl_IP": _section_count(s, "accessControl_IP"),
            f"{fname}:dhcpServerPoolCfgTbl": _section_count(s, "dhcpServerPoolCfgTbl"),
            f"{fname}:portLocationTblV2": _section_count(s, "portLocationTblV2"),
            f"{fname}:destinationHTTPRedirectionTbl": _section_count(s, "destinationHTTPRedirectionTbl"),
        })
    wan_sections = sections_by_file.get("wanconf.txt", {})
    if wan_sections:
        mw = wan_sections.get("multiWanInterfaceCfgTbl", [])
        dns = wan_sections.get("dnsConfigTbl", [])
        summary["wan"] = {
            "ip": _first(mw, "networkIpAddr"),
            "mask": _first(mw, "networkMask"),
            "gateway": _first(mw, "gatewayIpAddr"),
            "uplink": _first(mw, "upLinkSpeed"),
            "downlink": _first(mw, "downLinkSpeed"),
            "vlan_tagging_enabled": _first(mw, "vlanTaggingEnable"),
            "vlan_id": _first(mw, "vlanId"),
            "dns_domain": _first(dns, "dnsDomain"),
            "dns1": _first(dns, "primaryServer"),
            "dns2": _first(dns, "secondaryServer"),
            "dns3": _first(dns, "tertiaryServer"),
        }
    nse_sections = sections_by_file.get("nseconf.txt", {})
    if nse_sections:
        rad_client = nse_sections.get("radClient", [])
        mac_auth = nse_sections.get("macAuth", [])
        watchdog = nse_sections.get("primWanWdgParams", [])
        summary["profile_indicators"].update({
            "radius_default_profile": _first(rad_client, "dfltServerName"),
            "nas_id": _first(rad_client, "nasId"),
            "nas_id_on": _first(rad_client, "nasIdOn"),
            "mac_auth_enabled": _first(mac_auth, "enable"),
            "mac_auth_radius_profile": _first(mac_auth, "radiusProfile"),
        })
        summary["safety"]["primary_wan_watchdog_enabled"] = _first(watchdog, "enabled")
    room_sections = sections_by_file.get("RoomFileV2.txt", {})
    if room_sections:
        summary["port_location"] = {
            "row_count": _section_count(room_sections, "portLocationTblV2"),
            "has_850_stray": any("850" in rec.get("values", {}).get("port", []) for rec in room_sections.get("portLocationTblV2", [])),
        }
    return summary


def analyze_baseline_zip(zip_bytes: bytes) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ok": True,
        "errors": [],
        "warnings": [],
        "expected_files": expected_file_manifest(),
        "devices": {},
        "files": {},
        "sections": {},
        "baseline_classification": "unknown",
    }
    try:
        with ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            groups = _active_file_candidates(zf)
            if not groups:
                result["ok"] = False
                result["errors"].append("No active Nomadix config files found in ZIP.")
                return result
            for group, filemap in groups.items():
                device_name = group or "default"
                dev: Dict[str, Any] = {"found_files": sorted(filemap.keys()), "missing_required": [], "missing_optional": [], "files": {}, "sections": {}, "summary": {}}
                text_by_file: Dict[str, str] = {}
                sections_by_file: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
                for fname in CORE_REQUIRED_FILES:
                    if fname not in filemap:
                        dev["missing_required"].append(fname)
                for fname in CORE_OPTIONAL_FILES:
                    if fname not in filemap:
                        dev["missing_optional"].append(fname)
                for fname, member in filemap.items():
                    data = zf.read(member)
                    try:
                        text = data.decode("utf-8", errors="ignore")
                    except Exception:
                        text = ""
                    dev["files"][fname] = {"member": member, "bytes": len(data), "lines": len(text.splitlines()) if text else 0}
                    if text:
                        text_by_file[fname] = text
                        if "BEGIN_SECTION:" in text:
                            sections = _parse_sections(text)
                            sections_by_file[fname] = sections
                            dev["sections"][fname] = sorted(sections.keys())
                dev["summary"] = _extract_device_summary(text_by_file, sections_by_file)
                dev["complete_for_generation"] = len(dev["missing_required"]) == 0
                if not dev["complete_for_generation"]:
                    result["ok"] = False
                    result["warnings"].append(f"{device_name}: missing required files: {', '.join(dev['missing_required'])}")
                result["devices"][device_name] = dev
        if len(result["devices"]) >= 2:
            result["baseline_classification"] = "ha_pair_or_multi_device"
        else:
            result["baseline_classification"] = "single_device"
        # Backward-compatible flattened fields for the UI.
        first_dev = next(iter(result["devices"].values())) if result["devices"] else {}
        result["files"] = first_dev.get("files", {})
        result["sections"] = first_dev.get("sections", {})
        result["ok"] = result["ok"] and all(d.get("complete_for_generation") for d in result["devices"].values())
    except Exception as exc:  # noqa: BLE001
        result["ok"] = False
        result["errors"].append(str(exc))
    return result


# In-memory record of pulled baseline ZIPs for download during this app process.
SFTP_PULL_JOBS: Dict[str, Dict[str, Any]] = {}


def pull_baseline_via_sftp(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Read-only SFTP baseline pull from a Nomadix /flash directory."""
    host = str(payload.get("host") or payload.get("ip") or "").strip()
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    remote_dir = str(payload.get("remote_dir") or "/flash").strip() or "/flash"
    include_sensitive = bool(payload.get("include_sensitive", False))
    try:
        port = int(payload.get("port") or 22)
    except Exception:
        port = 22
    try:
        timeout = int(payload.get("timeout") or 20)
    except Exception:
        timeout = 20

    if not host:
        return {"ok": False, "errors": ["Nomadix IP/host is required."], "warnings": [], "files": {}, "sections": {}}
    if not username:
        return {"ok": False, "errors": ["Username is required."], "warnings": [], "files": {}, "sections": {}}
    if not password:
        return {"ok": False, "errors": ["Password is required."], "warnings": [], "files": {}, "sections": {}}
    if port < 1 or port > 65535:
        return {"ok": False, "errors": ["SSH port must be between 1 and 65535."], "warnings": [], "files": {}, "sections": {}}

    try:
        import paramiko  # type: ignore
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "errors": ["Paramiko is not installed. Install it with: pip install paramiko", str(exc)],
            "warnings": [],
            "files": {},
            "sections": {},
        }

    file_list = list(CONFIG_PULL_FILES)
    if include_sensitive:
        file_list += SENSITIVE_PULL_FILES
    fetched: Dict[str, bytes] = {}
    errors: List[str] = []
    warnings: List[str] = []
    started = time.strftime("%Y%m%d-%H%M%S")
    job_id = secrets.token_urlsafe(24)
    job_dir = Path(tempfile.gettempdir()) / "nomadix_sftp_pull" / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    zip_path = job_dir / f"nomadix_full_baseline_{host.replace(':','_')}_{started}.zip"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        sftp = client.open_sftp()
        try:
            for fname in file_list:
                remote_path = f"{remote_dir.rstrip('/')}/{fname}"
                bio = io.BytesIO()
                try:
                    sftp.getfo(remote_path, bio)
                    fetched[fname] = bio.getvalue()
                except FileNotFoundError:
                    if fname in CORE_REQUIRED_FILES:
                        errors.append(f"Missing required remote file: {remote_path}")
                    else:
                        warnings.append(f"Optional remote file not found: {remote_path}")
                except IOError as exc:
                    if fname in CORE_REQUIRED_FILES:
                        errors.append(f"Unable to read required file {remote_path}: {exc}")
                    else:
                        warnings.append(f"Unable to read optional file {remote_path}: {exc}")
        finally:
            try:
                sftp.close()
            except Exception:
                pass
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "errors": [f"SFTP connection failed for {host}:{port}: {exc}"],
            "warnings": warnings,
            "files": {},
            "sections": {},
            "source": {"method": "sftp", "host": host, "port": port, "remote_dir": remote_dir},
        }
    finally:
        try:
            client.close()
        except Exception:
            pass

    if fetched:
        with ZipFile(zip_path, "w") as zf:
            for fname, data in fetched.items():
                zf.writestr(fname, data)
        analysis = analyze_baseline_zip(zip_path.read_bytes())
    else:
        analysis = {"ok": False, "errors": ["No baseline files were fetched."], "warnings": [], "files": {}, "sections": {}}

    analysis.setdefault("errors", [])
    analysis.setdefault("warnings", [])
    analysis["errors"] = errors + analysis.get("errors", [])
    analysis["warnings"] = warnings + analysis.get("warnings", [])
    analysis["ok"] = bool(analysis.get("ok")) and not errors
    if fetched:
        analysis["backup"] = {
            "job_id": job_id,
            "filename": zip_path.name,
            "download_url": f"/apps/nomadix-config/api/pull-baseline-sftp/{job_id}/download",
            "fetched_files": sorted(fetched.keys()),
            "include_sensitive": include_sensitive,
        }
        SFTP_PULL_JOBS[job_id] = {
            "zip_path": str(zip_path),
            "host": host,
            "port": port,
            "remote_dir": remote_dir,
            "created": started,
        }
    analysis["source"] = {"method": "sftp", "host": host, "port": port, "remote_dir": remote_dir}
    analysis["credential_handling"] = "Credentials were used only for this request and are not saved in the response or backup ZIP."
    return analysis


def get_sftp_pull_zip(job_id: str) -> Path:
    job = SFTP_PULL_JOBS.get(job_id)
    if not job:
        raise KeyError(job_id)
    path = Path(job["zip_path"])
    if not path.exists():
        raise FileNotFoundError(str(path))
    return path
