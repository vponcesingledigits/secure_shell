from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, FileResponse
from fastapi.templating import Jinja2Templates

try:
    from shared.site_context import SiteProfile, load_site_profile, save_site_profile
except Exception:
    SiteProfile = None
    def load_site_profile():
        return None
    def save_site_profile(profile):
        return profile

APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))
router = APIRouter()

FAVICON_URL = "https://images.squarespace-cdn.com/content/v1/63eaba56d2bc1c0edd1199e0/6c87c44f-feae-44b2-a096-fea952fde4bf/favicon.ico?format=100w"
LOGO_URL = "/static/logo.png"
MODULE_BASE = "/apps/switch-configurator"

VENDOR_OPTIONS = ["ICX7000_Switch", "ICX7000_Router", "ICX8200_Switch", "ICX8200_Router", "Aruba CX-OS"]
BRAND_OPTIONS = ["Marriott", "Hyatt", "Generic / NonBranded"]
DEPLOYMENT_MODE_OPTIONS = {
    "Marriott": ["BAS", "MIC", "FUL"],
    "Hyatt": ["HSIA_ONLY", "STANDARD", "FULL_IP"],
    "Generic / NonBranded": ["Standard"],
}
PORT_COUNT_OPTIONS = ["12", "24", "48"]
SWITCH_ROLE_OPTIONS = ["Core", "Distribution", "Edge", "Other"]
CORE_TYPE_OPTIONS = ["Single Head End", "Redundant Head End"]
AP_PROFILE_OPTIONS = ["AP_Guest", "AP_Public", "AP_Conference", "AP_BOH"]
ZONE_OPTIONS = ["Guest", "Marriott", "Vendor", "Meeting", "Public", "Hyatt", "Admin", "IoT", "Voice", "DMZ"]
MULTICAST_OPTIONS = ["off", "active", "passive"]

BASE_DEFAULTS = {
    "vendor": "ICX7000_Switch",
    "brand_profile": "Generic / NonBranded",
    "deployment_model": "Standard",
    "marsha_code": "",
    "property_name": "",
    "site_code": "",
    "address_1": "",
    "address_2": "",
    "postal_code": "",
    "country": "US",
    "property_contact": "",
    "property_phone": "",
    "city": "",
    "state": "",
    "floor": "01",
    "closet": "IDF1",
    "hostname": "",
    "num_switches": "1",
    "switch_mgmt_vlan": "100",
    "switch_ip": "10.0.3.130",
    "switch_mask": "255.255.255.128",
    "switch_gateway": "10.0.3.129",
    "voice_vlan": "601",
    "tacacs_server_1": "199.168.146.38",
    "tacacs_server_2": "162.255.175.101",
    "tacacs_secret": "$T1pnOV5uOg==",
    "radius_server_ip": "",
    "radius_auth_port": "1812",
    "radius_acct_port": "1813",
    "radius_secret": "3brJ95t1Ng3r",
    "auth_mode": "multiple-untagged",
    "auth_default_vlan": "1025",
    "remediation_vlan": "399",
    "dot1x_enabled": "yes",
    "mac_auth_enabled": "yes",
    "macauth_override": "yes",
    "tx_period": "10",
    "quiet_period": "10",
    "supplicant_timeout": "10",
    "admin_local_fallback": "yes",
    "auth_enable_aaa": "yes",
    "aruba_mgmt_vrf": "mgmt",
    "logging_persistence": "yes",
    "disable_web_mgmt": "yes",
    "ssh_timeout": "30",
    "timezone_name": "GMT-05",
    "summer_time": "yes",
    "ntp_server_1": "",
    "ntp_server_2": "",
    "snmp_server_auth_local": "yes",
    "enable_loop_detection": "yes",
    "loop_detection_shutdown_disable": "yes",
    "oob_mgmt_enabled": "no",
    "manager_registrar": "no",
    "manager_active_list": "",
    "ve1_disabled": "yes",
    "ve1_ipv6_disabled": "yes",
}

VLAN_CATALOG = {
    "100": {"name": "100-SwMgmtVlan", "zone": "Marriott"},
    "101": {"name": "101-AP-Management", "zone": "Marriott"},
    "102": {"name": "102-WAP2", "zone": "Hyatt"},
    "103": {"name": "103-WAP3", "zone": "Hyatt"},
    "105": {"name": "105-LSP_Mgmt", "zone": "Hyatt"},
    "130": {"name": "130-GuestGatewayWAN", "zone": "Guest"},
    "200": {"name": "200-GuestAccess", "zone": "Guest"},
    "201": {"name": "201-GuestAccess-2", "zone": "Guest"},
    "202": {"name": "202-GuestAccess-3", "zone": "Guest"},
    "203": {"name": "203-GuestAccess-4", "zone": "Guest"},
    "252": {"name": "252-Hyatt_Admin", "zone": "Admin"},
    "265": {"name": "265-BOH_IOT", "zone": "IoT"},
    "300": {"name": "300-Marriott_PCs", "zone": "Marriott"},
    "301": {"name": "301-Operations", "zone": "Marriott"},
    "399": {"name": "399-Forescout", "zone": "Marriott"},
    "400": {"name": "400-Third_Party_Vendors", "zone": "Vendor"},
    "401": {"name": "401-Digital_Signage", "zone": "Vendor"},
    "402": {"name": "402-Guest_Lobby_PC_Printer", "zone": "Vendor"},
    "403": {"name": "403-Uniforms", "zone": "Vendor"},
    "404": {"name": "404-Elevators", "zone": "Vendor"},
    "405": {"name": "405-Building_Management", "zone": "Vendor"},
    "408": {"name": "408-Robots", "zone": "IoT"},
    "410": {"name": "410-IoT_Thermostats", "zone": "IoT"},
    "411": {"name": "411-IoT_Duress", "zone": "IoT"},
    "413": {"name": "413-IoT_InRoom_Tablets", "zone": "IoT"},
    "420": {"name": "420-IoT_Lighting", "zone": "IoT"},
    "450": {"name": "450-FW_Outside", "zone": "DMZ"},
    "451": {"name": "451-FW_Inside", "zone": "DMZ"},
    "500": {"name": "500-IPTV_MGMT", "zone": "Vendor"},
    "501": {"name": "501-IPTV_Service_1", "zone": "Vendor"},
    "502": {"name": "502-IPTV_Service_2", "zone": "Vendor"},
    "503": {"name": "503-IPTV_Service_3", "zone": "Vendor"},
    "504": {"name": "504-IPTV_Service_4", "zone": "Vendor"},
    "505": {"name": "505-IPTV_Service_5", "zone": "Vendor"},
    "601": {"name": "601-Voice", "zone": "Voice"},
    "603": {"name": "603-Voice", "zone": "Voice"},
    "800": {"name": "800-Vendor_DMZ", "zone": "DMZ"},
    "900": {"name": "900-Transit", "zone": "DMZ"},
    "901": {"name": "901-Internet_DMZ_2", "zone": "DMZ"},
    "902": {"name": "902-Internet_DMZ_3", "zone": "DMZ"},
    "903": {"name": "903-Interconnect", "zone": "Marriott"},
    "904": {"name": "904-Internet_DMZ_4", "zone": "DMZ"},
    "905": {"name": "905-Internet_DMZ_5", "zone": "DMZ"},
    "910": {"name": "910-ISP-DMZ", "zone": "DMZ"},
    "1000": {"name": "1000-Guest_Wireless", "zone": "Guest"},
    "1001": {"name": "1001-ConferenceWireless", "zone": "Meeting"},
    "1006": {"name": "1006-HyattPasspoint", "zone": "Guest"},
    "1007": {"name": "1007-BOH_Wired", "zone": "Hyatt"},
    "1008": {"name": "1008-Guest_BA_Wireless", "zone": "Guest"},
    "1010": {"name": "1010-Hyatt_Colleague", "zone": "Hyatt"},
    "1016": {"name": "1016-Lobby_Wireless", "zone": "Public"},
    "1017": {"name": "1017-AssociateWireless", "zone": "Marriott"},
}
for n in range(1025, 1036):
    VLAN_CATALOG[str(n)] = {"name": f"{n}-Special_Event", "zone": "Meeting"}

PROFILE_DEFAULTS = {
    "Marriott": {
        "BAS": {"100", "101", "130", "910", "1000", "1001", "1016"},
        "MIC": {"100", "101", "130", "450", "451", "900", "903", "910", "1000", "1001", "1016", "1017"},
        "FUL": {"100", "101", "130", "200", "201", "202", "203", "300", "301", "450", "451", "900", "903", "910", "1000", "1001", "1016", "1017"},
    },
    "Hyatt": {
        "HSIA_ONLY": {"100", "101", "105", "450", "451", "900", "1000", "1001"},
        "STANDARD": {"100", "101", "102", "103", "105", "252", "265", "300", "301", "400", "401", "402", "450", "451", "601", "603", "900", "1000", "1001", "1007", "1010"},
        "FULL_IP": {"100", "101", "102", "103", "105", "252", "265", "300", "301", "400", "401", "402", "403", "404", "405", "408", "410", "411", "413", "420", "450", "451", "500", "501", "502", "503", "504", "505", "601", "603", "800", "900", "901", "902", "904", "905", "1000", "1001", "1006", "1007", "1008", "1010"},
    },
    "Generic / NonBranded": {"Standard": {"100", "101", "130", "910", "1000", "1001", "1016"}},
}

DEFAULT_PORT_PROFILES = [
    {"name": "Switch", "untagged_vlan": "", "tagged_vlans": "__ALL__"},
    {"name": "Edge", "untagged_vlan": "", "tagged_vlans": []},
    {"name": "Other", "untagged_vlan": "", "tagged_vlans": []},
    {"name": "Exempt", "untagged_vlan": "", "tagged_vlans": []},
    {"name": "GW_LAN", "untagged_vlan": "", "tagged_vlans": "__GUEST_PUBLIC_MEETING__"},
    {"name": "GW_WAN", "untagged_vlan": "130", "tagged_vlans": []},
    {"name": "FW_WAN", "untagged_vlan": "910", "tagged_vlans": []},
    {"name": "FW_LAN", "untagged_vlan": "", "tagged_vlans": ["100", "101", "130", "1017"]},
    {"name": "ISP_DMZ", "untagged_vlan": "910", "tagged_vlans": []},
    {"name": "AP_Guest", "untagged_vlan": "101", "tagged_vlans": ["1000", "1017"]},
    {"name": "AP_Public", "untagged_vlan": "101", "tagged_vlans": ["1016", "1017"]},
    {"name": "AP_Conference", "untagged_vlan": "101", "tagged_vlans": ["1001", "1025", "1017"]},
    {"name": "AP_BOH", "untagged_vlan": "101", "tagged_vlans": ["1017"]},
]
DEFAULT_AUTH_PROFILES = ["Edge", "FW_LAN"]

@dataclass
class StackMember:
    port_count: str = "48"
    role: str = "Other"
    core_type: str = "Single Head End"
    edge_ap_profile: str = "AP_Guest"

@dataclass
class VlanRow:
    vlan_id: str
    name: str
    enabled: bool = False
    zone: str = "Marriott"
    multicast: str = "off"
    notes: str = ""

@dataclass
class PortProfileRow:
    name: str
    untagged_vlan: str = ""
    tagged_vlans: list[str] = field(default_factory=list)

@dataclass
class PortEntry:
    interface: str
    profile: str = "Other"
    description: str = ""
    voice_enabled: bool = False
    exempt_untagged: str = ""
    exempt_tagged: str = ""

def safe(s): return str(s or "").strip()
def truthy(s): return safe(s).lower() in {"1","yes","true","on","y"}

def quote(s):
    s = safe(s)
    if not s:
        return '""'
    if s.startswith('"') and s.endswith('"'):
        return s
    return f'"{s}"'

def mask_to_prefix(mask):
    try:
        parts = [int(p) for p in safe(mask).split(".")]
        if len(parts) != 4:
            return 24
        return "".join(bin(p)[2:].zfill(8) for p in parts).count("1")
    except:
        return 24

def normalize_num_switches(v):
    try:
        return max(1, min(10, int(v)))
    except:
        return 1

def compute_hostname(base):
    if safe(base.get("hostname")):
        return safe(base["hostname"])
    code = safe(base.get("marsha_code")).upper()
    if not code:
        return ""
    return f"{code}SW001-{safe(base.get('floor') or '01')}-{safe(base.get('closet') or 'IDF1').upper()}"

def make_default_members(num_switches, vendor):
    out = []
    for _ in range(max(1, min(10, num_switches))):
        out.append(StackMember())
    return out

def default_vlan_rows(brand, model, mgmt_vlan):
    enabled_set = PROFILE_DEFAULTS.get(brand, {}).get(model, set())
    all_ids = set(VLAN_CATALOG.keys()) | enabled_set | ({mgmt_vlan} if mgmt_vlan else set())
    rows = []
    for vlan_id in sorted(all_ids, key=lambda x: int(x)):
        cat = VLAN_CATALOG.get(vlan_id, {"name": f"{vlan_id}-VLAN", "zone": "Marriott"})
        name = cat["name"]
        if vlan_id == mgmt_vlan:
            suffix = name.split("-", 1)[1] if "-" in name else "SwMgmtVlan"
            name = f"{mgmt_vlan}-{suffix}"
        rows.append(VlanRow(vlan_id=vlan_id, name=name, enabled=(vlan_id in enabled_set or vlan_id == mgmt_vlan), zone=cat["zone"]))
    return rows

def default_profiles():
    out = []
    for row in DEFAULT_PORT_PROFILES:
        tagged = list(row["tagged_vlans"]) if isinstance(row["tagged_vlans"], list) else [row["tagged_vlans"]]
        out.append(PortProfileRow(name=row["name"], untagged_vlan=row["untagged_vlan"], tagged_vlans=tagged))
    return out

def parse_base(form):
    base = {k: safe(form.get(k, v)) for k, v in BASE_DEFAULTS.items()}
    if base["brand_profile"] not in BRAND_OPTIONS:
        base["brand_profile"] = "Marriott"
    if base["deployment_model"] not in DEPLOYMENT_MODE_OPTIONS[base["brand_profile"]]:
        base["deployment_model"] = DEPLOYMENT_MODE_OPTIONS[base["brand_profile"]][0]
    for key in ["dot1x_enabled","mac_auth_enabled","macauth_override","admin_local_fallback","auth_enable_aaa","logging_persistence","disable_web_mgmt","summer_time","snmp_server_auth_local","enable_loop_detection","loop_detection_shutdown_disable","oob_mgmt_enabled","manager_registrar","ve1_disabled","ve1_ipv6_disabled"]:
        base[key] = "yes" if form.get(key) == "on" or safe(form.get(key)) == "yes" else "no"
    return base

def parse_members(form, num_switches):
    out = []
    for i in range(1, num_switches + 1):
        out.append(StackMember(
            port_count=safe(form.get(f"member_{i}_port_count", "48")) or "48",
            role=safe(form.get(f"member_{i}_role", "Other")) or "Other",
            core_type=safe(form.get(f"member_{i}_core_type", "Single Head End")) or "Single Head End",
            edge_ap_profile=safe(form.get(f"member_{i}_edge_ap_profile", "AP_Guest")) or "AP_Guest",
        ))
    return out

def parse_vlans(form, base):
    try:
        count = int(safe(form.get("vlan_count", "0")))
    except:
        count = 0
    if count == 0:
        return default_vlan_rows(base["brand_profile"], base["deployment_model"], base["switch_mgmt_vlan"])
    rows = []
    for idx in range(count):
        vlan_id = safe(form.get(f"vlan_{idx}_id"))
        if not vlan_id:
            continue
        rows.append(VlanRow(
            vlan_id=vlan_id,
            name=safe(form.get(f"vlan_{idx}_name")) or f"{vlan_id}-VLAN",
            enabled=form.get(f"vlan_{idx}_enabled") == "on",
            zone=safe(form.get(f"vlan_{idx}_zone", "Marriott")) or "Marriott",
            multicast=safe(form.get(f"vlan_{idx}_multicast", "off")) or "off",
            notes=safe(form.get(f"vlan_{idx}_notes")),
        ))
    return rows

def parse_profiles(form):
    try:
        count = int(safe(form.get("profile_count", str(len(DEFAULT_PORT_PROFILES)))))
    except:
        count = len(DEFAULT_PORT_PROFILES)
    rows = []
    for idx in range(count):
        name = safe(form.get(f"profile_{idx}_name"))
        if not name:
            continue
        tagged_raw = form.get(f"profile_{idx}_tagged_vlans", "")
        tagged = [x.strip() for x in safe(tagged_raw).split(",") if x.strip()]
        rows.append(PortProfileRow(
            name=name,
            untagged_vlan=safe(form.get(f"profile_{idx}_untagged_vlan")),
            tagged_vlans=tagged,
        ))
    return rows or default_profiles()

def generate_ports(members, vendor):
    ports = []
    for unit, member in enumerate(members, start=1):
        port_count = int(member.port_count)
        extra = 4 if vendor == "Aruba CX-OS" else 0
        total = port_count + extra
        for p in range(1, total + 1):
            ports.append(PortEntry(interface=f"{unit}/1/{p}"))
    return ports

def apply_role_defaults(ports, members):
    for unit, member in enumerate(members, start=1):
        total = int(member.port_count)
        unit_ports = [p for p in ports if p.interface.startswith(f"{unit}/1/")]
        if member.role == "Distribution":
            for p in unit_ports:
                p.profile = "Switch"
                p.description = "Switch Uplink"
        elif member.role == "Edge":
            for p in unit_ports:
                num = int(p.interface.split("/")[-1])
                if num == total:
                    p.profile = "Switch"
                    p.description = "Switch Uplink"
                else:
                    p.profile = member.edge_ap_profile
        elif member.role == "Core":
            if member.core_type == "Single Head End":
                mapping = {
                    1: ("ISP_DMZ", "ISP"),
                    2: ("Other", "ESXi"),
                    3: ("FW_WAN", "FW1_WAN"),
                    4: ("FW_LAN", "FW1_LAN"),
                    5: ("GW_WAN", "GW1_WAN"),
                    6: ("GW_LAN", "GW1_LAN"),
                }
            else:
                mapping = {
                    1: ("ISP_DMZ", "ISP"),
                    2: ("Other", "ESXi"),
                    3: ("FW_WAN", "FW1_WAN"),
                    4: ("FW_LAN", "FW1_LAN"),
                    5: ("FW_WAN", "FW2_WAN"),
                    6: ("FW_LAN", "FW2_LAN"),
                    7: ("GW_WAN", "GW1_WAN"),
                    8: ("GW_LAN", "GW1_LAN"),
                    9: ("GW_WAN", "GW2_WAN"),
                    10: ("GW_LAN", "GW2_LAN"),
                }
            for p in unit_ports:
                num = int(p.interface.split("/")[-1])
                if num in mapping:
                    p.profile, p.description = mapping[num]
    return ports

def parse_ports(form, ports, profile_names):
    for idx, port in enumerate(ports):
        profile = safe(form.get(f"port_{idx}_profile", port.profile)) or port.profile
        if profile not in profile_names:
            profile = profile_names[0] if profile_names else "Other"
        port.profile = profile
        port.description = safe(form.get(f"port_{idx}_description", port.description))
        port.voice_enabled = form.get(f"port_{idx}_voice_enabled") == "on"
        port.exempt_untagged = safe(form.get(f"port_{idx}_exempt_untagged"))
        port.exempt_tagged = safe(form.get(f"port_{idx}_exempt_tagged"))
    return ports

def enabled_vlans(vlans):
    return [v for v in vlans if v.enabled]

def resolve_profile_defaults(profile, vlans):
    enabled_ids = [v.vlan_id for v in enabled_vlans(vlans)]
    tagged = [v for v in profile.tagged_vlans if safe(v)]
    if "__ALL__" in tagged:
        tagged = enabled_ids
    elif "__GUEST_PUBLIC_MEETING__" in tagged:
        tagged = [v.vlan_id for v in enabled_vlans(vlans) if v.zone in {"Guest", "Public", "Meeting"}]
    else:
        tagged = [v for v in tagged if v in enabled_ids]
    untagged = safe(profile.untagged_vlan) or None
    if untagged and untagged not in enabled_ids:
        untagged = None
    tagged = [v for v in tagged if v != untagged]
    return untagged, tagged

def build_vlan_membership_maps(vlans, ports, profiles, voice_vlan):
    tagged, untagged = {}, {}
    enabled_ids = {v.vlan_id for v in enabled_vlans(vlans)}
    profile_lookup = {p.name: p for p in profiles}
    for port in ports:
        if port.profile == "Exempt":
            if port.exempt_untagged and port.exempt_untagged in enabled_ids:
                untagged.setdefault(port.exempt_untagged, []).append(port.interface)
            for vlan in [x.strip() for x in port.exempt_tagged.split(",") if x.strip()]:
                if vlan in enabled_ids:
                    tagged.setdefault(vlan, []).append(port.interface)
            continue
        profile = profile_lookup.get(port.profile)
        if not profile:
            continue
        uvlan, tvlans = resolve_profile_defaults(profile, vlans)
        if uvlan and uvlan in enabled_ids:
            untagged.setdefault(uvlan, []).append(port.interface)
        for vlan in tvlans:
            if vlan in enabled_ids:
                tagged.setdefault(vlan, []).append(port.interface)
        if port.voice_enabled and safe(voice_vlan) in enabled_ids:
            tagged.setdefault(safe(voice_vlan), []).append(port.interface)
    return tagged, untagged

def compress_ports(ports):
    return " ".join(f"ethe {p}" for p in ports)

def evaluate_warnings(base, vlans, profiles):
    warnings = []
    if not safe(base.get("switch_ip")):
        warnings.append("Switch IP is blank.")
    if base.get("brand_profile") == "Hyatt":
        warnings.append("Hyatt profile is switch-focused in this build. Review VLAN/profile assignments carefully before deployment.")
    if base.get("vendor") == "Aruba CX-OS" and not safe(base.get("aruba_mgmt_vrf")):
        warnings.append("Aruba CX-OS selected but Management VRF is not defined.")
    if base.get("vendor") in {"ICX7000_Router", "ICX8200_Router"} and (not safe(base.get("switch_mgmt_vlan")) or not safe(base.get("switch_mask"))):
        warnings.append("ICX router mode selected but VE management settings are incomplete.")
    for profile in profiles:
        untagged, tagged = resolve_profile_defaults(profile, vlans)
        if profile.name == "FW_LAN" and ("910" in tagged or untagged == "910"):
            warnings.append("FW_LAN and ISP should never exist on the same profile.")
        if profile.name == "GW_LAN" and (untagged == "130" or "130" in tagged):
            warnings.append("GW_WAN and GW_LAN should never exist on the same port profile.")
    return warnings

def build_preview_icx(base, vlans, ports, profiles):
    tagged_map, untagged_map = build_vlan_membership_maps(vlans, ports, profiles, base.get("voice_vlan", "601"))
    router_mode = base["vendor"] in {"ICX7000_Router", "ICX8200_Router"}
    platform_8200 = base["vendor"] in {"ICX8200_Switch", "ICX8200_Router"}
    lines = []
    if not router_mode:
        if safe(base.get("switch_ip")) and safe(base.get("switch_mask")):
            lines.append(f"ip address {base['switch_ip']} {base['switch_mask']}")
        if safe(base.get("switch_gateway")):
            lines.append(f"default-gateway {base['switch_gateway']}")
        lines.append("!")
    lines.extend([
        "no snmp-server community public ro",
        "no snmp-server community private rw",
        "!"
    ])
    if truthy(base.get("auth_enable_aaa")):
        lines.extend([
            "aaa authentication web-server default local",
            "aaa authentication enable default tacacs+ local" if truthy(base.get("admin_local_fallback")) else "aaa authentication enable default tacacs+",
            "aaa authentication login default tacacs+ local" if truthy(base.get("admin_local_fallback")) else "aaa authentication login default tacacs+",
            "aaa authentication enable implicit-user",
            "aaa authentication dot1x default radius",
            "aaa authentication login privilege-mode",
            "aaa authorization exec default tacacs+",
            "aaa accounting commands 0 default start-stop tacacs+",
            "aaa accounting exec default start-stop tacacs+",
            "aaa accounting dot1x default start-stop radius",
            "aaa accounting mac-auth default start-stop radius",
        ])
        if safe(base.get("tacacs_server_1")):
            lines.append(f"tacacs-server host {base['tacacs_server_1']}")
        if safe(base.get("tacacs_server_2")):
            lines.append(f"tacacs-server host {base['tacacs_server_2']}")
        if safe(base.get("tacacs_secret")):
            lines.append(f"tacacs-server key 2 {base['tacacs_secret']}")
        if safe(base.get("radius_server_ip")):
            lines.append(f"radius-server host {base['radius_server_ip']} auth-port {base['radius_auth_port']} acct-port {base['radius_acct_port']} default key {base['radius_secret']}")
        lines.append("!")
    if truthy(base.get("logging_persistence")): lines.append("logging persistence")
    if truthy(base.get("disable_web_mgmt")): lines.append("web-management disable")
    if safe(base.get("ssh_timeout")): lines.append(f"ip ssh timeout {base['ssh_timeout']}")
    if truthy(base.get("snmp_server_auth_local")): lines.append("aaa authentication snmp-server default local")
    if platform_8200 and truthy(base.get("oob_mgmt_enabled")):
        lines.extend(["interface management 1", "!"])
    for vlan in enabled_vlans(vlans):
        lines.append(f"vlan {vlan.vlan_id} name {vlan.name} by port")
        if vlan.vlan_id in tagged_map and tagged_map[vlan.vlan_id]:
            lines.append(f" tagged {compress_ports(tagged_map[vlan.vlan_id])}")
        if vlan.vlan_id in untagged_map and untagged_map[vlan.vlan_id]:
            lines.append(f" untagged {compress_ports(untagged_map[vlan.vlan_id])}")
        if router_mode and vlan.vlan_id == safe(base.get("switch_mgmt_vlan")):
            lines.append(f" router-interface ve {vlan.vlan_id}")
        elif (not router_mode) and vlan.vlan_id == safe(base.get("switch_mgmt_vlan")):
            lines.append(" management-vlan")
            if safe(base.get("switch_gateway")):
                lines.append(f" default-gateway  {base['switch_gateway']} 1")
        lines.extend([" no spanning-tree", "!"])
    if router_mode:
        lines.append("interface ve 1")
        if truthy(base.get("ve1_disabled")): lines.append(" disable")
        if truthy(base.get("ve1_ipv6_disabled")): lines.append(" no ipv6 enable")
        lines.append("!")
        mgmt = safe(base.get("switch_mgmt_vlan"))
        if mgmt:
            lines.append(f"interface ve {mgmt}")
            if safe(base.get("switch_ip")) and safe(base.get("switch_mask")):
                lines.append(f" ip address {base['switch_ip']} {base['switch_mask']}")
            lines.append("!")
        if safe(base.get("switch_gateway")):
            lines.extend([f"ip route 0.0.0.0/0 {base['switch_gateway']}", "!"])
    auth_ports = [p.interface for p in ports if p.profile in DEFAULT_AUTH_PROFILES]
    for port in ports:
        lines.append(f"interface ethernet {port.interface}")
        if port.description: lines.append(f" port-name {quote(port.description)}")
        if port.voice_enabled: lines.append(f" voice-vlan {base['voice_vlan']}")
        if truthy(base.get("enable_loop_detection")) and port.profile in {"Edge","Other","AP_Guest","AP_Public","AP_Conference","AP_BOH"}:
            lines.append(" loop-detection")
            if truthy(base.get("loop_detection_shutdown_disable")):
                lines.append(" loop-detection shutdown-disable")
        lines.append("!")
    if truthy(base.get("dot1x_enabled")) and auth_ports:
        port_list = compress_ports(auth_ports)
        lines.extend([
            "authentication",
            f"  auth-mode {base['auth_mode']}",
            f"  auth-default-vlan {base['auth_default_vlan']}",
            f"  voice-vlan {base['voice_vlan']}",
            "  dot1x enable",
            f"  dot1x enable {port_list}",
            f"  dot1x port-control auto {port_list}",
        ])
        if truthy(base.get("macauth_override")):
            lines.append("  dot1x macauth-override")
        lines.extend([
            f"  dot1x timeout tx-period {base['tx_period']}",
            f"  dot1x timeout quiet-period {base['quiet_period']}",
            f"  dot1x timeout supplicant {base['supplicant_timeout']}",
        ])
        if truthy(base.get("mac_auth_enabled")):
            lines.extend(["  mac-authentication enable", "  mac-authentication password-format xx:xx:xx:xx:xx:xx upper-case"])
        lines.append("!")
    return "\n".join(lines)

def build_preview_aruba(base, vlans, ports, profiles):
    prefix = mask_to_prefix(base.get("switch_mask", "255.255.255.0"))
    lines = [
        f"vrf {base['aruba_mgmt_vrf']}",
        "no snmp-server community public",
        "no snmp-server community private",
        "!"
    ]
    for vlan in enabled_vlans(vlans):
        lines.extend([f"vlan {vlan.vlan_id}", f"    name {vlan.name}", "!"])
    mgmt = safe(base.get("switch_mgmt_vlan"))
    if mgmt:
        lines.append(f"interface vlan {mgmt}")
        if safe(base.get("switch_ip")):
            lines.append(f"    ip address {base['switch_ip']}/{prefix}")
        lines.extend([f"    vrf attach {base['aruba_mgmt_vrf']}", "!"])
    if safe(base.get("switch_gateway")):
        lines.extend([f"ip route 0.0.0.0/0 {base['switch_gateway']} vrf {base['aruba_mgmt_vrf']}", "!"])

    profile_lookup = {p.name: p for p in profiles}
    for port in ports:
        lines.append(f"interface {port.interface}")
        if port.profile == "Exempt":
            if port.exempt_untagged:
                lines.extend(["    no routing", f"    vlan access {port.exempt_untagged}"])
            if port.exempt_tagged:
                lines.append(f"    vlan trunk allowed {port.exempt_tagged.replace(' ', '')}")
        else:
            prof = profile_lookup.get(port.profile)
            if prof:
                uvlan, tvlans = resolve_profile_defaults(prof, vlans)
                if uvlan:
                    lines.extend(["    no routing", f"    vlan access {uvlan}"])
                elif tvlans:
                    lines.append("    no routing")
                if tvlans:
                    lines.append(f"    vlan trunk allowed {','.join(tvlans)}")
        if port.description:
            lines.append(f"    description {quote(port.description)}")
        lines.append("!")
    return "\n".join(lines)

def build_preview(base, members, vlans, ports, profiles):
    lines = ["! Switch Configurator Alpha 0.7.5", f"! Brand Profile: {base['brand_profile']}", f"! Deployment Model: {base['deployment_model']}", "!"]
    if base["vendor"] == "Aruba CX-OS":
        lines.append(build_preview_aruba(base, vlans, ports, profiles))
    else:
        lines.append(build_preview_icx(base, vlans, ports, profiles))
    lines.append("end")
    return "\n".join(lines)

def build_context(base, members, vlans, profiles, ports):
    return {
        "request": None,
        "base": base,
        "members": members,
        "vlans": vlans,
        "profiles": profiles,
        "ports": ports,
        "preview": build_preview(base, members, vlans, ports, profiles),
        "warnings": evaluate_warnings(base, vlans, profiles),
        "vendor_options": VENDOR_OPTIONS,
        "brand_options": BRAND_OPTIONS,
        "deployment_mode_options": DEPLOYMENT_MODE_OPTIONS,
        "port_count_options": PORT_COUNT_OPTIONS,
        "switch_role_options": SWITCH_ROLE_OPTIONS,
        "core_type_options": CORE_TYPE_OPTIONS,
        "ap_profile_options": AP_PROFILE_OPTIONS,
        "zone_options": ZONE_OPTIONS,
        "multicast_options": MULTICAST_OPTIONS,
        "favicon_url": FAVICON_URL,
    }



def apply_site_profile_defaults(base, site_profile):
    if not site_profile:
        return base
    data = site_profile.__dict__ if hasattr(site_profile, "__dict__") else {}
    if data.get("site_name") and not base.get("property_name"):
        base["property_name"] = data.get("site_name", "")
    if data.get("site_code"):
        base["site_code"] = data.get("site_code", "")
        if not base.get("marsha_code"):
            base["marsha_code"] = data.get("site_code", "")
    for key in ["brand", "deployment_model", "address_1", "address_2", "city", "state", "postal_code", "country", "property_contact", "property_phone", "marsha_code"]:
        if key in data and data.get(key):
            if key == "brand":
                base["brand_profile"] = data[key]
            elif not base.get(key):
                base[key] = data[key]
    for src, dst in [("default_switch_ip_start", "switch_ip"), ("default_switch_mask", "switch_mask"), ("default_switch_gateway", "switch_gateway"), ("default_mgmt_vlan", "switch_mgmt_vlan")]:
        if data.get(src) and (not base.get(dst) or base.get(dst) in {"10.0.3.130", "255.255.255.128", "10.0.3.129", "100"}):
            base[dst] = data[src]
    if base["brand_profile"] not in BRAND_OPTIONS:
        base["brand_profile"] = "Generic / NonBranded"
    if base["deployment_model"] not in DEPLOYMENT_MODE_OPTIONS.get(base["brand_profile"], []):
        base["deployment_model"] = DEPLOYMENT_MODE_OPTIONS[base["brand_profile"]][0]
    return base


def save_site_from_form(form):
    if SiteProfile is None:
        return None
    payload = {
        "site_name": safe(form.get("site_name")) or safe(form.get("property_name")),
        "site_code": safe(form.get("site_code")) or safe(form.get("marsha_code")),
        "brand": safe(form.get("brand_profile")) or "Generic / NonBranded",
        "deployment_model": safe(form.get("deployment_model")) or "Standard",
        "address_1": safe(form.get("address_1")),
        "address_2": safe(form.get("address_2")),
        "city": safe(form.get("city")),
        "state": safe(form.get("state")),
        "postal_code": safe(form.get("postal_code")),
        "country": safe(form.get("country")) or "US",
        "property_contact": safe(form.get("property_contact")),
        "property_phone": safe(form.get("property_phone")),
        "marsha_code": safe(form.get("marsha_code")),
        "notes": safe(form.get("site_notes")),
        "default_switch_ip_start": safe(form.get("switch_ip")) or "10.0.3.130",
        "default_switch_mask": safe(form.get("switch_mask")) or "255.255.255.128",
        "default_switch_gateway": safe(form.get("switch_gateway")) or "10.0.3.129",
        "default_mgmt_vlan": safe(form.get("switch_mgmt_vlan")) or "100",
        "default_ap_mgmt_vlan": "101",
    }
    return save_site_profile(SiteProfile(**payload))


def context_from_base(base, request):
    members = make_default_members(normalize_num_switches(base["num_switches"]), base["vendor"])
    vlans = default_vlan_rows(base["brand_profile"], base["deployment_model"], base["switch_mgmt_vlan"])
    profiles = default_profiles()
    ports = apply_role_defaults(generate_ports(members, base["vendor"]), members)
    ctx = build_context(base, members, vlans, profiles, ports)
    ctx["request"] = request
    ctx["site_profile"] = load_site_profile()
    ctx["module_base"] = MODULE_BASE
    ctx["logo_url"] = LOGO_URL
    return ctx


@router.get("/static/{file_path:path}")
async def module_static(file_path: str):
    target = APP_DIR / "static" / file_path
    if not target.exists() or not target.is_file():
        return PlainTextResponse("Not found", status_code=404)
    return FileResponse(target)


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    base = dict(BASE_DEFAULTS)
    base = apply_site_profile_defaults(base, load_site_profile())
    return templates.TemplateResponse(request=request, name="index.html", context=context_from_base(base, request))


@router.post("/", response_class=HTMLResponse)
async def render(request: Request):
    form = await request.form()
    if form.get("save_site_context") == "on":
        save_site_from_form(form)
    base = parse_base(form)
    members = parse_members(form, normalize_num_switches(base["num_switches"]))
    vlans = parse_vlans(form, base)
    profiles = parse_profiles(form)
    ports = apply_role_defaults(generate_ports(members, base["vendor"]), members)
    ports = parse_ports(form, ports, [p.name for p in profiles])
    ctx = build_context(base, members, vlans, profiles, ports)
    ctx["request"] = request
    ctx["site_profile"] = load_site_profile()
    ctx["module_base"] = MODULE_BASE
    ctx["logo_url"] = LOGO_URL
    return templates.TemplateResponse(request=request, name="index.html", context=ctx)


@router.post("/download")
async def download(request: Request):
    form = await request.form()
    if form.get("save_site_context") == "on":
        save_site_from_form(form)
    base = parse_base(form)
    members = parse_members(form, normalize_num_switches(base["num_switches"]))
    vlans = parse_vlans(form, base)
    profiles = parse_profiles(form)
    ports = apply_role_defaults(generate_ports(members, base["vendor"]), members)
    ports = parse_ports(form, ports, [p.name for p in profiles])
    content = build_preview(base, members, vlans, ports, profiles)
    filename = f"{safe(base.get('hostname')) or compute_hostname(base) or 'switch'}_config.txt".replace(" ", "_")
    return PlainTextResponse(content, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/api/legacy-script-reference")
def legacy_script_reference():
    import json
    ref_path = Path(__file__).resolve().parents[2] / "shared" / "config_reference" / "legacy_switch_scripts_summary.json"
    if not ref_path.exists():
        return {"available": False, "profiles": {}}
    return {"available": True, "profiles": json.loads(ref_path.read_text(encoding="utf-8"))}
