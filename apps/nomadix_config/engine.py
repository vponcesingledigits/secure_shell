from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
from zipfile import ZipFile, ZIP_DEFLATED

SECTION_RE = re.compile(r"BEGIN_SECTION:(.*?)\n(.*?)END_SECTION:\\1", re.DOTALL)
RECORD_RE = re.compile(r"BEGIN_RECORD:(.*?)\n(.*?)END_RECORD:\\1", re.DOTALL)
KV_RE = re.compile(r"^([^=\n]+)=(.*)$", re.MULTILINE)
REQUIRED_BASELINE_FILES = ["current.txt", "netconf.txt", "inatconf.txt", "mfilter.txt", "nseconf.txt", "subnets.txt"]

AAA_PROFILES = {
    "BAP": {
        "label": "BAP",
        "portal_url": "https://bap.aws.opennetworkexchange.net/cn3k/loginapi.jsp",
        "notes": "Baseline BAP captive portal profile. Detailed values will be profile-driven later.",
    },
    "CLP": {
        "label": "CLP",
        "portal_url": "https://portal.one.singledigits.com/captive-portal",
        "notes": "Baseline CLP/Connect captive portal profile. Detailed values will be profile-driven later.",
    },
    "11OS": {
        "label": "11OS",
        "portal_url": "",
        "notes": "11OS profile placeholder. Detailed AAA, RADIUS, and portal values will be defined later.",
    },
    "Other": {
        "label": "Other",
        "portal_url": "",
        "notes": "Manual/other profile. Use this when values are not covered by BAP, CLP, or 11OS yet.",
    },
}


def normalize_host(host: str) -> str:
    return host.strip().lower()


def nl_join(lines: List[str]) -> str:
    return "\n".join(lines)


@dataclass
class IniConfig:
    values: Dict[str, str] = field(default_factory=dict)


@dataclass
class SectionRecord:
    record_type: str
    values: Dict[str, List[str]] = field(default_factory=dict)

    def get_first(self, key: str, default: str = "") -> str:
        vals = self.values.get(key, [])
        return vals[0] if vals else default


@dataclass
class Section:
    name: str
    records: List[SectionRecord] = field(default_factory=list)


@dataclass
class TextConfig:
    header: str = "[NSE TEXT-BASED CONFIGURATION FILE HEADER VERSION 2.0]"
    trailer: str = "[NSE TEXT-BASED CONFIGURATION FILE TRAILER VERSION 2.0]00000000"
    sections: Dict[str, Section] = field(default_factory=dict)


@dataclass
class BuilderModel:
    current: IniConfig
    netconf: IniConfig
    inatconf: TextConfig
    mfilter: TextConfig
    nseconf: TextConfig
    subnets: TextConfig


@dataclass
class BuildResult:
    ok: bool
    warnings: List[str]
    errors: List[str]
    summary: Dict[str, str]
    output_files: List[str]
    output_zip: Optional[str] = None


class NSEParser:
    @staticmethod
    def parse_ini_like(text: str) -> IniConfig:
        values: Dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
        return IniConfig(values=values)

    @staticmethod
    def parse_text_config(text: str) -> TextConfig:
        cfg = TextConfig()
        for section_match in SECTION_RE.finditer(text):
            section_name = section_match.group(1).strip()
            section = Section(name=section_name)
            for record_match in RECORD_RE.finditer(section_match.group(2)):
                record_type = record_match.group(1).strip()
                values: Dict[str, List[str]] = {}
                for key, value in KV_RE.findall(record_match.group(2)):
                    values.setdefault(key.strip(), []).append(value.strip())
                section.records.append(SectionRecord(record_type=record_type, values=values))
            cfg.sections[section_name] = section
        return cfg


class NSESerializer:
    @staticmethod
    def dump_ini_like(cfg: IniConfig) -> str:
        return nl_join([f"{k}={v}" for k, v in cfg.values.items()]) + "\n"

    @staticmethod
    def dump_text_config(cfg: TextConfig) -> str:
        out: List[str] = [cfg.header, "", ""]
        for section in cfg.sections.values():
            out.extend([f"BEGIN_SECTION:{section.name}", ""])
            for record in section.records:
                out.append(f"BEGIN_RECORD:{record.record_type}")
                for key, vals in record.values.items():
                    for val in vals:
                        out.append(f"{key}={val}")
                out.extend([f"END_RECORD:{record.record_type}", "", ""])
            out.extend([f"END_SECTION:{section.name}", "", "", ""])
        out.append(cfg.trailer)
        return nl_join(out) + "\n"


class ConfigBuilder:
    def __init__(self, root: Path):
        self.root = root
        self.warnings: List[str] = []
        self.model = BuilderModel(
            current=NSEParser.parse_ini_like((root / "current.txt").read_text(encoding="utf-8", errors="ignore")),
            netconf=NSEParser.parse_ini_like((root / "netconf.txt").read_text(encoding="utf-8", errors="ignore")),
            inatconf=NSEParser.parse_text_config((root / "inatconf.txt").read_text(encoding="utf-8", errors="ignore")),
            mfilter=NSEParser.parse_text_config((root / "mfilter.txt").read_text(encoding="utf-8", errors="ignore")),
            nseconf=NSEParser.parse_text_config((root / "nseconf.txt").read_text(encoding="utf-8", errors="ignore")),
            subnets=NSEParser.parse_text_config((root / "subnets.txt").read_text(encoding="utf-8", errors="ignore")),
        )

    def build_from_profile(self, profile: dict) -> BuilderModel:
        self._apply_site_info(profile)
        self._apply_aaa(profile)
        self._apply_wan(profile)
        self._apply_dhcp(profile)
        self._apply_local_vlans(profile)
        self._apply_passthrough(profile)
        self._apply_profile_metadata(profile)
        return self.model

    def _apply_site_info(self, profile: dict) -> None:
        current = self.model.current.values
        site = profile.get("site", {})
        for src, dst in {
            "customer_name": "usg_lks_customer_name",
            "site_name": "usg_lks_site_name",
            "address1": "usg_lks_addr1",
            "address2": "usg_lks_addr2",
            "city": "usg_lks_city",
            "state": "usg_lks_state",
            "zip": "usg_lks_zip",
            "country": "usg_lks_country",
        }.items():
            val = str(site.get(src, "")).strip()
            if val:
                current[dst] = val

    def _apply_aaa(self, profile: dict) -> None:
        aaa = profile.get("aaa", {})
        profile_name = str(aaa.get("profile", "Other")).strip() or "Other"
        if profile_name not in AAA_PROFILES:
            profile_name = "Other"
        current = self.model.current.values
        current["config_aaa_profile"] = profile_name
        current["config_aaa_profile_notes"] = AAA_PROFILES[profile_name]["notes"]
        portal_url = str(aaa.get("portal_url", "")).strip() or AAA_PROFILES[profile_name]["portal_url"]
        if portal_url:
            current["usg_portal_xml_post_url"] = portal_url
        portal_ip = str(aaa.get("portal_ip", "")).strip()
        if portal_ip:
            current["usg_portal_xml_post_ip"] = portal_ip
        portal_host = str(aaa.get("ssl_host_name", "")).strip()
        if portal_host:
            current["aaa_ssl_host_name"] = portal_host
        current["aaa_portal_page_on"] = "yes"
        current["usg_portal_post_port"] = str(aaa.get("portal_port", "443")).strip() or "443"
        current["usg_portal_post_verify_http_on"] = "yes"
        # Only apply profile hints here; exact RADIUS/RadSec records remain later profile work.
        self._update_rad_client_default(str(aaa.get("radius_profile", "")).strip())

    def _update_rad_client_default(self, radius_profile: str) -> None:
        if not radius_profile:
            return
        section = self.model.nseconf.sections.get("radClient")
        if not section or not section.records:
            return
        section.records[0].values["dfltServerName"] = [radius_profile]

    def _apply_wan(self, profile: dict) -> None:
        wan = profile.get("wan", {})
        netconf = self.model.netconf.values
        for src, dst in {
            "network_ip": "network_ip",
            "netmask": "netmask",
            "gateway": "gateway",
            "gateway_arp_refresh_interval": "gateway_arp_refresh_interval",
            "ssid": "nse_loc_network_ssid",
        }.items():
            val = str(wan.get(src, "")).strip()
            if val:
                netconf[dst] = val
        self._apply_port_roles(wan.get("port_roles", {}))

    def _apply_port_roles(self, port_roles: dict) -> None:
        section = self.model.inatconf.sections.get("inatCfgTbl")
        if not section:
            return
        for record in section.records:
            port_name = record.get_first("portName")
            if port_name in port_roles and str(port_roles[port_name]).strip() != "":
                record.values["portRole"] = [str(port_roles[port_name]).strip()]

    def _apply_dhcp(self, profile: dict) -> None:
        pools = profile.get("dhcp", {}).get("pools", [])
        clean_pools = [p for p in pools if any(str(v).strip() for v in p.values())]
        if not clean_pools:
            return
        section = Section(name="dhcpServerPoolCfgTbl")
        for idx, pool in enumerate(clean_pools, start=1):
            section.records.append(SectionRecord("dhcpServerPoolCfgTbl_record", values={
                "poolId": [str(idx)],
                "server_ip": [str(pool.get("server_ip", "")).strip()],
                "netmask": [str(pool.get("netmask", "")).strip()],
                "pool_start_ip": [str(pool.get("start_ip", "")).strip()],
                "pool_stop_ip": [str(pool.get("stop_ip", "")).strip()],
                "lease_minutes": [str(pool.get("lease_minutes", "240")).strip() or "240"],
                "public_pool": ["false"],
                "ipupsell": ["false"],
                "default_pool": ["true" if idx == 1 else "false"],
                "router_specified": ["false"],
                "router": ["0.0.0.0"],
                "dns_server_spec_method": ["0"],
                "specifiedDnsServer": ["0.0.0.0"],
                "enabled": ["true"],
                "numOptions": ["0"],
            }))
        self.model.nseconf.sections["dhcpServerPoolCfgTbl"] = section
        self.model.nseconf.sections["_dhcpServerPoolCfgTbl_control"] = Section(
            name="_dhcpServerPoolCfgTbl_control",
            records=[SectionRecord("_dhcpServerPoolCfgTbl_control_record", {"lastId": [str(len(clean_pools))]})],
        )

    def _apply_local_vlans(self, profile: dict) -> None:
        vlans = profile.get("local_vlans", [])
        clean = [v for v in vlans if any(str(x).strip() for x in v.values())]
        if not clean:
            return
        self.model.netconf.values["config_local_vlan_count"] = str(len(clean))
        for idx, vlan in enumerate(clean, start=1):
            self.model.netconf.values[f"config_local_vlan_{idx}_id"] = str(vlan.get("vlan_id", "")).strip()
            self.model.netconf.values[f"config_local_vlan_{idx}_name"] = str(vlan.get("name", "")).strip()
            self.model.netconf.values[f"config_local_vlan_{idx}_gateway"] = str(vlan.get("gateway", "")).strip()
            self.model.netconf.values[f"config_local_vlan_{idx}_prefix"] = str(vlan.get("prefix", "")).strip()
        self.warnings.append("Local VLANs are recorded as builder metadata for this alpha. Exact Nomadix sub-interface generation will be profile-driven in a later pass.")

    def _apply_passthrough(self, profile: dict) -> None:
        hosts = [str(x).strip() for x in profile.get("passthrough_hosts", []) if str(x).strip()]
        seen = set()
        deduped: List[str] = []
        for host in hosts:
            key = normalize_host(host)
            if key and key not in seen:
                seen.add(key)
                deduped.append(host)
        current = self.model.current.values
        current["usg_hostpassthru_initialize_on"] = "1"
        current["usg_blacklist_hostPassthru_on"] = "yes"
        current["config_passthrough_host_count"] = str(len(deduped))
        for key in list(current.keys()):
            if re.fullmatch(r"(?:usg_)?hostpassthru_(?:host|addr|domain)\d+", key):
                current.pop(key, None)
        for idx, host in enumerate(deduped, start=1):
            current[f"hostpassthru_host{idx}"] = host
        self._set_host_passthru_table(deduped)

    def _set_host_passthru_table(self, hosts: List[str]) -> None:
        self.model.nseconf.sections["hostPassthru"] = Section(
            name="hostPassthru",
            records=[SectionRecord("hostPassthru_record", {"enable": ["true"], "numEntries": [str(len(hosts))]})],
        )
        self.model.nseconf.sections["_hostPassthruTbl_control"] = Section(
            name="_hostPassthruTbl_control",
            records=[SectionRecord("_hostPassthruTbl_control_record", {"lastId": [str(len(hosts))]})],
        )
        self.model.nseconf.sections["hostPassthruTbl"] = Section(
            name="hostPassthruTbl",
            records=[SectionRecord("hostPassthruTbl_record", {"passthruId": [str(i)], "passthruName": [host]}) for i, host in enumerate(hosts, start=1)],
        )

    def _apply_profile_metadata(self, profile: dict) -> None:
        current = self.model.current.values
        current["config_brand_profile"] = str(profile.get("brand", "Generic"))
        current["config_builder_mode"] = "guided-light"
        current["config_profile_note"] = "Site Info, AAA, WAN, DHCP, Local VLANs, and passthrough are guided. Remaining settings inherit from selected profiles/baseline."

    def write_output(self, outdir: Path, profile: dict) -> List[str]:
        outdir.mkdir(parents=True, exist_ok=True)
        files = {
            "current.txt": NSESerializer.dump_ini_like(self.model.current),
            "netconf.txt": NSESerializer.dump_ini_like(self.model.netconf),
            "inatconf.txt": NSESerializer.dump_text_config(self.model.inatconf),
            "mfilter.txt": NSESerializer.dump_text_config(self.model.mfilter),
            "nseconf.txt": NSESerializer.dump_text_config(self.model.nseconf),
            "subnets.txt": NSESerializer.dump_text_config(self.model.subnets),
            "profile.json": json.dumps(profile, indent=2),
            "README_IMPLEMENTATION.txt": self._readme(profile),
        }
        written = []
        for name, content in files.items():
            (outdir / name).write_text(content, encoding="utf-8")
            written.append(name)
        return written

    def _readme(self, profile: dict) -> str:
        lines = [
            "Nomadix Configuration Builder Output",
            "====================================",
            "Generated by Single Digits Engineering Platform shell module.",
            "",
            f"Brand/Profile: {profile.get('brand', 'Generic')}",
            f"AAA Profile: {profile.get('aaa', {}).get('profile', 'Other')}",
            "",
            "Guided sections used in this alpha:",
            "- Site Info",
            "- AAA",
            "- WAN",
            "- DHCP",
            "- Local VLANs",
            "- Passthrough list",
            "",
            "Remaining fields inherit from the baseline and selected profile placeholders. Review all generated files before importing or pasting into production equipment.",
        ]
        if self.warnings:
            lines.extend(["", "Warnings / Notes:"] + [f"- {w}" for w in self.warnings])
        return nl_join(lines) + "\n"


def extract_baseline_zip(zip_path: Path, dest: Path) -> None:
    with ZipFile(zip_path, "r") as zf:
        for member in zf.namelist():
            name = Path(member).name
            if name in REQUIRED_BASELINE_FILES:
                (dest / name).write_bytes(zf.read(member))
    missing = [name for name in REQUIRED_BASELINE_FILES if not (dest / name).exists()]
    if missing:
        raise ValueError("Baseline ZIP is missing required files: " + ", ".join(missing))


def build_zip_from_profile(baseline_zip: Path, profile: dict, job_dir: Path) -> BuildResult:
    baseline_dir = job_dir / "baseline"
    output_dir = job_dir / "output"
    baseline_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        extract_baseline_zip(baseline_zip, baseline_dir)
        builder = ConfigBuilder(baseline_dir)
        builder.build_from_profile(profile)
        output_files = builder.write_output(output_dir, profile)
        zip_path = job_dir / "nomadix_config_output.zip"
        with ZipFile(zip_path, "w", compression=ZIP_DEFLATED) as zf:
            for name in output_files:
                zf.write(output_dir / name, name)
        summary = {
            "brand": profile.get("brand", "Generic"),
            "aaa_profile": profile.get("aaa", {}).get("profile", "Other"),
            "site": profile.get("site", {}).get("site_name", ""),
            "passthrough_count": builder.model.current.values.get("config_passthrough_host_count", "0"),
            "dhcp_pools": str(len([p for p in profile.get("dhcp", {}).get("pools", []) if any(str(v).strip() for v in p.values())])),
            "local_vlans": str(len([v for v in profile.get("local_vlans", []) if any(str(x).strip() for x in v.values())])),
        }
        return BuildResult(True, builder.warnings, [], summary, output_files, str(zip_path))
    except Exception as exc:
        return BuildResult(False, [], [str(exc)], {}, [], None)
