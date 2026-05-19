
"""Monitoring and down-device investigation helpers for the shell.

This module captures reusable logic imported from the earlier Monitoring Tool
Alpha 0.7.5 imported standalone build and normalizes it for the Single Digits Engineering
Platform shared model.  It intentionally performs read-only collection.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Optional
import re

from shared.models import Credentials, SSHOptions, SwitchTarget, Vendor
from shared.parsers import clean_output, redact_sensitive, parse_interface_brief
from shared.ssh import scan_single_switch
from shared.vendors import detect_vendor
from shared.commands import get_monitoring_status_commands, get_monitoring_detail_commands


def mac_compact(mac: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", mac or "").lower()


def fmt_mac_cisco_ruckus(mac: str) -> str:
    s = mac_compact(mac)
    return f"{s[0:4]}.{s[4:8]}.{s[8:12]}" if len(s) == 12 else mac


def fmt_mac_colon(mac: str) -> str:
    s = mac_compact(mac)
    return ":".join(s[i:i + 2] for i in range(0, 12, 2)) if len(s) == 12 else mac


def fmt_mac_procurve(mac: str) -> str:
    s = mac_compact(mac)
    return f"{s[0:6]}-{s[6:12]}" if len(s) == 12 else mac


@dataclass
class DownDeviceFinding:
    port: str
    neighbor_name: Optional[str] = None
    link_speed_mbps: Optional[int] = None
    flap_detected: bool = False
    below_gig: bool = False
    total_errors: int = 0
    summary: str = ""


@dataclass
class DownDeviceResult:
    status: str = "Inconclusive"
    confidence: str = "low"
    parent_ip: str = ""
    parent_vendor: str = "Unknown"
    parent_hostname: Optional[str] = None
    identified_port: Optional[str] = None
    lldp_neighbor_name: Optional[str] = None
    lldp_management_ip: Optional[str] = None
    poe_detected: bool = False
    poe_watts: Optional[str] = None
    alternate_ip_detected: bool = False
    alternate_ip: Optional[str] = None
    version_info: dict[str, str] = field(default_factory=lambda: {
        "model": "Unknown", "firmware_version": "Unknown", "uptime": "Unknown", "last_reboot_reason": "Unknown"
    })
    interface_observations: list[dict[str, Any]] = field(default_factory=list)
    port_findings: list[dict[str, Any]] = field(default_factory=list)
    recommended_next_steps: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    raw_output: str = ""
    started_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    completed_at: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _vendor_label(vendor: Vendor | str | None) -> str:
    value = getattr(vendor, "value", vendor) or "unknown"
    return str(value).replace("_", " ").replace("cxos", "CX").title()


def _device_aliases(value: str) -> set[str]:
    raw = (value or "").strip().lower()
    compact = re.sub(r"[^a-z0-9]", "", raw)
    aliases = {raw, compact}
    pieces = [p for p in re.split(r"[^a-z0-9]+", raw) if p]
    aliases.update(pieces)
    for m in re.finditer(r"sw(\d{1,3})", compact):
        digits = m.group(1)
        aliases.add(f"sw{digits}")
        aliases.add(f"sw{digits.zfill(3)}")
        aliases.add(f"sw{int(digits):02d}")
        aliases.add(f"sw{int(digits)}")
    if "mdf" in compact:
        aliases.add("mdf")
    for m in re.finditer(r"idf(\d+)", compact):
        aliases.add(f"idf{m.group(1)}")
    return {a for a in aliases if a}


def score_device_name_match(target: str, candidate: str) -> tuple[int, str]:
    t_aliases = _device_aliases(target)
    c_aliases = _device_aliases(candidate)
    if not t_aliases or not c_aliases:
        return 0, "none"
    t_compact = re.sub(r"[^a-z0-9]", "", (target or "").lower())
    c_compact = re.sub(r"[^a-z0-9]", "", (candidate or "").lower())
    if t_compact and t_compact == c_compact:
        return 100, "exact"
    if t_compact and c_compact and (t_compact in c_compact or c_compact in t_compact):
        return 90, "strong_partial"
    common = t_aliases & c_aliases
    if common:
        if any(a.startswith("sw") and len(a) >= 4 for a in common):
            if ("mdf" in t_aliases and "mdf" in c_aliases) or any(a.startswith("idf") for a in common):
                return 82, "strong_partial"
            return 72, "reasonable_partial"
        return 65, "alias_partial"
    return 0, "none"


def parse_version_info(vendor: Vendor | str, text: str) -> dict[str, str]:
    clean = clean_output(text)
    v = getattr(vendor, "value", vendor)
    result = {"model": "Unknown", "firmware_version": "Unknown", "uptime": "Unknown", "last_reboot_reason": "Unknown"}
    if v == Vendor.RUCKUS_ICX.value or "ruckus" in str(v):
        if m := re.search(r"HW:\s*(.+)", clean): result["model"] = m.group(1).strip()
        if m := re.search(r"SW:\s*Version\s+([^\s]+)", clean): result["firmware_version"] = m.group(1).strip()
        if m := re.search(r"system uptime is\s+(.+)", clean, re.I): result["uptime"] = m.group(1).strip()
        if m := re.search(r"The system\s*:\s*started=([^\s]+)(?:\s+reloaded=by\s+\"([^\"]+)\")?", clean):
            result["last_reboot_reason"] = f"{m.group(1)}; reloaded by {m.group(2) or 'unknown'}"
    elif v == Vendor.CISCO_IOS.value or "cisco" in str(v):
        if m := re.search(r"(?:cisco\s+)?(WS-[A-Za-z0-9-]+|C\d{3,4}[A-Za-z0-9-]+)", clean, re.I): result["model"] = m.group(1)
        if m := re.search(r"Version\s+([^,\s]+)", clean): result["firmware_version"] = m.group(1)
        if m := re.search(r"uptime is\s+(.+)", clean, re.I): result["uptime"] = m.group(1).strip()
        if m := re.search(r"Last reload reason:\s*(.+)", clean, re.I): result["last_reboot_reason"] = m.group(1).strip()
    elif v == Vendor.ARUBA_CX.value or "cx" in str(v):
        if m := re.search(r"(?:AOS-CX\s+)?Version\s*[: ]\s*([^\r\n]+)", clean, re.I): result["firmware_version"] = m.group(1).strip()
        if m := re.search(r"Product\s+Name\s*:\s*([^\r\n]+)", clean, re.I): result["model"] = m.group(1).strip()
        else: result["model"] = "AOS-CX Switch"
    elif v == Vendor.PROCURVE.value or "procurve" in str(v):
        if m := re.search(r"\b([A-Z]{1,3}\.\d{2}\.\d{2}\.\d{4})\b", clean): result["firmware_version"] = m.group(1).strip()
        if m := re.search(r"\b(J\d{4}[A-Z])\b", clean): result["model"] = m.group(1).strip()
        else: result["model"] = "Aruba ProCurve"
    elif v == Vendor.TPLINK_MEDIA_PANEL.value or "tplink" in str(v) or "tp" in str(v):
        if m := re.search(r"System Description\s*-\s*(.+)", clean): result["model"] = m.group(1).strip()
        if m := re.search(r"Software Version\s*-\s*(.+)", clean): result["firmware_version"] = m.group(1).strip()
        if m := re.search(r"Running Time\s*-\s*(.+)", clean): result["uptime"] = m.group(1).strip()
    elif v == Vendor.EXTREME_EXOS.value or "extreme" in str(v):
        if m := re.search(r"System Type\s*:\s*([^\r\n]+)", clean): result["model"] = m.group(1).strip()
        if m := re.search(r"ExtremeXOS\s+version\s+([^\s]+)", clean, re.I): result["firmware_version"] = m.group(1).strip()
        if m := re.search(r"Boot Time\s*:\s*([^\r\n]+)", clean): result["uptime"] = m.group(1).strip()
    return result


def parse_candidate_port_details(vendor: Vendor, hostname: str, status_text: str) -> Optional[dict[str, Any]]:
    target = (hostname or "").strip()
    if not target:
        return None
    ports = parse_interface_brief(vendor, status_text)
    best: Optional[dict[str, Any]] = None
    for row in ports:
        candidate_name = row.description or ""
        score, match_type = score_device_name_match(target, candidate_name)
        if score <= 0:
            continue
        enriched = asdict(row)
        enriched["admin_state"] = row.status or "unknown"
        enriched["oper_state"] = row.status or "unknown"
        enriched["speed_mbps"] = _speed_to_mbps(row.speed)
        enriched["native_vlan"] = row.untagged_vlan or ""
        enriched["match_score"] = score
        enriched["match_type"] = match_type
        if best is None or enriched["match_score"] > best["match_score"]:
            best = enriched
    return best


def _speed_to_mbps(value: Any) -> Optional[int]:
    if value is None:
        return None
    s = str(value).strip().lower()
    if s in ("auto", "--", "none", ""):
        return None
    if s.endswith("g"):
        try: return int(float(s[:-1]) * 1000)
        except ValueError: return None
    if s.endswith("m"):
        try: return int(float(s[:-1]))
        except ValueError: return None
    if s in ("1000", "100", "10", "2500", "5000", "10000"):
        return int(s)
    return None


def parse_lldp_identity(text: str) -> dict[str, Optional[str]]:
    clean = clean_output(text)
    data = {"neighbor_name": None, "management_ip": None}
    patterns = [
        r"System\s+name\s*[:=]\s*(.+)", r"System\s+Name\s*[:=]\s*(.+)", r"SysName\s*[:=]\s*(.+)",
        r"Device\s+ID\s*[:=]\s*(.+)",
    ]
    for pat in patterns:
        if m := re.search(pat, clean, re.I):
            data["neighbor_name"] = m.group(1).strip().strip('"')
            break
    ip_patterns = [
        r"Management address \(IPv4\):\s*([0-9.]+)", r"Management\s+Address\s*:?\s*([0-9.]+)", r"IP\s+address\s*:?\s*([0-9.]+)",
    ]
    for pat in ip_patterns:
        if m := re.search(pat, clean, re.I):
            data["management_ip"] = m.group(1).strip()
            break
    return data


def parse_port_health(vendor: Vendor, port: str, text: str) -> dict[str, Any]:
    clean = clean_output(text)
    health: dict[str, Any] = {
        "port": port,
        "admin_state": "unknown",
        "oper_state": "unknown",
        "link_state": "unknown",
        "interface_uptime": "Unknown",
        "speed_mbps": None,
        "down_transition_count": 0,
        "likely_going_down": "No",
        "notes": [],
        "errors": 0,
    }
    if m := re.search(r"is (up|down), line protocol is (up|down)", clean, re.I):
        health["oper_state"] = m.group(1).lower(); health["link_state"] = m.group(1).lower()
    if m := re.search(r"Port up for (.+)", clean, re.I): health["interface_uptime"] = m.group(1).strip()
    if m := re.search(r"actual\s+(\d+)Gbit", clean, re.I): health["speed_mbps"] = int(m.group(1)) * 1000
    elif m := re.search(r"actual\s+(\d+)Mbit", clean, re.I): health["speed_mbps"] = int(m.group(1))
    elif m := re.search(r"\b(10|100|1000|2500|5000|10000)\s*(?:Mb/s|Mbps|Mbit)?\b", clean, re.I): health["speed_mbps"] = int(m.group(1))
    if m := re.search(r"(\d+) input errors, (\d+) CRC, (\d+) frame", clean, re.I):
        errs = sum(int(x) for x in m.groups()); health["errors"] += errs
        if errs: health["notes"].append(f"input/CRC/frame errors {errs}")
    if m := re.search(r"(\d+) output errors, (\d+) collisions", clean, re.I):
        errs = sum(int(x) for x in m.groups()); health["errors"] += errs
        if errs: health["notes"].append(f"output/collision errors {errs}")
    if health["speed_mbps"] and health["speed_mbps"] < 1000:
        health["notes"].append("below expected gigabit speed")
    if health["errors"] > 0:
        health["likely_going_down"] = "Possible"
    return health


def run_down_device_troubleshooter(
    parent_ip: str,
    username: str,
    password: str,
    down_device_ip: str = "",
    down_device_mac: str = "",
    down_device_hostname: str = "",
    is_access_point: bool = False,
    timeout: int = 12,
    debug: bool = False,
) -> DownDeviceResult:
    result = DownDeviceResult(parent_ip=parent_ip)
    creds = Credentials(username=username, password=password)
    opts = SSHOptions(timeout=timeout, command_timeout=30, debug=debug, old_kex=True)
    target = SwitchTarget(host=parent_ip, port=22)
    status_commands = []
    # Run broad read-only discovery commands. The shared SSH engine detects vendor first and disables paging.
    for cmd in [
        "show version", "show system", "show int brief", "show interface brief", "show interfaces brief",
        "show interface status", "show interfaces status", "show name", "show ports no-refresh",
        "show lldp neighbors", "show lldp neighbor-info", "show lldp info remote-device", "show lldp neighbors detailed | include Name|Address",
    ]:
        if cmd not in status_commands:
            status_commands.append(cmd)
    session = scan_single_switch(target, creds, status_commands, opts)
    transcript = []
    for row in session.command_results:
        transcript.append(f"\n# {row.command}\n{row.output}\n")
    result.raw_output = redact_sensitive(clean_output("\n".join(transcript)), [password])

    if not session.ok:
        result.status = "SSH collection failed"
        result.notes.append(session.error or "Unable to connect to parent switch.")
        result.completed_at = datetime.now().isoformat(timespec="seconds")
        return result

    vendor = session.vendor
    result.parent_vendor = _vendor_label(vendor)
    result.parent_hostname = session.hostname
    version_blob = "\n".join(row.output for row in session.command_results if "version" in row.command.lower() or row.command.lower() == "show system")
    result.version_info = parse_version_info(vendor, version_blob)

    status_blob = "\n".join(row.output for row in session.command_results if row.command in get_monitoring_status_commands(vendor) or "ports no-refresh" in row.command)
    candidate = parse_candidate_port_details(vendor, down_device_hostname, status_blob)

    # MAC/IP direct lookup can be added here later. Hostname/port-name matching is the imported Alpha 0.7.5 imported behavior.
    if candidate:
        candidate_port = candidate["port"]
        result.identified_port = candidate_port
        detail_commands = get_monitoring_detail_commands(vendor, candidate_port, down_device_mac, down_device_ip)
        if detail_commands:
            detail_session = scan_single_switch(target, creds, detail_commands, opts)
            detail_blob = "\n".join(f"\n# {r.command}\n{r.output}\n" for r in detail_session.command_results)
            result.raw_output += "\n" + redact_sensitive(clean_output(detail_blob), [password])
        else:
            detail_blob = ""

        iface = parse_port_health(vendor, candidate_port, detail_blob)
        if candidate.get("speed_mbps") and not iface.get("speed_mbps"):
            iface["speed_mbps"] = candidate.get("speed_mbps")
        iface["admin_state"] = candidate.get("admin_state") or iface.get("admin_state")
        iface["oper_state"] = candidate.get("oper_state") or iface.get("oper_state")
        result.interface_observations.append(iface)
        lldp = parse_lldp_identity(detail_blob)
        result.lldp_neighbor_name = lldp.get("neighbor_name")
        result.lldp_management_ip = lldp.get("management_ip")
        notes = list(iface.get("notes") or [])
        notes.append(f"name match {candidate.get('match_type', 'unknown').replace('_', ' ')}")
        if result.lldp_neighbor_name:
            notes.append(f"LLDP neighbor {result.lldp_neighbor_name}")
        lldp_score, _ = score_device_name_match(down_device_hostname, result.lldp_neighbor_name or "")
        result.port_findings.append({
            "port": candidate_port,
            "neighbor_name": result.lldp_neighbor_name or candidate.get("description") or down_device_hostname or None,
            "link_speed_mbps": iface.get("speed_mbps"),
            "flap_detected": False,
            "below_gig": bool(iface.get("speed_mbps") and iface.get("speed_mbps") < 1000),
            "total_errors": iface.get("errors", 0),
            "summary": "; ".join(notes) if notes else "Interface collected",
        })
        if lldp_score >= 80:
            result.status = "Confirmed by LLDP and port-name evidence"
            result.confidence = "high"
        elif candidate.get("match_score", 0) >= 80:
            result.status = "Strong partial port-name match located"
            result.confidence = "probable"
        else:
            result.status = "Reasonable port-name match located"
            result.confidence = "medium"
        result.recommended_next_steps = [
            f"Validate port {candidate_port} on the parent switch.",
            "Review LLDP, interface health, and PoE if this is an AP.",
        ]
    else:
        result.status = "Inconclusive after live SSH checks"
        result.notes.append("No direct candidate port match was identified from the collected port-name/status output.")
        result.recommended_next_steps = [
            "Review raw output for parser behavior and platform differences.",
            "Provide the exact down-device hostname or MAC address to improve confidence.",
            "Run MAC Trace if the device MAC is known and the parent switch is not certain.",
        ]
    result.completed_at = datetime.now().isoformat(timespec="seconds")
    return result
