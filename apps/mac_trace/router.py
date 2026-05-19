from __future__ import annotations
from shared.hp_models import extract_hp_model, get_hp_model_info, enrich_from_text, is_hp_aruba_model_text, observe_hp_model_text

import json
import re
import socket
import threading
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates

from shared.models import Credentials, SSHOptions, SwitchTarget, Vendor
from shared.ssh import scan_single_switch, _connect, _prime_shell, _run_detection, _send_command, configure_logging, clean_terminal_text, extract_network_prompt, has_network_prompt, settle_shell_prompt
from shared.commands import get_paging_disable_commands, get_mac_trace_lookup_commands, get_mac_trace_port_detail_commands, get_mac_trace_ap_power_commands
from shared.vendors import detect_vendor

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
router = APIRouter(prefix="/apps/mac-trace", tags=["MAC Trace"])
_LAST_TRACE: Dict[str, Any] | None = None
_TRACE_JOBS: Dict[str, Dict[str, Any]] = {}
_TRACE_JOBS_LOCK = threading.Lock()

# MAC Trace intentionally avoids dumping the full MAC table.
# It sends vendor-specific single-MAC lookup commands, then follows up with
# port-specific LLDP / health commands only after the learned port is known.


# --- MAC Trace ProCurve single-MAC result parser hotfix ---

def _mt_clean_mac_hotfix(mac: str) -> str:
    import re
    return re.sub(r"[^0-9A-Fa-f]", "", mac or "").lower()


def _mt_parse_procurve_single_mac_result(outputs, mac: str):
    """
    Parse ProCurve/ArubaOS-Switch single-MAC lookup output.

    Example:
        Status and Counters - Address Table - 48d6d5-3a5728

        Port                            VLAN
        ------------------------------- ----
        B15                             1000

    Returns:
        vlan, port, evidence_line
    """
    import re

    combined = "\n".join(str(v) for v in outputs.values()) if isinstance(outputs, dict) else str(outputs)
    target = _mt_clean_mac_hotfix(mac)

    compact_output = _mt_clean_mac_hotfix(combined)
    if target and target not in compact_output:
        return "", "", ""

    lines = combined.splitlines()

    for idx, line in enumerate(lines):
        if re.search(r"\bPort\b", line, re.I) and re.search(r"\bVLAN\b", line, re.I):
            for row in lines[idx + 1: idx + 10]:
                raw = row.strip()
                if not raw:
                    continue
                if re.fullmatch(r"[-\s]+", raw):
                    continue
                if raw.endswith("#") or raw.startswith("$"):
                    continue

                parts = raw.split()
                if len(parts) < 2:
                    continue

                port = parts[0].strip()
                vlan = parts[1].strip()

                if re.fullmatch(r"([A-Z]\d{1,2}|\d{1,3}|Trk\d+|trk\d+|[A-Z]\d{1,2}-[A-Z]\d{1,2})", port, re.I) and re.fullmatch(r"\d{1,4}", vlan):
                    return vlan, port, raw

    for line in lines:
        raw = line.strip()
        if not raw:
            continue

        compact_line = _mt_clean_mac_hotfix(raw)
        if target and target not in compact_line:
            continue

        parts = raw.replace(",", " ").split()
        for i in range(len(parts) - 1):
            port = parts[i].strip()
            vlan = parts[i + 1].strip()
            if re.fullmatch(r"([A-Z]\d{1,2}|\d{1,3}|Trk\d+|trk\d+)", port, re.I) and re.fullmatch(r"\d{1,4}", vlan):
                return vlan, port, raw

    return "", "", ""
# --- End MAC Trace ProCurve single-MAC result parser hotfix ---

def mac_formats(mac: str) -> Dict[str, str]:
    compact = compact_mac(mac)
    if len(compact) != 12:
        return {"raw": mac.strip()}
    return {
        "compact": compact,
        "dot": f"{compact[0:4]}.{compact[4:8]}.{compact[8:12]}",
        "colon": ":".join(compact[i:i+2] for i in range(0, 12, 2)),
        "dash6": f"{compact[0:6]}-{compact[6:12]}",
        "dash4": f"{compact[0:4]}-{compact[4:8]}-{compact[8:12]}",
    }



def _vendor_key(vendor: Any) -> str:
    value = vendor.value if hasattr(vendor, "value") else str(vendor or "")
    return value.lower()


def vendor_mac_lookup_commands(vendor: Any, mac: str) -> List[str]:
    f = mac_formats(mac)
    v = _vendor_key(vendor)

    if any(x in v for x in ["procurve", "hp_aruba_procurve", "aruba_procurve", "arubaos-switch"]):
        return [
            f"show mac-address | includ {f['dash6']}",
            f"show mac-address {f['dash6']}",
        ]

    if any(x in v for x in ["ruckus", "icx", "tp-link", "tplink", "tp_link"]):
        return [f"show mac-address {f['dot']}"]

    if any(x in v for x in ["cisco", "ios"]):
        return [
            f"show mac address-table address {f['dot']}",
            f"show mac address-table | include {f['dot']}",
        ]

    if any(x in v for x in ["aruba_cx", "aos-cx", "cxos"]):
        return [
            f"show mac-address-table address {f['colon']}",
            f"show mac-address-table | include {f['colon']}",
            f"show mac-address-table | include {f['dot']}",
        ]

    return [f"show mac-address {f['dot']}", f"show mac-address {f['dash6']}"]

def build_mac_lookup_commands(mac: str, vendor: Any = "") -> List[str]:
    return vendor_mac_lookup_commands(vendor, mac)

def build_port_detail_commands(vendor: str, port: str | None) -> List[str]:
    # Shared vendor-aware command catalog. This must remain learned-port-only.
    return get_mac_trace_port_detail_commands(vendor, normalize_port(port) if port else port)

AP_HINTS = re.compile(r"(\b(ap|wap|r3\d\d|r5\d\d|r6\d\d|r7\d\d|r8\d\d|h3\d\d|h5\d\d|t3\d\d|t5\d\d|ruckus\s*ap|zoneflex|unleashed)\b|[A-Z0-9_-]*AP\d*[A-Z0-9_-]*)", re.I)
SWITCH_HINTS = re.compile(r"(\b(sw|switch|icx|cx\d*|procurve|catalyst|cisco|aruba|hpe|brocade|stack)\b|[A-Z0-9_-]*(?:LWSW|DSW|CSW|MDF|IDF)[A-Z0-9_-]*)", re.I)
FIREWALL_HINTS = re.compile(r"(firewall|watchguard|fortinet|fortigate|palo|sonicwall|gateway|nomadix)", re.I)
PORT_RE = re.compile(r"(?i)\b(?:eth|ethernet|gi|gigabitethernet|te|tengigabitethernet|fa|port-channel|po)?\s*([a-z]*\d+(?:/\d+){0,3}|\d+/\d+/\d+|\d+/\d+|\d+)\b")


def norm_mac(mac: str) -> str:
    s = re.sub(r"[^0-9a-fA-F]", "", mac or "").lower()
    if len(s) != 12:
        return (mac or "").strip().lower()
    return ":".join(s[i:i+2] for i in range(0, 12, 2))


def compact_mac(mac: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", mac or "").lower()


def looks_like_mac(value: str | None) -> bool:
    return len(compact_mac(value or "")) == 12


def command_map(result) -> Dict[str, str]:
    return {c.command: c.output or "" for c in result.command_results}


def output_blob(outputs: Dict[str, str], names: List[str]) -> str:
    return "\n".join(v for k, v in outputs.items() if any(n.lower() in k.lower() for n in names))


PROPERTY_DEVICE_NAME_RE = re.compile(
    r"(?i)\b(?P<property>[A-Z0-9]{3,8})(?P<device>SW|AP|WAP|GW|FW|RTR|RTRS|CORE|EDGE)(?P<number>\d{0,3})(?:[-_](?P<floor>[A-Z0-9]+))?(?:[-_](?P<location>[A-Z0-9]+))?"
)

def _classify_single_digits_name(name: str | None) -> str | None:
    """Classify common Single Digits device names.

    Convention:
      <propertycode><devicecode>-<floor>-<idf_location>

    Example:
      PHXBDSW01-14-IDF14
        property = PHXBD
        device   = SW
        floor    = 14
        location = IDF14

    Important:
      SW means switch and should override generic LLDP capabilities like
      "bridge, router". Many switches advertise router capability.
    """
    value = (name or "").strip().upper()
    if not value:
        return None

    # Strong explicit AP naming.
    if re.search(r"(^|[-_])(AP|WAP)\d*($|[-_])", value) or re.search(r"[A-Z0-9]+AP\d+", value):
        return "ap"

    # Strong explicit switch naming.
    # PHXBDSW01-14-IDF14, PVDLWSW03-03-IDFBC, CORE/MDF/IDF switch names.
    if re.search(r"^[A-Z0-9]{3,8}SW\d{0,3}(?:[-_][A-Z0-9]+){0,3}$", value):
        return "switch"
    if re.search(r"(?:LWSW|DSW|CSW|MDF|IDF)", value):
        return "switch"

    # Gateway/firewall naming. Do not treat plain "router" capability as gateway.
    if re.search(r"^[A-Z0-9]{3,8}(?:GW|FW|RTR)\d{0,3}(?:[-_][A-Z0-9]+){0,3}$", value):
        return "gateway"

    m = PROPERTY_DEVICE_NAME_RE.search(value)
    if m:
        dev = (m.group("device") or "").upper()
        if dev in {"SW", "CORE", "EDGE"}:
            return "switch"
        if dev in {"AP", "WAP"}:
            return "ap"
        if dev in {"GW", "FW", "RTR", "RTRS"}:
            return "gateway"

    return None




def _looks_like_procurve_run_header(text: str) -> bool:
    """Detect ProCurve / ArubaOS-Switch from running-config header."""
    s = text or ""
    return bool(
        re.search(r"(?im)^\s*;\s*(?:HP\s*)?J\d{4}[A-Z]\b.*Configuration Editor", s)
        or re.search(r"(?im)^\s*;\s*(?:HP\s*)?J\d{4}[A-Z]\b.*release\s+#?[A-Z]{1,3}\.\d+\.\d+", s)
        or re.search(r"(?im)^\s*;\s*Created on release\s+#?[A-Z]{1,3}\.\d+\.\d+", s)
        or is_hp_aruba_model_text(s)
    )


def _parse_procurve_run_header(text: str) -> dict:
    """Parse model/release from ProCurve running-config header."""
    s = text or ""
    result = {}

    m = re.search(r"(?im)^\s*;\s*((?:HP\s*)?J\d{4}[A-Z])\b", s)
    if m:
        result["model"] = m.group(1).replace(" ", "").strip()

    m = re.search(r"(?i)release\s+#?([A-Z]{1,3}\.\d+\.\d+(?:\.\d+)?)", s)
    if m:
        result["software_revision"] = m.group(1).strip()

    return result

def _looks_like_procurve_show_system(text: str) -> bool:
    """Detect ProCurve / ArubaOS-Switch from show system output."""
    s = (text or "").lower()
    return (
        "status and counters - general system information" in s
        or ("software revision" in s and "rom version" in s)
        or ("allow v2 modules" in s and "mac age time" in s)
        or ("ip mgmt" in s and "pkts rx" in s and "pkts tx" in s)
        or is_hp_aruba_model_text(text)
    )

def _infer_vendor_from_hostname_and_prompt(hostname: str | None, prompt: str | None = None) -> Optional[str]:
    """Infer ProCurve/ArubaOS-Switch from Single Digits switch hostnames.

    If show version is inconclusive after nested SSH, do not leave a hostname
    like PHXBDSW03-17-IDF17 as unknown. Use the ProCurve command set instead of
    broad unknown fallbacks.
    """
    text = f"{hostname or ''} {prompt or ''}".upper()
    if re.search(r"\b[A-Z0-9]{3,8}SW\d{0,3}(?:[-_][A-Z0-9]+){0,3}\b", text):
        return "hp_aruba_procurve"
    if "IDF" in text or "MDF" in text:
        return "hp_aruba_procurve"
    return None

def classify_neighbor(name: str | None, ip: str | None = None, description: str | None = None) -> str:
    """Classify LLDP neighbor type.

    Priority:
    1. Single Digits naming convention / explicit hostname.
    2. AP-specific description or AP naming.
    3. Switch-specific description / bridge capability.
    4. Gateway/firewall-specific name or description.

    This avoids false gateway classification from LLDP capability text like
    "bridge, router" on normal ProCurve switches.
    """
    name_text = (name or "").strip()
    desc_text = (description or "").strip()
    combined = f"{name_text} {ip or ''} {desc_text}".strip()

    named_type = _classify_single_digits_name(name_text)
    if named_type:
        return named_type

    # APs first when description is explicit.
    if AP_HINTS.search(combined):
        return "ap"
    if re.search(r"(?i)wireless\s+ap|access\s+point|multimedia\s+hotzone|ruckus\s+h\d+|ruckus\s+r\d+|ruckus\s+t\d+|wlan-access-point", combined):
        return "ap"
    if ip and re.match(r"^192\.168\.", ip) and name_text and re.search(r"(?i)AP|WAP|wireless", name_text):
        return "ap"

    # Switch before gateway. Normal switches often advertise router capability.
    if SWITCH_HINTS.search(combined):
        return "switch"
    if re.search(r"(?i)\bswitch\b|procurve|aruba\s+2920|hpe?\s+\S+\s+switch|icx|catalyst|system capabilities.*bridge|capabilities.*bridge", combined):
        return "switch"

    # Gateway only on stronger evidence than generic "router" capability.
    if re.search(r"(?i)\b(firewall|watchguard|fortinet|fortigate|palo alto|sonicwall|nomadix)\b", combined):
        return "gateway"
    if re.search(r"(?i)(^|[-_])(gw|fw|rtr)\d*($|[-_])", name_text):
        return "gateway"
    if re.search(r"(?i)\bgateway\b", combined) and not re.search(r"(?i)\bbridge\b", combined):
        return "gateway"

    return "unknown"

def normalize_port(port: str | None) -> str | None:
    if not port:
        return None
    p = port.strip()
    p = re.sub(r"^(ethernet|eth|gigabitethernet|gi|tengigabitethernet|te|fastethernet|fa)\s*", "", p, flags=re.I)
    p = p.replace(" ", "")
    return p


def same_port(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    aa, bb = normalize_port(a), normalize_port(b)
    if aa == bb:
        return True
    return (aa or "").lower().endswith((bb or "").lower()) or (bb or "").lower().endswith((aa or "").lower())


def parse_mac_hits(outputs: Dict[str, str], wanted_mac: str) -> List[Dict[str, Any]]:
    wanted = compact_mac(wanted_mac)
    hits: List[Dict[str, Any]] = []

    if not wanted or len(wanted) != 12:
        return hits

    f = mac_formats(wanted_mac)
    mac_variants = [f["compact"], f["dot"], f["colon"], f["dash6"]]

    mac_text = output_blob(outputs, ["mac", "fdb", "address table"])
    compact_output = compact_mac(mac_text)

    # ProCurve single-MAC lookup table format:
    # Status and Counters - Address Table - 48d6d5-3a5728
    # Port                            VLAN
    # B15                             1000
    if wanted in compact_output:
        lines = mac_text.splitlines()
        for idx, line in enumerate(lines):
            if re.search(r"\bPort\b", line, re.I) and re.search(r"\bVLAN\b", line, re.I):
                for row in lines[idx + 1: idx + 12]:
                    raw = row.strip()
                    if not raw or re.fullmatch(r"[-\s]+", raw) or raw.endswith("#") or raw.startswith("$"):
                        continue
                    parts = raw.split()
                    if len(parts) < 2:
                        continue
                    port, vlan = parts[0].strip(), parts[1].strip()
                    if re.fullmatch(r"([A-Z]\d{1,2}|\d{1,3}|Trk\d+|trk\d+|[A-Z]\d{1,2}-[A-Z]\d{1,2})", port, re.I) and re.fullmatch(r"\d{1,4}", vlan):
                        hits.append({"port": normalize_port(port), "vlan": vlan, "line": raw})
                        break
                if hits:
                    break

    # One-line MAC table format:
    # 48d6d5-3a5728     B15     1000
    # 829b.6d91.618b    1/2/1   Dynamic   1000
    for line in mac_text.splitlines():
        cline = compact_mac(line)
        if wanted not in cline:
            continue

        vlan = None
        port = parse_port_from_mac_line(line, mac_variants)

        # ProCurve filtered line: MAC PORT VLAN
        pc = re.search(r"(?i)\b[0-9a-f]{6}-[0-9a-f]{6}\b\s+[A-Z]?\d{1,3}\s+(\d{1,4})\b", line)
        if pc:
            vlan = pc.group(1)

        if not vlan:
            vlan_match = re.search(r"(?i)(?:vlan\s*[:=]?\s*|\bVLAN\s+)(\d{1,4})", line)
            if vlan_match:
                vlan = vlan_match.group(1)

        if not vlan:
            tail_vlan = re.search(r"(?i)\b(?:dynamic|static|learned|secure)\b\s+(\d{1,4})\s*$", line)
            if tail_vlan:
                vlan = tail_vlan.group(1)
            else:
                scrubbed = line
                for mv in mac_variants:
                    scrubbed = re.sub(re.escape(mv), " ", scrubbed, flags=re.I)
                if port:
                    scrubbed = re.sub(re.escape(str(port)), " ", scrubbed, flags=re.I)
                nums = re.findall(r"\b\d{1,4}\b", scrubbed)
                if nums:
                    vlan = nums[-1]

        if port:
            hits.append({"port": normalize_port(port), "vlan": vlan, "line": line.strip()})

    out: List[Dict[str, Any]] = []
    seen = set()
    for h in hits:
        key = (normalize_port(h.get("port")), h.get("vlan"), h.get("line"))
        if key not in seen:
            out.append(h)
            seen.add(key)
    return out

def parse_port_from_mac_line(line: str, mac_variants: List[str]) -> Optional[str]:
    """Extract likely port/interface from a MAC-table line."""
    # ProCurve filtered table: 48d6d5-3a5728   B15   1000
    pc = re.search(
        r"(?i)\b[0-9a-f]{6}-[0-9a-f]{6}\b\s+([A-Z]\d{1,2}|\d{1,3}|Trk\d+|trk\d+)\s+\d{1,4}\b",
        line,
    )
    if pc:
        return pc.group(1)

    scrubbed = line
    for mv in mac_variants:
        if mv:
            scrubbed = re.sub(re.escape(mv), " ", scrubbed, flags=re.I)

    tokens = scrubbed.replace(",", " ").split()

    for tok in tokens:
        t = tok.strip()
        if re.fullmatch(r"\d+/\d+(/\d+)?", t):
            return t
        if re.fullmatch(r"(Gi|Te|Fa|Eth|Po|Port-channel)\S+", t, re.I):
            return t
        if re.fullmatch(r"(Trk|trk|LAG|lag)\d+", t):
            return t
        if re.fullmatch(r"[A-Z]\d{1,2}", t, re.I):
            return t

    for tok in tokens:
        t = tok.strip()
        if re.fullmatch(r"\d{1,3}", t):
            return t

    return None

def parse_macs_on_port(outputs: Dict[str, str], port: str | None) -> List[str]:
    if not port:
        return []
    macs: List[str] = []
    mac_text = output_blob(outputs, ["mac", "fdb"])
    mac_re = re.compile(r"(?i)([0-9a-f]{4}[.:-][0-9a-f]{4}[.:-][0-9a-f]{4}|[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})")
    for line in mac_text.splitlines():
        if not same_port(port, line):
            continue
        for m in mac_re.findall(line):
            nm = norm_mac(m)
            if nm not in macs:
                macs.append(nm)
    return macs



def _extract_lldp_fallback_identity(outputs: Dict[str, str], port: str | None = None) -> Dict[str, Optional[str]]:
    """Extract LLDP neighbor identity from raw/detail/filter outputs.

    Handles:
      Address : 192.168.162.127
      SysName : PHXBD-AP003-16-Rm1604

    This is intentionally used as a safety net after the normal LLDP parser.
    """
    text = output_blob(outputs, ["lldp", "remote-device", "neighbor"])
    result: Dict[str, Optional[str]] = {"neighbor_ip": None, "neighbor_name": None}

    if not text:
        return result

    # SysName can appear in full detail or filtered short output.
    names = re.findall(r"(?im)^\s*SysName\s*:\s*(.+?)\s*$", text)
    if names:
        # Prefer the last parsed name because filtered command output may come after full detail.
        name = names[-1].strip()
        if name and not re.search(r"not advertised|none|unknown", name, re.I):
            result["neighbor_name"] = name

    # Prefer Address line under Remote Management Address block.
    block_match = re.search(
        r"(?is)Remote\s+Management\s+Address(?P<body>.*?)(?:\n\s*\n|Poe\s+Plus|[A-Za-z0-9_.-]+[#>])",
        text,
    )
    if block_match:
        ips = re.findall(r"(?im)^\s*Address\s*:\s*((?:\d{1,3}\.){3}\d{1,3})\s*$", block_match.group("body"))
        if ips:
            result["neighbor_ip"] = ips[-1]

    # Generic fallback for filtered outputs.
    if not result.get("neighbor_ip"):
        ips = re.findall(
            r"(?im)^\s*(?:Address|Management\s+Address|Mgmt\s+Address|IP\s+Address)\s*[:=]\s*((?:\d{1,3}\.){3}\d{1,3})\s*$",
            text,
        )
        if ips:
            result["neighbor_ip"] = ips[-1]

    if not result.get("neighbor_ip"):
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        if ips:
            result["neighbor_ip"] = ips[-1]

    return result

def parse_lldp_neighbors(outputs: Dict[str, str]) -> List[Dict[str, Any]]:
    """Parse LLDP detail/table outputs into normalized neighbor records.

    ProCurve detail output is treated as one block from Local Port to the next
    Local Port so blank lines before "Remote Management Address" do not cause
    us to lose Address/SysName.
    """
    text = output_blob(outputs, ["lldp", "remote-device", "neighbor"])
    neighbors: List[Dict[str, Any]] = []

    # Block parser for detail-style outputs.
    block_starts = [m.start() for m in re.finditer(r"(?im)^\s*Local\s+Port\s*:", text)]
    if block_starts:
        block_starts.append(len(text))
        for i in range(len(block_starts) - 1):
            block = text[block_starts[i]:block_starts[i + 1]]
            current: Dict[str, Any] = {}

            m = re.search(r"(?im)^\s*Local\s+Port\s*:\s*(\S+)\s*$", block)
            if m:
                current["local_port"] = normalize_port(m.group(1))

            m = re.search(r"(?im)^\s*SysName\s*:\s*(.+?)\s*$", block)
            if m:
                val = m.group(1).strip()
                if val and not re.search(r"not advertised|none|unknown", val, re.I):
                    current["neighbor_name"] = val

            m = re.search(r"(?im)^\s*(?:System\s+Descr|System\s+Description|Description)\s*:\s*(.+?)\s*$", block)
            if m:
                current["neighbor_description"] = m.group(1).strip().strip('"')

            m = re.search(r"(?im)^\s*PortDescr\s*:\s*(.+?)\s*$", block)
            if m:
                current["neighbor_port_description"] = m.group(1).strip()

            m = re.search(r"(?im)^\s*PortId\s*:\s*(.+?)\s*$", block)
            if m:
                val = m.group(1).strip()
                if looks_like_mac(val):
                    current["neighbor_port_mac"] = norm_mac(val)
                else:
                    current["neighbor_port"] = val

            m = re.search(r"(?im)^\s*ChassisId\s*:\s*(.+?)\s*$", block)
            if m:
                val = m.group(1).strip()
                if looks_like_mac(val):
                    current["neighbor_chassis_mac"] = norm_mac(val)
                    current.setdefault("neighbor_mac", norm_mac(val))

            # Prefer Address under Remote Management Address, but accept any Address line.
            mgmt_block = re.search(r"(?is)Remote\s+Management\s+Address(?P<body>.*?)(?:\n\s*\n|Poe\s+Plus|[A-Za-z0-9_.-]+[#>])", block)
            if mgmt_block:
                ips = re.findall(r"(?im)^\s*Address\s*:\s*((?:\d{1,3}\.){3}\d{1,3})\s*$", mgmt_block.group("body"))
                if ips:
                    current["neighbor_ip"] = ips[-1]
            if not current.get("neighbor_ip"):
                ips = re.findall(r"(?im)^\s*(?:Address|Management\s+Address|Mgmt\s+Address|IP\s+Address)\s*[:=]\s*((?:\d{1,3}\.){3}\d{1,3})\s*$", block)
                if ips:
                    current["neighbor_ip"] = ips[-1]

            caps = re.findall(r"(?im)^\s*System\s+Capabilities.*?:\s*(.+?)\s*$", block)
            if caps:
                current["capabilities"] = caps

            if current.get("local_port"):
                cap_text = " ".join(current.get("capabilities") or [])
                current["neighbor_type"] = classify_neighbor(
                    current.get("neighbor_name"),
                    current.get("neighbor_ip"),
                    f"{current.get('neighbor_description') or ''} {cap_text}",
                )
                neighbors.append(current)

    # Fallback parser for non-ProCurve line-based detail.
    current: Dict[str, Any] = {}
    in_remote_management = False
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue

        if re.search(r"(?i)^remote management address", s):
            in_remote_management = True
            continue

        m = re.search(r"(?i)(?:local\s+(?:port|interface|intf)|port)\s*[:=]\s*(\S+)", s)
        if m:
            if current.get("local_port"):
                neighbors.append(current)
            current = {"local_port": normalize_port(m.group(1))}
            in_remote_management = False
            continue

        if not current.get("local_port"):
            continue

        m = re.search(r"(?i)(?:sysname|system\s+name|chassis\s+name|device\s+id|remote\s+system)\s*[:=]\s*(.+)", s)
        if m and not current.get("neighbor_name"):
            current["neighbor_name"] = m.group(1).strip()
            continue

        m = re.search(r"(?i)(?:system\s+description|system\s+descr|description)\s*[:=]\s*(.+)", s)
        if m and not current.get("neighbor_description"):
            current["neighbor_description"] = m.group(1).strip().strip('"')
            continue

        m = re.search(r"(?i)(?:management\s+address|mgmt\s+address|ip\s+address|address)(?:\s*\([^)]*\))?\s*[:=]\s*((?:\d{1,3}\.){3}\d{1,3})", s)
        if m and (in_remote_management or not current.get("neighbor_ip")):
            current["neighbor_ip"] = m.group(1)
            continue

    if current.get("local_port"):
        neighbors.append(current)

    # Table-style fallback.
    for line in text.splitlines():
        s = line.strip()
        if not s or (re.search(r"local|port|chassis|system|----", s, re.I) and not re.match(r"^\d|^[A-Z]\d", s)):
            continue
        parts = re.split(r"\s{2,}|\t+", s)
        if len(parts) >= 2:
            lp = normalize_port(parts[0])
            name = parts[1].strip()
            if lp and name and not any(same_port(lp, n.get("local_port")) and n.get("neighbor_name") == name for n in neighbors):
                neighbors.append({"local_port": lp, "neighbor_name": name, "neighbor_port": parts[2].strip() if len(parts) > 2 else None})

    # Fallback identity from filtered commands:
    #   sh lldp inf rem <port> | i Address
    #   sh lldp inf rem <port> | inc Name
    fallback_ips = re.findall(r"(?im)^\s*(?:Address|Management\s+Address|Mgmt\s+Address|IP\s+Address)\s*[:=]\s*((?:\d{1,3}\.){3}\d{1,3})\s*$", text)
    fallback_names = re.findall(r"(?im)^\s*SysName\s*:\s*(.+?)\s*$", text)
    if neighbors:
        if fallback_ips:
            for n in neighbors:
                if not n.get("neighbor_ip"):
                    n["neighbor_ip"] = fallback_ips[-1]
                    break
        if fallback_names:
            for n in neighbors:
                if not n.get("neighbor_name"):
                    n["neighbor_name"] = fallback_names[-1].strip()
                    break



    # ProCurve rich fast identity command fallback:
    #   sh lldp inf rem 22 | i SysName / Desc / Add
    # Output includes SysName, System Descr, PortDescr, and Address but not Local Port,
    # so derive local_port from the command key.
    for cmd_text, out_text in outputs.items():
        cmd_s = str(cmd_text)
        out_s = str(out_text)

        if not re.search(r"(?i)\blldp\b.*\b(?:inf|info)\b.*\brem(?:ote-device)?\b", cmd_s):
            continue

        port_match = re.search(r"(?i)\brem(?:ote-device)?\s+(\S+)", cmd_s)
        if not port_match:
            continue

        lp = normalize_port(port_match.group(1))
        if not lp:
            continue

        name_match = re.search(r"(?im)^\s*SysName\s*:\s*(.+?)\s*$", out_s)
        desc_match = re.search(r"(?im)^\s*(?:System\s+Descr|System\s+Description|Description)\s*:\s*(.+?)\s*$", out_s)
        portdesc_match = re.search(r"(?im)^\s*PortDescr\s*:\s*(.+?)\s*$", out_s)
        ip_matches = re.findall(r"(?im)^\s*(?:Address|Management\s+Address|Mgmt\s+Address|IP\s+Address)\s*[:=]\s*((?:\d{1,3}\.){3}\d{1,3})\s*$", out_s)

        if not (name_match or desc_match or portdesc_match or ip_matches):
            continue

        existing = None
        for n in neighbors:
            if same_port(lp, n.get("local_port")):
                existing = n
                break

        if existing is None:
            existing = {"local_port": lp}
            neighbors.append(existing)

        if name_match and not existing.get("neighbor_name"):
            existing["neighbor_name"] = name_match.group(1).strip()

        if desc_match and not existing.get("neighbor_description"):
            existing["neighbor_description"] = desc_match.group(1).strip().strip('"')

        if portdesc_match and not existing.get("neighbor_port_description"):
            existing["neighbor_port_description"] = portdesc_match.group(1).strip()

        if ip_matches and not existing.get("neighbor_ip"):
            existing["neighbor_ip"] = ip_matches[-1]



    # Ruckus ICX fast LLDP filtered command fallback:
    #   show lldp neighbor detail port eth 1/3/2 | include name|add|desc
    # Output can include:
    #   + System name: HS015296SW01-MDataCent
    #   + Port description: "10GigabitEthernet2/1/2"
    #   + System description: "Ruckus Wireless, Inc. Stacking System ..."
    #   + Management address (IPv4): 192.168.250.242
    # It may not include a local port line after filtering, so derive the local
    # port from the command key.
    for cmd_text, out_text in outputs.items():
        cmd_s = str(cmd_text)
        out_s = str(out_text)

        if not re.search(r"(?i)\blldp\b.*neighbor.*detail.*port", cmd_s):
            continue

        port_match = re.search(r"(?i)\bport\s+(?:eth(?:ernet)?\s+)?(\S+)", cmd_s)
        if not port_match:
            continue

        lp = normalize_port(port_match.group(1))
        if not lp:
            continue

        name_match = re.search(r"(?im)^\s*\+?\s*System\s+name\s*:\s*(.+?)\s*$", out_s)
        desc_match = re.search(r"(?im)^\s*\+?\s*System\s+description\s*:\s*(.+?)\s*$", out_s)
        portdesc_match = re.search(r"(?im)^\s*\+?\s*Port\s+description\s*:\s*\"?(.+?)\"?\s*$", out_s)
        ip_matches = re.findall(r"(?im)^\s*\+?\s*Management\s+address(?:\s*\([^)]*\))?\s*:\s*((?:\d{1,3}\.){3}\d{1,3})\s*$", out_s)

        if not (name_match or desc_match or portdesc_match or ip_matches):
            continue

        existing = None
        for n in neighbors:
            if same_port(lp, n.get("local_port")):
                existing = n
                break

        if existing is None:
            existing = {"local_port": lp}
            neighbors.append(existing)

        if name_match and not existing.get("neighbor_name"):
            existing["neighbor_name"] = name_match.group(1).strip().strip('"')

        if desc_match and not existing.get("neighbor_description"):
            existing["neighbor_description"] = desc_match.group(1).strip().strip('"')

        if portdesc_match and not existing.get("neighbor_port_description"):
            existing["neighbor_port_description"] = portdesc_match.group(1).strip().strip('"')

        if ip_matches and not existing.get("neighbor_ip"):
            existing["neighbor_ip"] = ip_matches[-1]

    # Dedupe and classify.
    out: List[Dict[str, Any]] = []
    seen = set()
    for n in neighbors:
        if not n.get("local_port"):
            continue
        n["local_port"] = normalize_port(n.get("local_port"))
        cap_text = " ".join(n.get("capabilities") or [])
        model_info = enrich_from_text(f"{n.get('neighbor_description') or ''} {n.get('neighbor_name') or ''}", source="mac_trace:lldp")
        if model_info:
            n["model_info"] = model_info
            n.setdefault("neighbor_model", model_info.get("model"))

        n["neighbor_type"] = classify_neighbor(
            n.get("neighbor_name"),
            n.get("neighbor_ip"),
            f"{n.get('neighbor_description') or ''} {cap_text}",
        )
        key = (n.get("local_port"), n.get("neighbor_name"), n.get("neighbor_ip"), n.get("neighbor_description"))
        if key not in seen:
            out.append(n)
            seen.add(key)

    return out

def neighbor_on_port(neighbors: List[Dict[str, Any]], port: str | None) -> Optional[Dict[str, Any]]:
    for n in neighbors:
        if same_port(n.get("local_port"), port):
            return n
    return None


def _is_useful_command_output(text: str) -> bool:
    """Return True when command output appears to contain real device data."""
    if not text:
        return False
    cleaned = []
    for line in str(text).splitlines():
        ln = line.strip()
        if not ln:
            continue
        if re.search(r"(?i)^(invalid input|type \?|syntax error|unknown command|incomplete command|ambiguous command|% invalid|error:)", ln):
            continue
        if re.search(r"(?m)[>#]\s*$", ln) and len(ln) < 80:
            continue
        cleaned.append(ln)
    return bool(cleaned)


def _extract_port_health_text(outputs: Dict[str, str], port: str | None) -> Tuple[str, str, List[str]]:
    """Split interface/counter text from filtered log text.

    Targeted commands like ``show int eth 1/1/41`` usually return a full block
    where only the first line contains the port.  The earlier parser threw most
    of that away by keeping only lines that contained the port number, which is
    why speed/duplex stayed unknown.  This keeps full output for commands that
    were targeted at the learned port, but still only pulls matching rows from
    broad table commands.
    """
    p = normalize_port(port) or ""
    interface_blocks: List[str] = []
    log_blocks: List[str] = []
    attempted: List[str] = []

    for cmd, output in outputs.items():
        c = (cmd or "").lower()
        text = output or ""
        if not text:
            continue

        is_log = any(k in c for k in [" log", "logging", "events"])
        is_port_targeted = bool(p and same_port(p, cmd))
        is_interfaceish = any(k in c for k in ["interface", "interfaces", "statistics", "counters", "status", "brief", "inline power", "power-over-ethernet", "power inline", "poe"])

        if is_log:
            attempted.append(cmd)
            # These commands are already filtered with include/match.  Keep the
            # useful output so we can say whether anything matched.
            if _is_useful_command_output(text):
                log_blocks.append(f"\n### {cmd}\n{text}")
            continue

        if is_interfaceish:
            if is_port_targeted:
                interface_blocks.append(f"\n### {cmd}\n{text}")
            else:
                # Broad status/brief fallback. Keep rows that mention the port.
                rows = [ln for ln in text.splitlines() if same_port(p, ln)]
                if rows:
                    interface_blocks.append(f"\n### {cmd}\n" + "\n".join(rows))

    return "\n".join(interface_blocks), "\n".join(log_blocks), attempted


def _parse_speed_duplex_from_text(text: str) -> Tuple[str, str]:
    speed = "unknown"
    duplex = "unknown"

    speed_patterns = [
        r"(?i)\b(?:actual|oper(?:ational)?|current)?\s*speed\s*[:=]?\s*(40g|40000|25g|25000|10g|10000|5g|5000|2\.5g|2500|1g|1000|100m|100|10m|10)\b",
        r"(?i)\b(40g|40000|25g|25000|10g|10000|5g|5000|2\.5g|2500|1g|1000|100m|100|10m|10)\s*(?:mbps|m|g|gbps)?\b",
    ]
    for pat in speed_patterns:
        m = re.search(pat, text)
        if m:
            raw = m.group(1).lower()
            speed = (raw.replace("40000", "40g")
                        .replace("25000", "25g")
                        .replace("10000", "10g")
                        .replace("5000", "5g")
                        .replace("2500", "2.5g")
                        .replace("1000", "1g")
                        .replace("100m", "100m")
                        .replace("10m", "10m"))
            if speed == "100": speed = "100m"
            if speed == "10": speed = "10m"
            break

    if re.search(r"(?i)\bfull[- ]?duplex\b|\bduplex\s*[:=]?\s*full\b|\bfull\b", text):
        duplex = "full"
    elif re.search(r"(?i)\bhalf[- ]?duplex\b|\bduplex\s*[:=]?\s*half\b|\bhalf\b", text):
        duplex = "half"

    return speed, duplex



def parse_filtered_port_log(outputs: Dict[str, str], port: str | None) -> Dict[str, Any]:
    """Parse targeted/filtered port logs.

    Empty filtered output is OK, not an error.
    """
    if not port:
        return {
            "log_summary": "not checked",
            "log_severity": "info",
            "log_entries": 0,
            "log_notes": [],
        }

    text = output_blob(outputs, ["log", "logging", "event"])
    port_text = str(port).strip()

    if not text.strip():
        return {
            "log_summary": "checked; no relevant port log entries found",
            "log_severity": "ok",
            "log_entries": 0,
            "log_notes": [],
        }

    meaningful: List[str] = []
    prompt_re = re.compile(r"^[A-Za-z0-9_.-]+[#>]\s*$")

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if prompt_re.match(line):
            continue
        if line.startswith("$"):
            continue

        low = line.lower()

        # Skip command echo.
        if "show log" in low or "show logging" in low or "sh log" in low:
            continue

        # Keep lines that mention the specific port.
        if re.search(rf"(?i)(?:port\s+{re.escape(port_text)}\b|{re.escape(port_text)}[-\s])", line):
            meaningful.append(line)

    if not meaningful:
        return {
            "log_summary": "checked; no relevant port log entries found",
            "log_severity": "ok",
            "log_entries": 0,
            "log_notes": [],
        }

    stp_count = sum(1 for line in meaningful if re.search(r"blocked by stp|stp", line, re.I))
    offline_count = sum(1 for line in meaningful if re.search(r"off-?line|down", line, re.I))
    online_count = sum(1 for line in meaningful if re.search(r"on-?line|up", line, re.I))
    transition_count = sum(1 for line in meaningful if re.search(r"excessive link state transitions|link state transition|flap", line, re.I))
    error_count = sum(1 for line in meaningful if re.search(r"error|fault|failure|failed|excessive|blocked", line, re.I))

    notes: List[str] = []
    if stp_count:
        notes.append(f"STP blocking events found: {stp_count}")
    if offline_count or online_count:
        notes.append(f"Link state changes found: offline={offline_count}, online={online_count}")
    if transition_count:
        notes.append(f"Excessive link transition indicators found: {transition_count}")
    if error_count and not notes:
        notes.append(f"Relevant warning/error log entries found: {error_count}")

    if transition_count or offline_count >= 3 or stp_count >= 5:
        severity = "warning"
    elif error_count:
        severity = "warning"
    else:
        severity = "info"

    return {
        "log_summary": "; ".join(notes) if notes else f"checked; {len(meaningful)} relevant entries found",
        "log_severity": severity,
        "log_entries": len(meaningful),
        "log_notes": notes,
        "log_sample": meaningful[:8],
    }

def parse_ap_power(outputs: Dict[str, str], port: str | None) -> Dict[str, Any]:
    """Parse lightweight AP-facing PoE details."""
    if not port:
        return {}
    text = output_blob(outputs, ["power-over-ethernet", "inline power", "power inline"])
    if not text:
        return {}

    result: Dict[str, Any] = {}
    p = re.escape(str(port))

    m = re.search(rf"(?im)^\s*{p}\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+([\d.]+\s*W)\s+([\d.]+\s*W)\s+([A-Za-z/-]+)\s+(\d+)?", text)
    if m:
        result["poe_reserved"] = m.group(1).strip()
        result["poe_draw"] = m.group(2).strip()
        result["poe_state"] = m.group(3).strip()
        if m.group(4):
            result["poe_class"] = m.group(4).strip()
        result["poe"] = f"{result.get('poe_state')} / {result.get('poe_draw')}"
        return result

    if re.search(r"(?i)deliver|on|power", text):
        result["poe"] = "present"
    return result



def _parse_procurve_custom_speed(outputs: Dict[str, str], port: str | None) -> Dict[str, str]:
    """Parse ProCurve 'show interfaces custom <port> speed' output.

    Example:
      PHXBDSW01-1-MDF# sh int custom b15 speed | i 1
        1000FDx

    This is preferred over brief-table parsing when present because it avoids
    accidentally reading the port number or Type column as speed.
    """
    text = output_blob(outputs, ["custom", "speed"])
    if not text:
        return {}

    # Skip echoed commands, prompts, and invalid-input lines.
    candidates: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if "sh int" in low or "show int" in low or "custom" in low:
            continue
        if "invalid input" in low or "usage error" in low:
            continue
        if re.search(r"[#>]\s*$", line):
            continue
        candidates.append(line)

    joined = "\n".join(candidates)
    mode_match = re.search(r"(?i)\b(10|100|1000|10000)\s*(F|H)?D?x\b|\b(10G|1G|100M|10M)\b", joined)
    if not mode_match:
        return {}

    token = mode_match.group(0).strip().lower().replace(" ", "")
    result: Dict[str, str] = {}

    if token in {"1000fdx", "1g", "1gbit"}:
        result["speed"] = "1gbit"
        result["duplex"] = "full" if token == "1000fdx" else "unknown"
    elif token == "1000hdx":
        result["speed"] = "1gbit"
        result["duplex"] = "half"
    elif token in {"100fdx", "100m"}:
        result["speed"] = "100m"
        result["duplex"] = "full" if token == "100fdx" else "unknown"
    elif token == "100hdx":
        result["speed"] = "100m"
        result["duplex"] = "half"
    elif token in {"10fdx", "10m"}:
        result["speed"] = "10m"
        result["duplex"] = "full" if token == "10fdx" else "unknown"
    elif token == "10hdx":
        result["speed"] = "10m"
        result["duplex"] = "half"
    elif token in {"10000fdx", "10g"}:
        result["speed"] = "10gbit"
        result["duplex"] = "full" if token == "10000fdx" else "unknown"
    elif token == "10000hdx":
        result["speed"] = "10gbit"
        result["duplex"] = "half"

    return result

def _parse_procurve_interface_brief_mode(outputs: Dict[str, str], port: str | None) -> Dict[str, str]:
    """Strictly parse ProCurve 'show interfaces brief | include <port>' speed/duplex."""
    if not port:
        return {}

    text = output_blob(outputs, ["interfaces brief", "interface brief", "port status"])
    if not text:
        return {}

    wanted = str(port).strip().lower()

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        parts = line.split()
        if not parts or parts[0].strip().lower() != wanted:
            continue

        result: Dict[str, str] = {}
        status_idx = None
        for idx, token in enumerate(parts):
            if token.lower() in {"up", "down", "disabled"}:
                status_idx = idx
                break

        if status_idx is not None:
            result["link_state"] = parts[status_idx].lower()
            mode = parts[status_idx + 1] if status_idx + 1 < len(parts) else ""
        else:
            mode = parts[5] if len(parts) > 5 else ""
            if len(parts) > 4:
                result["link_state"] = parts[4].lower()

        mode_l = mode.strip().lower()

        if mode_l == "1000fdx":
            result["speed"] = "1gbit"
            result["duplex"] = "full"
        elif mode_l == "1000hdx":
            result["speed"] = "1gbit"
            result["duplex"] = "half"
        elif mode_l == "100fdx":
            result["speed"] = "100m"
            result["duplex"] = "full"
        elif mode_l == "100hdx":
            result["speed"] = "100m"
            result["duplex"] = "half"
        elif mode_l == "10fdx":
            result["speed"] = "10m"
            result["duplex"] = "full"
        elif mode_l == "10hdx":
            result["speed"] = "10m"
            result["duplex"] = "half"
        elif "auto" in mode_l:
            result["speed"] = "unknown"
            result["duplex"] = "auto"
        elif mode:
            result["mode_raw"] = mode

        return result

    return {}

def parse_port_health(outputs: Dict[str, str], port: str | None) -> Dict[str, Any]:
    status = "unknown"
    speed = "unknown"
    duplex = "unknown"
    poe = "unknown"
    notes: List[str] = []
    counters: Dict[str, int] = {}
    log_summary = "not checked"

    if not port:
        return {"status": status, "speed_duplex": "unknown", "poe": poe, "notes": notes, "severity": "info", "counters": counters, "log_summary": log_summary}

    iface_text, logs, log_attempts = _extract_port_health_text(outputs, port)
    health_text = iface_text or output_blob(outputs, ["interface", "interfaces", "statistics", "counters", "status", "brief"])

    # Link/admin status.  Prefer clear operational phrases over generic words.
    if re.search(r"(?i)(?:line protocol is|link status|oper(?:ational)? status|admin state|port state|state)\s*(?:is|:)?\s*up\b|\bconnected\b|\blink-up\b", health_text):
        status = "up"
    if re.search(r"(?i)(?:line protocol is|link status|oper(?:ational)? status|admin state|port state|state)\s*(?:is|:)?\s*(?:down|disabled)\b|\bnotconnect\b|\berr-disabled\b|\blink-down\b", health_text):
        # Down/disabled should override if explicitly present.
        status = "down"
    if re.search(r"(?i)\bis up,\s*line protocol is up\b|\bport is up\b", health_text):
        status = "up"

    speed, duplex = _parse_speed_duplex_from_text(health_text)

    # Common error/counter phrasings across Ruckus, Aruba CX/ProCurve, Cisco and TP-Link.
    counter_patterns = {
        "crc": [r"(?i)\bcrc\s*(?:errors?)?\s*[:=]?\s*(\d+)", r"(?i)\bfcs\s*(?:errors?)?\s*[:=]?\s*(\d+)"],
        "input_errors": [r"(?i)\binput errors?\s*[:=]?\s*(\d+)", r"(?i)\brx errors?\s*[:=]?\s*(\d+)", r"(?i)\breceive errors?\s*[:=]?\s*(\d+)"],
        "output_errors": [r"(?i)\boutput errors?\s*[:=]?\s*(\d+)", r"(?i)\btx errors?\s*[:=]?\s*(\d+)", r"(?i)\btransmit errors?\s*[:=]?\s*(\d+)"],
        "drops": [r"(?i)\bdrops?\s*[:=]?\s*(\d+)", r"(?i)\bdropped\s*[:=]?\s*(\d+)", r"(?i)\bdiscards?\s*[:=]?\s*(\d+)"],
        "collisions": [r"(?i)\bcollisions?\s*[:=]?\s*(\d+)", r"(?i)\blate collisions?\s*[:=]?\s*(\d+)"],
        "giants": [r"(?i)\bgiants?\s*[:=]?\s*(\d+)", r"(?i)\bjabbers?\s*[:=]?\s*(\d+)"],
        "runts": [r"(?i)\brunts?\s*[:=]?\s*(\d+)", r"(?i)\bfragments?\s*[:=]?\s*(\d+)"],
    }
    for name, pats in counter_patterns.items():
        total = 0
        for pat in pats:
            for m in re.finditer(pat, health_text):
                try:
                    total += int(m.group(1))
                except Exception:
                    pass
        if total:
            counters[name] = total

    if counters.get("crc"):
        notes.append(f"CRC/FCS errors detected ({counters['crc']})")
    if counters.get("input_errors"):
        notes.append(f"Input/RX errors detected ({counters['input_errors']})")
    if counters.get("output_errors"):
        notes.append(f"Output/TX errors detected ({counters['output_errors']})")
    if counters.get("drops"):
        notes.append(f"Drops/discards detected ({counters['drops']})")
    if counters.get("collisions"):
        notes.append(f"Collisions detected ({counters['collisions']})")
    if counters.get("giants") or counters.get("runts"):
        notes.append("Frame size errors detected")

    # Filtered logs: explicitly tell the user whether the port filter found anything.
    relevant_log_lines: List[str] = []
    if log_attempts:
        for ln in logs.splitlines():
            clean = ln.strip()
            if not clean or clean.startswith("###"):
                continue
            if re.search(r"(?i)invalid input|unknown command|type \?|syntax error", clean):
                continue
            if re.search(r"(?i)flap|link.*down|link.*up|down|up|error|err|crc|collision|fault|blocked|stp|loop|storm|disabled", clean):
                relevant_log_lines.append(clean)
        if relevant_log_lines:
            log_summary = f"matched {len(relevant_log_lines)} relevant line(s)"
            notes.append(f"Recent port log indicators found ({min(len(relevant_log_lines), 99)} matching lines)")
        else:
            log_summary = "checked; no relevant port log entries found"
            notes.append("Filtered logs checked: no relevant port entries found")

    if duplex == "half":
        notes.append("Half-duplex detected")
    if speed in ("10m", "10", "100m", "100"):
        notes.append("Port is below 1G")

    poe_text = output_blob(outputs, ["inline power", "power-over-ethernet", "poe", "power inline"])
    for line in poe_text.splitlines():
        if same_port(port, line) or (port and port in line):
            if re.search(r"(?i)fault|denied|overload|short|off|disabled", line):
                poe = "warning"
            elif re.search(r"(?i)on|delivering|class|watts|mw|power|present|enable", line):
                poe = "present/active"
            break

    if status == "unknown" and not _is_useful_command_output(health_text):
        notes.append("Port detail commands returned no parseable interface data")

    if not counters:
        counters = {}

    severity = "warning" if any(not n.lower().startswith("filtered logs checked") for n in notes) else "ok"
    if counters.get("crc", 0) > 100 or counters.get("input_errors", 0) > 100 or counters.get("output_errors", 0) > 100:
        severity = "critical"
    return {"status": status, "speed_duplex": f"{speed} {duplex}".strip(), "poe": poe, "notes": notes or ["No immediate indicators"], "severity": severity, "counters": counters, "log_summary": log_summary}

def resolve_neighbor_ip(name: str | None) -> Optional[str]:
    if not name:
        return None
    try:
        ip = socket.gethostbyname(name)
        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip):
            return ip
    except Exception:
        return None
    return None


def choose_hit(hits: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not hits:
        return None
    # Prefer non-CPU physical-looking ports.
    for h in hits:
        p = h.get("port") or ""
        if re.search(r"\d", p) and not re.search(r"cpu|router|drop", p, re.I):
            return h
    return hits[0]



SENSITIVE_TEXT = "[REDACTED]"
TESTING_UNREDACTED_DEBUG = False

def _redact_runtime_text(value: Any, extra_secrets: Optional[List[str]] = None) -> str:
    """Redact passwords/secrets from UI events, debug output, raw JSON, and errors."""
    if value is None:
        return ""
    text = str(value)
    secrets = [x for x in (extra_secrets or []) if x]
    for secret in secrets:
        text = text.replace(str(secret), SENSITIVE_TEXT)

    # Common interactive/debug forms. Keep prompts and context, hide values.
    text = re.sub(r"(?im)^(\s*(?:password|passphrase|secret|snmp\s*community)\s*[:=]\s*).*$", r"\1" + SENSITIVE_TEXT, text)
    text = re.sub(r"(?i)(password\s+)(\S+)", r"\1" + SENSITIVE_TEXT, text)
    text = re.sub(r"(?i)(snmp-server\s+community\s+)(\S+)", r"\1" + SENSITIVE_TEXT, text)
    text = re.sub(r"(?i)(community\s+)([\"']?)([^\s\"']+)([\"']?)", r"\1\2" + SENSITIVE_TEXT + r"\4", text)
    return text

def _redact_obj_runtime(obj: Any, extra_secrets: Optional[List[str]] = None) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if re.search(r"password|secret|token|community|credential", str(k), re.I):
                out[k] = SENSITIVE_TEXT
            else:
                out[k] = _redact_obj_runtime(v, extra_secrets)
        return out
    if isinstance(obj, list):
        return [_redact_obj_runtime(v, extra_secrets) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_redact_obj_runtime(v, extra_secrets) for v in obj)
    if isinstance(obj, str):
        return _redact_runtime_text(obj, extra_secrets)
    return obj

def _event(events: List[Dict[str, Any]], level: str, message: str, host: str | None = None, command: str | None = None) -> None:
    events.append({
        "time": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "level": level,
        "host": _redact_runtime_text(host),
        "command": _redact_runtime_text(command),
        "message": _redact_runtime_text(message),
    })


def _vendor_first_mac_lookup_commands(vendor: str, mac: str) -> List[str]:
    return get_mac_trace_lookup_commands(vendor, mac)

def _run_mac_lookup_on_open_shell(shell, opts: SSHOptions, mac: str, events: List[Dict[str, Any]], host: str) -> Tuple[Any, Dict[str, str], str, str]:
    detection_output = _run_detection(shell, opts, lambda m: _event(events, "debug", m, host))
    detection = detect_vendor(detection_output)
    vendor_obj = detection.vendor
    vendor = vendor_obj.value if hasattr(vendor_obj, "value") else str(vendor_obj)
    hostname = detection.hostname or host

    _event(events, "info", f"Detected {vendor} on {hostname}", host)

    for pager_cmd in get_paging_disable_commands(vendor_obj):
        _event(events, "command", pager_cmd, host, pager_cmd)
        _send_command(shell, pager_cmd, opts, lambda m: _event(events, "debug", m, host), tolerate_errors=True)

    commands = _vendor_first_mac_lookup_commands(vendor, mac)

    outputs: Dict[str, str] = {}
    for command in commands:
        _event(events, "command", command, host, command)
        try:
            outputs[command] = _send_command(shell, command, opts, lambda m: _event(events, "debug", m, host), tolerate_errors=True)
        except Exception as exc:
            outputs[command] = ""
            _event(events, "warning", f"Command failed: {command}: {exc}", host, command)

    return detection, outputs, hostname, vendor

def _run_targeted_commands_on_open_shell(shell, opts: SSHOptions, commands: List[str], events: List[Dict[str, Any]], host: str) -> Dict[str, str]:
    """Run already-selected targeted commands without re-running vendor detection."""
    outputs: Dict[str, str] = {}
    for command in commands:
        _event(events, "command", command, host, command)
        try:
            outputs[command] = _send_command(shell, command, opts, lambda m: _event(events, "debug", m, host), tolerate_errors=True)
        except Exception as exc:
            outputs[command] = ""
            _event(events, "warning", f"Command failed: {command}: {exc}", host, command)
    return outputs

def _run_commands_on_open_shell(shell, opts: SSHOptions, commands: List[str], events: List[Dict[str, Any]], host: str) -> Tuple[Any, Dict[str, str], str, str]:
    """Run detection + commands on the current shell context.

    This is intentionally separate from scan_single_switch because MAC Trace must
    continue from switch to switch through the CLI session. Many customer/VPN
    paths can reach only the first switch directly; subsequent switch management
    IPs are reachable from the previous switch, not from the technician laptop.
    """
    detection_output = _run_detection(shell, opts, lambda m: _event(events, "debug", m, host))
    detection = detect_vendor(detection_output)
    vendor = detection.vendor
    hostname = detection.hostname or host
    _event(events, "info", f"Detected {vendor.value if hasattr(vendor, 'value') else vendor} on {hostname}", host)
    for pager_cmd in get_paging_disable_commands(vendor):
        _event(events, "command", pager_cmd, host, pager_cmd)
        _send_command(shell, pager_cmd, opts, lambda m: _event(events, "debug", m, host), tolerate_errors=True)
    outputs: Dict[str, str] = {}
    for command in commands:
        _event(events, "command", command, host, command)
        try:
            outputs[command] = _send_command(shell, command, opts, lambda m: _event(events, "debug", m, host), tolerate_errors=True)
        except Exception as exc:
            outputs[command] = ""
            _event(events, "warning", f"Command failed: {command}: {exc}", host, command)
    return detection, outputs, hostname, vendor.value if hasattr(vendor, "value") else str(vendor)


def _read_until_interactive(shell, opts: SSHOptions, keywords: List[str], timeout: int | None = None) -> str:
    import time
    end = time.time() + (timeout or opts.command_timeout)
    buf = b""
    lower_keywords = [k.lower() for k in keywords]
    while time.time() < end:
        if shell.recv_ready():
            chunk = shell.recv(65535)
            buf += chunk
            text = buf.decode(errors="ignore")
            low = text.lower()
            if any(k in low for k in lower_keywords):
                return text
            if re.search(r"(?m)([A-Za-z0-9_.()/: -]+[>#])\s*$", text[-500:]):
                return text
        else:
            time.sleep(0.03)
    return buf.decode(errors="ignore")


def _drain_shell(shell) -> None:
    """Clear any stale prompt/output before starting an interactive command."""
    import time
    end = time.time() + 0.8
    while time.time() < end:
        if shell.recv_ready():
            shell.recv(65535)
            end = time.time() + 0.15
        else:
            time.sleep(0.02)









def _read_for_prompt(shell, opts: SSHOptions, keywords: List[str], timeout: int | None = None, allow_cli_prompt: bool = False) -> str:
    """Read interactive SSH output until a keyword or CLI prompt is seen."""
    import time

    end = time.time() + (timeout or opts.command_timeout)
    buf = b""
    lower_keywords = [k.lower() for k in keywords]
    pressed_continue = False

    while time.time() < end:
        if shell.recv_ready():
            chunk = shell.recv(65535)
            buf += chunk
            raw_text = buf.decode(errors="ignore")
            clean_text = clean_terminal_text(raw_text)
            low = clean_text.lower()

            if "press any key to continue" in low and not pressed_continue:
                shell.send(" \n")
                pressed_continue = True
                time.sleep(0.2)
                continue

            if any(k in low for k in lower_keywords):
                return raw_text

            if allow_cli_prompt and has_network_prompt(clean_text):
                return raw_text
        else:
            time.sleep(0.03)

    return buf.decode(errors="ignore")

def _ssh_next_hop(shell, next_ip: str, username: str, password: str, opts: SSHOptions, events: List[Dict[str, Any]], from_host: str) -> bool:
    """SSH from the current switch CLI to the next switch using shared prompt settling.

    Handles:
    - username + password prompts
    - ProCurve password-only prompt: Enter user@host's password
    - host-key prompts
    - HPE/ProCurve banners and "Press any key to continue"
    - Ruckus slow outbound SSH helper behavior
    """
    import time

    def _clean_low(value: str) -> str:
        return clean_terminal_text(value).lower()

    _event(events, "info", f"Opening switch-to-switch SSH session to {next_ip}", from_host)
    _drain_shell(shell)

    shell.send(f"ssh {next_ip}\n")
    _event(events, "command", f"ssh {next_ip}", from_host, f"ssh {next_ip}")

    transcript = ""

    time.sleep(0.5)
    text = _read_for_prompt(
        shell,
        opts,
        [
            "yes/no",
            "continue connecting",
            "username",
            "login as",
            "user name",
            "user:",
            "login:",
            "password",
            "connection refused",
            "timed out",
            "no route",
            "unreachable",
            "outbound connection closed",
            "outbound connection failed",
        ],
        timeout=max(8, min(opts.command_timeout, 35)),
        allow_cli_prompt=False,
    )
    transcript += text
    low = _clean_low(transcript)

    if "yes/no" in low or "continue connecting" in low:
        _event(events, "info", "Accepting SSH host key prompt", from_host)
        shell.send("yes\n")
        time.sleep(0.4)
        text = _read_for_prompt(
            shell,
            opts,
            ["username", "login as", "user name", "user:", "login:", "password"],
            timeout=max(8, min(opts.command_timeout, 35)),
            allow_cli_prompt=False,
        )
        transcript += text
        low = _clean_low(transcript)

    early_failure_terms = ["connection refused", "timed out", "no route", "unreachable", "outbound connection closed", "outbound connection failed"]
    if any(term in low for term in early_failure_terms) and "password" not in low and not has_network_prompt(transcript):
        safe = clean_terminal_text(transcript).replace(password, "[REDACTED]")
        _event(events, "debug", f"Sanitized switch-to-switch SSH transcript for {next_ip}:\n{safe}", from_host)
        _event(events, "error", f"Switch-to-switch SSH to {next_ip} failed before authentication.", from_host)
        return False

    username_prompt = any(k in low for k in ["username", "login as", "user name", "user:", "login:"])
    password_prompt = "password" in low

    if username_prompt and not password_prompt:
        _event(events, "info", "Username prompt detected; sending username", from_host)
        time.sleep(0.2)
        _event(events, "command", username, from_host, username)
        shell.send(username + "\n")
        time.sleep(0.5)

        text = _read_for_prompt(
            shell,
            opts,
            ["password", "permission denied", "authentication failed", "failed", "refused", "timed out"],
            timeout=max(10, min(opts.command_timeout, 40)),
            allow_cli_prompt=False,
        )
        transcript += text
        low = _clean_low(transcript)
        password_prompt = "password" in low

    elif password_prompt:
        _event(events, "info", "Password prompt detected without requiring username; using carried SSH username if present", from_host)

    if password_prompt:
        _event(events, "info", "Password prompt detected; sending [REDACTED]", from_host)
        _event(events, "command", "[password REDACTED]", from_host, "[password REDACTED]")
        time.sleep(0.2)
        shell.send(password + "\n")
        time.sleep(0.6)

        text = _read_for_prompt(
            shell,
            opts,
            [
                "permission denied",
                "authentication failed",
                "user authentication failed",
                "failed",
                "refused",
                "timed out",
                "closed",
                "denied",
                "outbound connection closed",
                "outbound connection failed",
            ],
            timeout=max(15, min(opts.command_timeout, 60)),
            allow_cli_prompt=True,
        )
        transcript += text
        low = _clean_low(transcript)
    else:
        _event(events, "warning", f"Switch-to-switch SSH to {next_ip} did not present a password prompt.", from_host)

    safe = clean_terminal_text(transcript).replace(password, "[REDACTED]")
    _event(events, "debug", f"Sanitized switch-to-switch SSH transcript for {next_ip}:\n{safe}", from_host)

    # If a prompt appears anywhere in the cleaned transcript, login succeeded.
    prompt_seen = extract_network_prompt(transcript)
    if prompt_seen:
        settled_text, settled_prompt = settle_shell_prompt(shell, enters=1, pause=0.15, timeout=1.5)
        final_prompt = settled_prompt or prompt_seen
        _event(events, "info", f"Switch-to-switch SSH connected to {next_ip}; prompt {final_prompt} detected", next_ip)
        if settled_text:
            _event(events, "debug", f"Post-login settled prompt text:\n{settled_text[-800:]}", next_ip)
        return True

    # Last-chance settle before failure. This catches prompts that appear after
    # banners, terminal status requests, or previous-login messages.
    settled_text, settled_prompt = settle_shell_prompt(shell, enters=2, pause=0.15, timeout=1.8)
    if settled_prompt:
        _event(events, "info", f"Switch-to-switch SSH connected to {next_ip}; prompt {settled_prompt} detected after post-login settle", next_ip)
        _event(events, "debug", f"Post-login settled prompt text:\n{settled_text[-800:]}", next_ip)
        return True

    bad_terms = ["permission denied", "authentication failed", "user authentication failed", "connection refused", "timed out", "no route", "unreachable", "outbound connection closed", "outbound connection failed"]
    if any(term in low for term in bad_terms):
        reason = "authentication failed" if re.search(r"authentication failed|permission denied|user authentication failed", low, re.I) else "connection failed"
        if re.search(r"timed out", low, re.I):
            reason = "timed out"
        elif re.search(r"refused", low, re.I):
            reason = "connection refused"
        elif re.search(r"no route|unreachable", low, re.I):
            reason = "unreachable"
        elif re.search(r"outbound connection closed|outbound connection failed", low, re.I):
            reason = "outbound connection failed"
        _event(events, "error", f"Switch-to-switch SSH to {next_ip} failed: {reason}.", from_host)
        return False

    _event(events, "error", f"Switch-to-switch SSH to {next_ip} did not reach a prompt.", from_host)
    return False

def trace_mac(start_switch: str, mac: str, username: str, password: str, max_hops: int, timeout: int, debug: bool, events_override: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    credentials = Credentials(username=username, password=password)
    options = SSHOptions(timeout=timeout, banner_timeout=timeout, auth_timeout=timeout, command_timeout=max(8, timeout), debug=debug, concurrency=1, old_kex=True)
    configure_logging(debug)
    events: List[Dict[str, Any]] = events_override if events_override is not None else []
    visited: set[str] = set()
    current = start_switch.strip()
    path: List[Dict[str, Any]] = []
    health_rows: List[Dict[str, Any]] = []
    raw: Dict[str, Any] = {}
    status = "not_found"; confidence = "low"; origin = "unknown"; summary = "MAC not found."
    final_device = None; final_switch = None; final_port = None; final_vlan = None; final_ap_mac = None; final_ap_ip = None
    client = None
    shell = None

    try:
        _event(events, "info", f"Connecting from workstation to starting switch {current}", current)
        target = SwitchTarget(host=current)
        client = _connect(target, username, password, options)
        shell = client.invoke_shell(width=240, height=1000)
        _prime_shell(shell, options, lambda m: _event(events, "debug", m, current))

        for hop in range(1, max(1, max_hops) + 1):
            if current in visited:
                status = "loop_detected"; summary = f"Trace stopped because {current} was already visited."; break
            visited.add(current)
            _event(events, "info", f"Hop {hop}: searching for {norm_mac(mac)} on {current}", current)

            detection, outputs, hostname, vendor = _run_mac_lookup_on_open_shell(shell, options, mac, events, current)
            hits = parse_mac_hits(outputs, mac)
            hit = choose_hit(hits)
            if not hit:
                if debug:
                    raw[current] = {"mac_lookup_outputs": outputs}
                path.append({"hop": hop, "switch": current, "hostname": hostname, "vendor": vendor, "result": "mac_not_found"})
                status = "not_found"; summary = f"MAC {norm_mac(mac)} was not found on {hostname} ({current})."; final_switch = current; break

            port = normalize_port(hit.get("port")); vlan = hit.get("vlan")
            _event(events, "info", f"MAC found on {hostname} port {port} VLAN {vlan or 'unknown'}", current)

            _event(events, "info", f"Collecting LLDP and health details for port {port}", current)
            detail_outputs = _run_targeted_commands_on_open_shell(shell, options, build_port_detail_commands(vendor, port), events, current)
            combined_outputs = {**outputs, **detail_outputs}
            if debug:
                raw[current] = {"mac_lookup_outputs": outputs, "port_detail_outputs": detail_outputs}

            neighbors = parse_lldp_neighbors(combined_outputs)
            neighbor = neighbor_on_port(neighbors, port)
            macs_on_port = parse_macs_on_port(combined_outputs, port)
            health = parse_port_health(combined_outputs, port)
            health_rows.append({"switch": hostname or current, "ip": current, "port": port, "role": "learned/downlink", **health})
            path_row = {"hop": hop, "switch": current, "hostname": hostname, "vendor": vendor, "port": port, "vlan": vlan, "mac_count": len(macs_on_port), "neighbor": neighbor, "result": "continue"}
            path.append(path_row)
            final_switch, final_port, final_vlan = current, port, vlan

            if neighbor:
                n_name = neighbor.get("neighbor_name") or "LLDP neighbor"
                n_type = neighbor.get("neighbor_type") or classify_neighbor(n_name, neighbor.get("neighbor_ip"), neighbor.get("neighbor_description"))
                n_ip = neighbor.get("neighbor_ip") or resolve_neighbor_ip(n_name)
                path_row["neighbor_type"] = n_type; path_row["neighbor_ip"] = n_ip
                _event(events, "info", f"LLDP neighbor on {port}: {n_name} ({n_type}) {n_ip or ''}".strip(), current)
                if n_type == "ap":
                    power_cmds = get_mac_trace_ap_power_commands(vendor, port)
                    if power_cmds:
                        _event(events, "info", f"Collecting AP-facing PoE details for port {port}", current)
                        power_outputs = _run_targeted_commands_on_open_shell(shell, options, power_cmds, events, current)
                        if debug:
                            raw.setdefault(current, {}).setdefault("ap_power_outputs", {}).update(power_outputs)
                        combined_outputs.update(power_outputs)
                        power_info = parse_ap_power(power_outputs, port)
                        if power_info and health_rows:
                            health_rows[-1].update(power_info)

                    status = "found"; confidence = "high"; origin = "ap"; final_device = n_name; final_ap_mac = neighbor.get("neighbor_mac") or neighbor.get("neighbor_chassis_mac") or neighbor.get("neighbor_port_mac"); final_ap_ip = n_ip
                    ap_identity = f"{n_name}" + (f" ({n_ip})" if n_ip else "") + (f" MAC {final_ap_mac}" if final_ap_mac else "")
                    summary = f"MAC {norm_mac(mac)} appears to be behind AP {ap_identity}, connected to {hostname} ({current}) port {port} on VLAN {vlan or 'unknown'}."
                    break
                if n_type in ("switch", "unknown") and n_ip and n_ip not in visited:
                    if _ssh_next_hop(shell, n_ip, username, password, options, events, current):
                        current = n_ip
                        continue
                    status = "connect_failed"; confidence = "low"; origin = "unknown"
                    final_switch = n_ip
                    summary = f"Connected path stopped at {n_ip}: switch-to-switch SSH failed."
                    break
                if n_type in ("switch", "unknown") and not n_ip:
                    status = "needs_manual_next_hop"; confidence = "medium"; origin = "switch"
                    final_device = n_name
                    summary = f"MAC {norm_mac(mac)} continues through {n_name} on {hostname} port {port}, but no LLDP management IP was found for recursive switch-to-switch SSH."
                    break
                status = "found"; confidence = "medium"; origin = n_type; final_device = n_name
                summary = f"MAC {norm_mac(mac)} points to {n_type} {n_name} on {hostname} port {port}."
                break

            if len(macs_on_port) > 1:
                status = "likely_unmanaged_switch"; confidence = "medium"; origin = "unmanaged_switch"
                final_device = "Likely unmanaged switch"
                summary = f"MAC {norm_mac(mac)} was learned on {hostname} port {port} with {len(macs_on_port)} MAC addresses and no LLDP neighbor. This is likely an unmanaged switch or non-LLDP bridge."
                break
            status = "found"; confidence = "medium"; origin = "endpoint"; final_device = "Endpoint / no LLDP neighbor"
            summary = f"MAC {norm_mac(mac)} terminates on {hostname} port {port} with no LLDP neighbor."
            break
        else:
            status = "max_hops"; summary = f"Trace stopped after max hops ({max_hops})."
    except Exception as exc:
        status = "connect_failed"
        summary = f"Trace failed: {exc}"
        _event(events, "error", summary, current)
    finally:
        try:
            if client:
                client.close()
        except Exception:
            pass

    return {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "input": {"start_switch": start_switch, "mac": norm_mac(mac), "max_hops": max_hops},
        "summary": summary,
        "status": status,
        "confidence": confidence,
        "origin": origin,
        "final": {"device": final_device, "switch": final_switch, "port": final_port, "vlan": final_vlan, "ap_mac": final_ap_mac, "ap_ip": final_ap_ip},
        "path": path,
        "port_health": health_rows,
        "events": _redact_obj_runtime(events, [password]),
        "raw": _redact_obj_runtime(raw, [password]) if debug else {},
    }


def _run_trace_job(job_id: str, payload: Dict[str, Any]) -> None:
    with _TRACE_JOBS_LOCK:
        job = _TRACE_JOBS.get(job_id)
        if not job:
            return
        job["status"] = "running"
    events = job["events"]
    try:
        result = trace_mac(
            payload["start_switch"], payload["mac"], payload["username"], payload["password"],
            int(payload.get("max_hops", 8)), int(payload.get("timeout", 20)), bool(payload.get("debug", False)),
            events_override=events,
        )
        with _TRACE_JOBS_LOCK:
            job["status"] = "complete"
            job["result"] = result
    except Exception as exc:
        _event(events, "error", f"Trace job failed: {_redact_runtime_text(exc, [payload.get('password', '')])}")
        with _TRACE_JOBS_LOCK:
            job["status"] = "failed"
            job["error"] = _redact_runtime_text(str(exc), [payload.get("password", "")])


@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def mac_trace_home(request: Request):
    return templates.TemplateResponse("mac_trace.html", {"request": request, "trace": _LAST_TRACE})


@router.post("/trace/start")
async def mac_trace_start(
    start_switch: str = Form(...),
    mac: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    max_hops: int = Form(8),
    timeout: int = Form(20),
    debug: bool = Form(False),
):
    job_id = secrets.token_urlsafe(24)
    payload = {"start_switch": start_switch, "mac": mac, "username": username, "password": password, "max_hops": max_hops, "timeout": timeout, "debug": debug}
    with _TRACE_JOBS_LOCK:
        _TRACE_JOBS[job_id] = {"status": "queued", "events": [], "result": None, "error": None}
    t = threading.Thread(target=_run_trace_job, args=(job_id, payload), daemon=True)
    t.start()
    return JSONResponse({"job_id": job_id, "status": "queued"})


@router.get("/trace/status/{job_id}")
async def mac_trace_status(job_id: str):
    global _LAST_TRACE
    with _TRACE_JOBS_LOCK:
        job = _TRACE_JOBS.get(job_id)
        if not job:
            return JSONResponse({"status": "missing", "error": "Trace job not found."}, status_code=404)
        data = {"status": job.get("status"), "events": list(job.get("events") or []), "result": job.get("result"), "error": job.get("error")}
    if data.get("result"):
        _LAST_TRACE = data["result"]
    return JSONResponse(data)


@router.post("/trace")
async def mac_trace_api(
    start_switch: str = Form(...),
    mac: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    max_hops: int = Form(8),
    timeout: int = Form(20),
    debug: bool = Form(False),
):
    global _LAST_TRACE
    trace = trace_mac(start_switch, mac, username, password, max_hops, timeout, debug)
    _LAST_TRACE = trace
    return JSONResponse(trace)


@router.get("/export/json")
async def export_json():
    data = _LAST_TRACE or {"status": "empty", "message": "No MAC trace has been run yet."}
    return JSONResponse(data, headers={"Content-Disposition": "attachment; filename=mac_trace_result.json"})
