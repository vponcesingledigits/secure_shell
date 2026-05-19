from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

try:
    from shared.switchport_commands import COMMAND_PROFILES as SHARED_COMMANDS
    from shared.commands import get_port_rename_commands, get_paging_disable_commands
except Exception:  # pragma: no cover
    SHARED_COMMANDS = None
    get_port_rename_commands = None
    get_paging_disable_commands = None

try:
    from shared.switchport_lldp import parse_lldp_neighbors as shared_parse_lldp_neighbors
except Exception:  # pragma: no cover
    shared_parse_lldp_neighbors = None

try:
    import paramiko
except Exception:  # pragma: no cover
    paramiko = None

DEFAULT_SSH_PORT = 22
MAX_HOSTS = 2048
PROMPT_RE = re.compile(r"(?m)^[\s\*]*[A-Za-z0-9_.:/()\-]+(?:\.\d+)?\s*[>#]\s*$")
ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

VENDOR_LABELS = {
    "auto": "Auto Detect",
    "ruckus": "Ruckus ICX",
    "aruba_cx": "Aruba CX",
    "hp_procurve": "HP / Aruba ProCurve",
    "cisco_ios": "Cisco IOS / Catalyst",
    "tplink": "TP-Link Media Panel",
    "extreme_exos": "Extreme EXOS / Switch Engine",
    "unknown": "Unknown",
}

LOCAL_COMMANDS: dict[str, dict[str, list[str] | str]] = {
    "ruckus": {
        "detect": ["show version"],
        "ports": ["show interfaces brief wide", "show interfaces brief"],
        "names": ["show interfaces brief wide", "show running-config | include port-name"],
        "lldp": ["show lldp neighbors", "show lldp neighbors detail"],
    },
    "aruba_cx": {
        "detect": ["show version"],
        "ports": ["show interface brief"],
        "names": ["show interface brief", "show running-config interface"],
        "lldp": ["show lldp neighbor-info", "show lldp neighbor-info detail"],
    },
    "hp_procurve": {
        "detect": ["show system", "show version"],
        "ports": ["show interfaces brief", "show name"],
        "names": ["show name"],
        "lldp": ["show lldp info remote-device", "show lldp info remote-device detail"],
    },
    "cisco_ios": {
        "detect": ["show version"],
        "ports": ["show interface status", "show interfaces status"],
        "names": ["show interface status", "show running-config | include ^interface|description"],
        "lldp": ["show lldp neighbors", "show lldp neighbors detail"],
    },
    "tplink": {
        "detect": ["show system-info", "show version"],
        "ports": ["show interface status", "show interfaces status"],
        "names": ["show interface status", "show running-config | include description"],
        "lldp": ["show lldp neighbor-information", "show lldp neighbors", "show lldp neighbor-information detail"],
    },
    "extreme_exos": {
        "detect": ["show system"],
        "ports": ["show ports no-refresh"],
        "names": ["show ports description"],
        "lldp": ["show lldp neighbors", "show lldp neighbors detailed"],
    },
}

COMMANDS = SHARED_COMMANDS or LOCAL_COMMANDS

PORT_RE = re.compile(
    r"(?P<port>(?:Gi|Gig|GigabitEthernet|Te|Ten|TenGigabitEthernet|Fa|Eth|ethernet|Po|Port-channel)\s*\d+(?:/\d+){0,2}|\d+/\d+/\d+|\d+/\d+|\d+)",
    re.I,
)

@dataclass
class PortRow:
    switch_ip: str
    switch_name: str
    vendor: str
    local_port: str
    current_name: str = ""
    patch_panel_port: str = ""
    link_state: str = ""
    neighbor_hostname: str = ""
    neighbor_ip: str = ""
    neighbor_port: str = ""
    neighbor_type: str = "unknown"
    suggested_name: str = ""
    status: str = "no_change"
    reason: str = ""
    command_preview: list[str] = field(default_factory=list)
    raw_evidence: str = ""

@dataclass
class ScanResult:
    target: str
    port: int
    success: bool
    vendor: str = "unknown"
    hostname: str = ""
    error: str = ""
    rows: list[PortRow] = field(default_factory=list)
    raw_outputs: dict[str, str] = field(default_factory=dict)


def clean_output(text: str) -> str:
    text = ANSI_RE.sub("", text or "").replace("\r", "")
    lines: list[str] = []
    for raw in text.splitlines():
        line = re.sub(r"--\s*more\s*--.*", "", raw, flags=re.I)
        line = re.sub(r"Press any key to continue.*", "", line, flags=re.I)
        if line.strip():
            lines.append(line.rstrip())
    return "\n".join(lines).strip()


def parse_targets(raw_targets: str, default_port: int = DEFAULT_SSH_PORT) -> list[tuple[str, int]]:
    targets: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for token in re.split(r"[\n,]+", raw_targets or ""):
        token = token.strip()
        if not token:
            continue
        if "/" in token:
            net = ipaddress.ip_network(token, strict=False)
            for idx, ip in enumerate(net.hosts()):
                if idx >= MAX_HOSTS:
                    break
                item = (str(ip), default_port)
                if item not in seen:
                    targets.append(item); seen.add(item)
            continue
        host = token
        port = default_port
        if token.count(":") == 1 and re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", token):
            host, port_s = token.split(":", 1)
            port = int(port_s)
        socket.inet_aton(host)
        item = (host, port)
        if item not in seen:
            targets.append(item); seen.add(item)
    return targets


def detect_vendor(text: str) -> str:
    low = (text or "").lower()
    if "extremexos" in low or "extreme networks" in low or "switchengine" in low:
        return "extreme_exos"
    if "ruckus" in low or "fastiron" in low or "icx" in low:
        return "ruckus"
    if "arubaos-cx" in low or "service os version" in low or "aos-cx" in low:
        return "aruba_cx"
    if "procurve" in low or "arubaos-switch" in low or re.search(r"software revision\s*:\s*[a-z]{1,2}\.\d+", low):
        return "hp_procurve"
    if "cisco ios" in low or "cisco ios xe" in low or "catalyst" in low:
        return "cisco_ios"
    if "tp-link" in low or "tplink" in low or "jetstream" in low or "omada" in low:
        return "tplink"
    return "unknown"


def parse_hostname(text: str, fallback: str) -> str:
    patterns = [
        r"SysName\s*[:=]\s*([A-Za-z0-9_.:-]+)",
        r"System Name\s*[:=]\s*([A-Za-z0-9_.:-]+)",
        r"Switch\s+Name\s*[:=]\s*([A-Za-z0-9_.:-]+)",
        r"hostname\s+\"?([A-Za-z0-9_.:-]+)\"?",
        r"(?m)^\s*([A-Za-z0-9_.:-]+)#\s*$",
    ]
    for pat in patterns:
        m = re.search(pat, text or "", flags=re.I)
        if m:
            return m.group(1).strip()
    return fallback


def normalize_port(port: str) -> str:
    value = (port or "").strip().replace(" ", "")
    value = re.sub(r"^GigabitEthernet", "Gi", value, flags=re.I)
    value = re.sub(r"^TenGigabitEthernet", "Te", value, flags=re.I)
    value = re.sub(r"^ethernet", "Eth", value, flags=re.I)
    return value


def classify_neighbor(name: str, capabilities: str = "") -> str:
    blob = f"{name} {capabilities}".lower()
    if re.search(r"(^|[^a-z])ap\d*|wap|r510|r550|r650|r750|t350|h510|access point|wlan", blob):
        return "ap"
    if "gw" in blob or "gateway" in blob or "nomadix" in blob or "router" in blob:
        return "gateway"
    if "fw" in blob or "firewall" in blob or "watchguard" in blob or "fortinet" in blob:
        return "firewall"
    if "phone" in blob or "mitel" in blob or "poly" in blob or "voip" in blob:
        return "phone"
    if "sw" in blob or "switch" in blob or "idf" in blob or "mdf" in blob or "bridge" in blob:
        return "switch"
    return "unknown"


def sanitize_name(value: str, max_len: int = 63) -> str:
    value = (value or "").strip().strip('"')
    value = re.sub(r"\s+", "_", value)
    value = re.sub(r"[^A-Za-z0-9_.:\-/]+", "", value)
    return value[:max_len]


def suggested_port_name(neighbor: str, neighbor_type: str, neighbor_port: str = "") -> tuple[str, str]:
    """
    Topology Builder naming model:
    - If LLDP gives us a remote hostname/system-name, use that hostname directly.
    - Do not add SW_/AP_/GW_/FW_ prefixes in this module.
    - If no LLDP hostname is available, leave the suggested name blank.
      The UI still shows the current local port name separately so operators can decide.
    """
    n = sanitize_name(neighbor, 63)
    if not n:
        return "", "No LLDP remote hostname available."
    if neighbor_type == "switch":
        return n, "Switch-facing LLDP neighbor."
    if neighbor_type == "ap":
        return n, "Access point LLDP neighbor."
    if neighbor_type == "gateway":
        return n, "Gateway/Nomadix LLDP neighbor."
    if neighbor_type == "firewall":
        return n, "Firewall LLDP neighbor."
    if neighbor_type == "phone":
        return n, "Phone endpoint LLDP neighbor."
    return n, "LLDP remote hostname."


def is_real_switch_port(vendor: str, port: str, evidence_line: str = "") -> bool:
    """
    Reject parser noise while still allowing vendor-native port formats.
    This avoids rows like Ruckus CPU speed lines ("1000") and ASIC inventory lines
    showing up as fake switchports.
    """
    p = normalize_port(port)
    if not p:
        return False
    low = (evidence_line or "").lower()
    if any(token in low for token in ("processor", "asic", "boot", "serial", "memory", "temperature", "fan", "power supply")):
        return False
    if vendor == "ruckus":
        return bool(re.match(r"^\d+/\d+/\d+$", p))
    if vendor == "aruba_cx":
        return bool(re.match(r"^\d+/\d+/\d+$", p) or re.match(r"^(?:lag|vlan)\d+$", p, re.I))
    if vendor == "cisco_ios":
        return bool(re.match(r"^(?:Gi|Gig|GigabitEthernet|Te|Ten|TenGigabitEthernet|Fa|Eth|Ethernet|Po|Port-channel)\s*\d+(?:/\d+){0,2}$", p, re.I))
    if vendor == "tplink":
        return bool(re.match(r"^(?:Gi|GigabitEthernet|Eth|GE|TG)?\s*\d+(?:/\d+){0,2}$", p, re.I))
    if vendor in {"hp_procurve", "extreme_exos"}:
        if not re.match(r"^\d+(?:/\d+){0,2}$", p):
            return False
        first = int(p.split("/")[0])
        return 0 < first < 512
    return bool(re.match(r"^\d+/\d+/\d+$", p) or re.match(r"^[A-Za-z]+\s*\d", p))


def parse_port_rows(vendor: str, switch_ip: str, switch_name: str, outputs: dict[str, str]) -> list[PortRow]:
    ports: dict[str, PortRow] = {}
    port_text = "\n".join(outputs.get(k, "") for k in ("ports", "names"))
    for line in port_text.splitlines():
        m = PORT_RE.search(line)
        if not m:
            continue
        port = normalize_port(m.group("port"))
        if not is_real_switch_port(vendor, port, line):
            continue
        row = ports.setdefault(port, PortRow(switch_ip=switch_ip, switch_name=switch_name, vendor=vendor, local_port=port))
        row.raw_evidence = (row.raw_evidence + "\n" + line.strip()).strip()
        low = line.lower()
        if any(x in low for x in (" up ", " connected", " active", " e a ")):
            row.link_state = "up"
        elif any(x in low for x in ("down", "notconnect", "disabled", "ready", " e r ", " d r ")):
            row.link_state = row.link_state or "down"
        # Cisco/Aruba show interface status often places name after port; ProCurve show name is easier.
        if vendor == "hp_procurve":
            mm = re.match(r"^\s*(\S+)\s+(.+?)\s{2,}", line)
            if mm and normalize_port(mm.group(1)) == port:
                row.current_name = mm.group(2).strip().strip('"')
        elif vendor == "cisco_ios":
            mm = re.match(r"^\s*(\S+)\s+(.{1,28}?)\s{2,}(connected|notconnect|disabled|err-disabled|inactive)", line, flags=re.I)
            if mm and normalize_port(mm.group(1)) == port:
                row.current_name = mm.group(2).strip().strip('"')
        elif vendor == "aruba_cx":
            parts = re.split(r"\s{2,}", line.strip())
            if parts and normalize_port(parts[0]) == port and len(parts) >= 2:
                row.current_name = parts[-1].strip().strip('"') if len(parts[-1]) > 1 else row.current_name
        elif vendor == "extreme_exos":
            # show ports description: Port Display String / Description appears in loose columns.
            parts = re.split(r"\s{2,}", line.strip())
            if parts and normalize_port(parts[0]) == port and len(parts) >= 2:
                row.current_name = parts[-1].strip().strip('"')
    parse_lldp_into_rows(vendor, ports, outputs.get("lldp", ""), switch_ip, switch_name)
    rows = list(ports.values())
    for row in rows:
        row.neighbor_type = classify_neighbor(row.neighbor_hostname)
        row.suggested_name, row.reason = suggested_port_name(row.neighbor_hostname, row.neighbor_type, row.neighbor_port)
        if not row.suggested_name:
            row.status = "skip"
        elif row.current_name.strip() == row.suggested_name.strip():
            row.status = "no_change"
        elif row.current_name.strip():
            row.status = "change"
        else:
            row.status = "new"
        row.command_preview = build_rename_commands(row.vendor, row.local_port, row.suggested_name, preview=True) if row.suggested_name else []
    return sorted(rows, key=lambda r: sort_port(r.local_port))


def parse_lldp_into_rows(vendor: str, ports: dict[str, PortRow], text: str, switch_ip: str, switch_name: str) -> None:
    if not text:
        return
    if shared_parse_lldp_neighbors is not None:
        try:
            neighbors = shared_parse_lldp_neighbors(vendor, text)
            for local, data in neighbors.items():
                local = normalize_port(local)
                if not is_real_switch_port(vendor, local, str(data.get("raw_evidence", ""))):
                    continue
                row = ports.setdefault(local, PortRow(switch_ip=switch_ip, switch_name=switch_name, vendor=vendor, local_port=local))
                if data.get("remote_hostname"):
                    row.neighbor_hostname = sanitize_name(str(data.get("remote_hostname", "")), 80)
                if data.get("remote_ip"):
                    row.neighbor_ip = str(data.get("remote_ip", ""))
                if data.get("remote_port"):
                    row.neighbor_port = sanitize_name(str(data.get("remote_port", "")), 40)
                if data.get("raw_evidence"):
                    row.raw_evidence = (row.raw_evidence + "\n" + str(data.get("raw_evidence", ""))[:1200]).strip()
            return
        except Exception:
            # Fall back to the legacy module-local parser if shared parsing fails.
            pass
    if vendor == "ruckus":
        parse_ruckus_lldp_into_rows(ports, text, switch_ip, switch_name)
        return
    if vendor == "cisco_ios":
        blocks = re.split(r"\n-{8,}\n", text)
    else:
        blocks = re.split(r"\n(?=\s*(?:Local\s+(?:Port|Intf|Interface)|Port\s+ID|LLDP Neighbor|Neighbor))", text, flags=re.I)
    for block in blocks:
        local = grab(block, [r"Local\s+(?:Port|Intf|Interface)\s*[:=]?\s*(\S+)", r"Local Intf\s*:\s*(\S+)"])
        if not local:
            # Summary line fallback for non-Ruckus vendors. Keep this conservative so
            # command echoes such as "show lldp neighbors" never become hostnames.
            for line in block.splitlines():
                low_line = line.strip().lower()
                if low_line.startswith(("show ", "sh ", "device", "local", "port", "capability", "total")):
                    continue
                if PORT_RE.search(line):
                    m = PORT_RE.search(line)
                    local = m.group("port") if m else ""
                    break
        if not local:
            continue
        local = normalize_port(local)
        if not is_real_switch_port(vendor, local, block):
            continue
        row = ports.setdefault(local, PortRow(switch_ip=switch_ip, switch_name=switch_name, vendor=vendor, local_port=local))
        name = grab(block, [r"System\s+Name\s*[:=]\s*\"?(.+?)\"?\s*$", r"SysName\s*[:=]\s*(.+?)\s*$", r"Device\s+ID\s*[:=]\s*(.+?)\s*$"])
        if not name and vendor == "cisco_ios":
            # Cisco summary first column fallback.
            first_data = next((ln.strip() for ln in block.splitlines() if ln.strip() and not ln.lower().startswith(("show ", "sh ", "capability", "device", "total", "local"))), "")
            if first_data:
                name = first_data.split()[0]
        ip = grab(block, [r"Management\s+Address\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)", r"Management\s+address\s*\(IPv4\)\s*:\s*(\d+\.\d+\.\d+\.\d+)", r"IP\s*:\s*(\d+\.\d+\.\d+\.\d+)"])
        nport = grab(block, [r"Port\s+ID\s*[:=]\s*(.+?)\s*$", r"PortId\s*[:=]\s*(.+?)\s*$", r"Port Description\s*[:=]\s*(.+?)\s*$"])
        if name:
            row.neighbor_hostname = sanitize_name(name.strip().strip('"'), 80)
        if ip:
            row.neighbor_ip = ip
        if nport and normalize_port(nport) != local:
            row.neighbor_port = sanitize_name(nport.strip().strip('"'), 32)
        row.raw_evidence = (row.raw_evidence + "\n" + block.strip()[:1200]).strip()


def parse_ruckus_lldp_into_rows(ports: dict[str, PortRow], text: str, switch_ip: str, switch_name: str) -> None:
    """Parse Ruckus ICX LLDP summary and detail output.

    Ruckus commonly returns both forms in this module:
      show lldp neighbors
      show lldp neighbors detail

    Summary rows look like:
      1/1/2  b8a4.fd0.08fe  b8a4.fd0.08fe  eth0  axis-b8a4fd008fe

    Detail blocks look like:
      Local port: 1/1/2
        + System name: axis-b8a4fd008fe
        + Management address (IPv4): 192.168.1.56
        + Port description : "eth0"

    The generic fallback previously treated the command echo line (`show lldp neighbors`)
    as data, which is why the UI could show a bogus remote hostname of `show`.
    """
    # Detail parser first; it has the best IP data.
    detail_blocks = re.split(r"(?im)^\s*(?=Local\s+port\s*:)" , text)
    for block in detail_blocks:
        local = grab(block, [r"Local\s+port\s*:\s*(\S+)"])
        if not local:
            continue
        local = normalize_port(local)
        if not is_real_switch_port("ruckus", local, block):
            continue
        row = ports.setdefault(local, PortRow(switch_ip=switch_ip, switch_name=switch_name, vendor="ruckus", local_port=local))
        name = grab(block, [r"System\s+name\s*:\s*\"?(.+?)\"?\s*$"])
        ip = grab(block, [r"Management\s+address\s*\(IPv4\)\s*:\s*(\d+\.\d+\.\d+\.\d+)", r"Management\s+Address\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)"])
        nport = grab(block, [r"Port\s+description\s*:\s*\"?(.+?)\"?\s*$", r"Port\s+ID.*?:\s*(.+?)\s*$"])
        if name:
            row.neighbor_hostname = sanitize_name(name.strip().strip('"'), 80)
        if ip:
            row.neighbor_ip = ip
        if nport:
            row.neighbor_port = sanitize_name(nport.strip().strip('"'), 32)
        row.raw_evidence = (row.raw_evidence + "\n" + block.strip()[:1200]).strip()

    # Summary parser fills hostnames when detail is unavailable or incomplete.
    for line in text.splitlines():
        raw = line.strip()
        low = raw.lower()
        if not raw or low.startswith(("show ", "sh ", "neighbors", "neighbor", "local port", "lldp", "---", "total")):
            continue
        parts = raw.split()
        if len(parts) < 5:
            continue
        local = normalize_port(parts[0])
        if not is_real_switch_port("ruckus", local, line):
            continue
        # Last column is System Name in the Ruckus summary table.
        name = parts[-1]
        if not name or re.fullmatch(r"[0-9a-f]{2,4}(?:[.:-][0-9a-f]{2,4})+", name, flags=re.I):
            continue
        row = ports.setdefault(local, PortRow(switch_ip=switch_ip, switch_name=switch_name, vendor="ruckus", local_port=local))
        if not row.neighbor_hostname:
            row.neighbor_hostname = sanitize_name(name.strip().strip('"'), 80)
        if len(parts) >= 4 and not row.neighbor_port:
            row.neighbor_port = sanitize_name(parts[-2].strip().strip('"'), 32)
        row.raw_evidence = (row.raw_evidence + "\n" + raw).strip()


def grab(text: str, patterns: list[str]) -> str:
    for pat in patterns:
        m = re.search(pat, text or "", flags=re.I | re.M)
        if m:
            return m.group(1).strip()
    return ""


def sort_port(value: str) -> list[Any]:
    return [int(x) if x.isdigit() else x.lower() for x in re.split(r"(\d+)", value or "")]


def build_rename_commands(vendor: str, port: str, name: str, preview: bool = False) -> list[str]:
    port = normalize_port(port)
    name = sanitize_name(name, 63)
    if not name:
        return []
    if get_port_rename_commands:
        commands = get_port_rename_commands(vendor, port, name)
        if commands:
            return commands
    return [f"# Unsupported vendor {vendor}: set {port} to {name}"]


class SSHRunner:
    def __init__(self, host: str, port: int, username: str, password: str, timeout: int = 12):
        if paramiko is None:
            raise RuntimeError("Paramiko is not installed.")
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.client = None
        self.channel = None

    def __enter__(self) -> "SSHRunner":
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            banner_timeout=self.timeout,
            auth_timeout=self.timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        self.channel = self.client.invoke_shell(width=240, height=5000)
        self.channel.settimeout(self.timeout)
        time.sleep(0.8)
        self._drain()
        pager_cmds = []
        if get_paging_disable_commands:
            try:
                pager_cmds.extend(get_paging_disable_commands("unknown"))
            except Exception:
                pass
        pager_cmds.extend(["terminal length 0", "no page", "skip"])
        for cmd in list(dict.fromkeys(pager_cmds)):
            self.run(cmd, quiet_limit=2, initial_wait=0.15)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass

    def _drain(self) -> str:
        out = ""
        if not self.channel:
            return out
        while self.channel.recv_ready():
            out += self.channel.recv(65535).decode(errors="ignore")
        return out

    def run(self, command: str, initial_wait: float = 0.7, quiet_limit: int = 5) -> str:
        if not self.channel:
            raise RuntimeError("SSH channel is not open")
        self.channel.send(command + "\n")
        time.sleep(initial_wait)
        out = ""
        quiet = 0
        while quiet < quiet_limit:
            if self.channel.recv_ready():
                chunk = self.channel.recv(65535).decode(errors="ignore")
                out += chunk
                quiet = 0
                if "--more--" in chunk.lower() or "press any key" in chunk.lower():
                    self.channel.send(" ")
                    time.sleep(0.2)
            else:
                quiet += 1
                time.sleep(0.25)
        return clean_output(out)


def scan_switch(host: str, port: int, username: str, password: str, vendor_hint: str = "auto") -> ScanResult:
    raw: dict[str, str] = {}
    try:
        with SSHRunner(host, port, username, password) as ssh:
            detect_out = ""
            detect_vendors = [vendor_hint] if vendor_hint != "auto" else ["ruckus", "aruba_cx", "hp_procurve", "cisco_ios", "tplink", "extreme_exos"]
            for v in detect_vendors:
                for cmd in COMMANDS[v]["detect"]:
                    out = ssh.run(cmd)
                    raw[f"detect::{cmd}"] = out
                    detect_out += "\n" + out
                    found = detect_vendor(detect_out)
                    if found != "unknown":
                        vendor_hint = found
                        break
                if vendor_hint != "auto" and vendor_hint != "unknown":
                    break
            vendor = vendor_hint if vendor_hint not in {"auto", "unknown"} else detect_vendor(detect_out)
            if vendor == "unknown":
                vendor = "cisco_ios"  # Keep basic setup useful; command failures will show in evidence.
            outputs = {"detect": detect_out, "ports": "", "names": "", "lldp": ""}
            for section in ("ports", "names", "lldp"):
                for cmd in COMMANDS.get(vendor, {}).get(section, []):
                    out = ssh.run(cmd, initial_wait=0.9, quiet_limit=6)
                    raw[f"{section}::{cmd}"] = out
                    outputs[section] += "\n" + out
            hostname = parse_hostname("\n".join(raw.values()), host)
            rows = parse_port_rows(vendor, host, hostname, outputs)
            return ScanResult(target=host, port=port, success=True, vendor=vendor, hostname=hostname, rows=rows, raw_outputs=raw)
    except Exception as exc:
        return ScanResult(target=host, port=port, success=False, error=str(exc), raw_outputs=raw)


def compact_push_commands(rows: list[PortRow]) -> list[str]:
    commands: list[str] = []
    for row in rows:
        commands.extend(build_rename_commands(row.vendor, row.local_port, row.suggested_name, preview=False))
    if not rows:
        return []
    vendor = rows[0].vendor
    if vendor == "extreme_exos":
        seen: list[str] = []
        for c in commands:
            if c == "save configuration" and c in seen:
                continue
            seen.append(c)
        return seen
    begin_cmd = {
        "ruckus": "config t",
        "aruba_cx": "configure terminal",
        "hp_procurve": "config",
        "cisco_ios": "configure terminal",
        "tplink": "configure",
    }.get(vendor)
    if vendor == "ruckus":
        save_cmd = "write mem"
    elif vendor == "tplink":
        save_cmd = "copy running-config startup-config"
    else:
        save_cmd = "write memory"
    compact: list[str] = []
    if begin_cmd:
        compact.append(begin_cmd)
    for row in rows:
        body = build_rename_commands(row.vendor, row.local_port, row.suggested_name, preview=False)
        for cmd in body:
            if cmd in {begin_cmd, "end", "write memory", "write mem"}:
                continue
            compact.append(cmd)
    compact.append("end")
    compact.append(save_cmd)
    return compact


def now_stamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
