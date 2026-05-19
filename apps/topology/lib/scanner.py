from __future__ import annotations

import ipaddress
import queue
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set

from .classification import ROLE_SWITCH, role_is_visible
from .models import DeviceRecord, LinkRecord, TopologyProject
from .parsers import merge_lldp_into_ports, parse_generic_lldp, parse_interface_inventory, parse_mstp_priority

LogFn = Callable[[str], None]


@dataclass
class ScanResult:
    data: Dict
    logs: List[str] = field(default_factory=list)


def expand_targets(text: str, default_port: int = 22) -> List[str]:
    targets: List[str] = []
    for part in re.split(r"[\n,;\s]+", text or ""):
        item = part.strip()
        if not item:
            continue
        if "/" in item:
            try:
                net = ipaddress.ip_network(item, strict=False)
                for host in net.hosts():
                    targets.append(f"{host}:{default_port}")
            except Exception:
                targets.append(item)
        elif ":" not in item and re.match(r"^\d+\.\d+\.\d+\.\d+$", item):
            targets.append(f"{item}:{default_port}")
        else:
            targets.append(item)
    seen = set()
    out = []
    for t in targets:
        if t not in seen:
            out.append(t)
            seen.add(t)
    return out


def split_target(target: str, default_port: int = 22) -> tuple[str, int]:
    if target.count(":") == 1 and re.match(r"^[^:]+:\d+$", target):
        host, port = target.rsplit(":", 1)
        return host.strip(), int(port)
    return target.strip(), default_port


class CommandRunner:
    """SSH command runner. Uses shell shared SSH helpers when available, otherwise Paramiko."""

    def __init__(self, username: str, password: str, timeout: int = 20, log: Optional[LogFn] = None):
        self.username = username
        self.password = password
        self.timeout = timeout
        self.log = log or (lambda m: None)

    def run_commands(self, host: str, port: int, commands: Iterable[str]) -> Dict[str, str]:
        # Prefer future shell shared SSH if present.
        try:
            from shared.ssh import run_commands as shared_run_commands  # type: ignore
            return shared_run_commands(host=host, port=port, username=self.username, password=self.password, commands=list(commands), timeout=self.timeout)
        except Exception:
            pass
        return self._run_paramiko(host, port, commands)

    def _run_paramiko(self, host: str, port: int, commands: Iterable[str]) -> Dict[str, str]:
        try:
            import paramiko  # type: ignore
        except Exception as exc:
            raise RuntimeError("Paramiko is not installed and shared.ssh.run_commands is unavailable.") from exc

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=host, port=port, username=self.username, password=self.password, timeout=self.timeout, banner_timeout=self.timeout, auth_timeout=self.timeout, look_for_keys=False, allow_agent=False)
            chan = client.invoke_shell(width=240, height=1000)
            chan.settimeout(self.timeout)
            time.sleep(0.4)
            self._drain(chan)
            # disable paging best-effort across vendors
            for pager in ("skip-page-display", "terminal length 0", "no page", "page", "set cli pager off"):
                try:
                    chan.send(pager + "\n")
                    time.sleep(0.15)
                    self._drain(chan)
                except Exception:
                    pass
            outputs: Dict[str, str] = {}
            for cmd in commands:
                self.log(f"{host} | command | {cmd}")
                chan.send(cmd + "\n")
                outputs[cmd] = self._read_until_prompt(chan)
            return outputs
        finally:
            try:
                client.close()
            except Exception:
                pass

    def _drain(self, chan) -> str:
        chunks = []
        end = time.time() + 1.0
        while time.time() < end:
            try:
                if chan.recv_ready():
                    chunks.append(chan.recv(65535).decode("utf-8", "ignore"))
                    end = time.time() + 0.2
                else:
                    time.sleep(0.05)
            except socket.timeout:
                break
        return "".join(chunks)

    def _read_until_prompt(self, chan) -> str:
        buf = []
        deadline = time.time() + self.timeout
        prompt_pat = re.compile(r"(?m)^[\s\*\w.()/:\-]+[>#]\s*$")
        while time.time() < deadline:
            try:
                if chan.recv_ready():
                    data = chan.recv(65535).decode("utf-8", "ignore")
                    buf.append(data)
                    text = "".join(buf)
                    if prompt_pat.search(text.splitlines()[-1] if text.splitlines() else text):
                        break
                else:
                    time.sleep(0.1)
            except socket.timeout:
                break
        return "".join(buf)


def scan_topology(
    targets: str,
    username: str,
    password: str,
    timeout: int = 20,
    port: int = 22,
    concurrency: int = 10,
    include_aps: bool = False,
    include_all_devices: bool = False,
    log_callback: Optional[LogFn] = None,
) -> ScanResult:
    logs: List[str] = []

    def log(msg: str) -> None:
        logs.append(msg)
        if log_callback:
            log_callback(msg)

    concurrency = max(1, min(int(concurrency or 10), 25))
    target_list = expand_targets(targets, port)
    log(f"Starting topology scan for {len(target_list)} initial target(s), concurrency={concurrency}.")

    runner = CommandRunner(username, password, timeout, log)
    q: "queue.Queue[str]" = queue.Queue()
    queued: Set[str] = set()
    scanned_hosts: Set[str] = set()
    devices: Dict[str, DeviceRecord] = {}
    links: Dict[tuple, LinkRecord] = {}
    all_ports = []
    raw_neighbors = []
    lock = threading.Lock()

    for t in target_list:
        q.put(t)
        queued.add(t)

    def add_target(ip: str) -> None:
        if not ip:
            return
        target = f"{ip}:{port}"
        with lock:
            if target in queued or ip in scanned_hosts:
                return
            queued.add(target)
            q.put(target)
            log(f"Discovered switch neighbor {ip}; queued for scan.")

    def worker() -> None:
        while True:
            try:
                target = q.get(timeout=1.0)
            except queue.Empty:
                return
            host, ssh_port = split_target(target, port)
            with lock:
                if host in scanned_hosts:
                    q.task_done()
                    continue
                scanned_hosts.add(host)
            try:
                log(f"Connecting to {host}:{ssh_port}")
                commands = [
                    "show lldp neigh det | i Local|name|address|Desc",
                    "show lldp neighbors detailed | include Name|Address|Local|Port|Description|Capability",
                    "show interfaces brief wide",
                    "show interfaces status",
                    "show ports no-refresh",
                    "show run | include priority",
                    "show system",
                    "show version",
                ]
                outputs = runner.run_commands(host, ssh_port, commands)
                # Choose best LLDP output with data.
                lldp_text = ""
                for cmd in commands[:2]:
                    txt = outputs.get(cmd, "") or ""
                    if ("Local port" in txt or "System Name" in txt or "System name" in txt) and len(txt) > len(lldp_text):
                        lldp_text = txt
                name = guess_hostname(outputs, fallback=host)
                mgmt_ip = guess_management_ip(outputs, fallback=host)
                vendor, model, version, serial = guess_identity(outputs)
                mstp_priority = parse_mstp_priority(outputs.get("show run | include priority", ""))

                local_id = stable_device_id(name, mgmt_ip or host)
                device = DeviceRecord(local_id=local_id, name=name, role="switch", management_ip=mgmt_ip or host, ssh_target_ip=host, vendor=vendor, model=model, serial_number=serial, software_version=version, mstp_priority=mstp_priority, discovered_from=target, source="scan")
                with lock:
                    devices[local_id] = device

                neighbors = parse_generic_lldp(lldp_text, local_device=name, local_ip=mgmt_ip or host)
                int_text = "\n".join(outputs.get(c, "") for c in ["show interfaces brief wide", "show interfaces status", "show ports no-refresh"] if outputs.get(c))
                port_rows = merge_lldp_into_ports(parse_interface_inventory(int_text, name), neighbors)

                with lock:
                    all_ports.extend([p.to_dict() for p in port_rows])
                    raw_neighbors.extend([n.to_dict() for n in neighbors])

                for n in neighbors:
                    visible = role_is_visible(n.role, include_aps, include_all_devices)
                    # Always store visible/non-visible raw neighbors. Only create links/devices for visible roles.
                    if n.role == ROLE_SWITCH and n.remote_ip:
                        add_target(n.remote_ip)
                    if not visible:
                        continue
                    target_name = n.remote_hostname or n.remote_ip or "unknown"
                    target_ip = n.remote_ip or ""
                    target_id = stable_device_id(target_name, target_ip)
                    with lock:
                        if target_id not in devices:
                            devices[target_id] = DeviceRecord(local_id=target_id, name=target_name, role=n.role, management_ip=target_ip, discovered_from=name, source="lldp")
                        link = LinkRecord(local_id=f"link-{len(links)+1:04d}", source_device=name, source_ip=mgmt_ip or host, source_port=n.local_port, target_device=target_name, target_ip=target_ip, target_port=n.remote_port, target_role=n.role, source="lldp")
                        links[link.canonical_key()] = link
                log(f"Completed {name} ({host}).")
            except Exception as exc:
                log(f"ERROR | {host} | {exc}")
            finally:
                q.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(concurrency)]
    for t in threads:
        t.start()
    q.join()

    dev_list = [d.to_dict() for d in devices.values()]
    link_list = [l.to_dict() for l in links.values()]
    tree = build_tree(dev_list, link_list)
    project = TopologyProject(
        scan_settings={"targets": targets, "timeout": timeout, "port": port, "concurrency": concurrency, "include_aps": include_aps, "include_all_devices": include_all_devices},
        devices=sorted(dev_list, key=lambda d: (d.get("role") != "switch", d.get("name", ""))),
        links=sorted(link_list, key=lambda l: (l.get("source_device", ""), l.get("source_port", ""), l.get("target_device", ""))),
        ports=sorted(all_ports, key=lambda p: (p.get("switch_name", ""), p.get("local_port_id", ""))),
        raw_neighbors=raw_neighbors,
        topology_tree=tree,
    )
    data = project.to_dict()
    data["summary"] = {
        "devices": len(dev_list),
        "switches": sum(1 for d in dev_list if d.get("role") == "switch"),
        "links": len(link_list),
        "ports": len(all_ports),
        "raw_neighbors": len(raw_neighbors),
    }
    log("Topology scan complete.")
    return ScanResult(data=data, logs=logs)


def stable_device_id(name: str, ip: str = "") -> str:
    base = re.sub(r"[^a-z0-9]+", "-", (name or ip or "device").lower()).strip("-") or "device"
    return base[:80]


def guess_hostname(outputs: Dict[str, str], fallback: str) -> str:
    blob = "\n".join(outputs.values())
    patterns = [r"SysName\s*:\s*(\S+)", r"System\s+Name\s*:\s*(\S+)", r"Hostname\s*[:=]\s*(\S+)", r"Switch\s+Name\s*:\s*(\S+)"]
    for pat in patterns:
        m = re.search(pat, blob, re.I)
        if m:
            return m.group(1).strip('"')
    # Prompt echo best-effort: line ending with # or >
    for line in blob.splitlines():
        s = line.strip()
        m = re.match(r"^\*?\s*([A-Za-z0-9_.-]{3,})\S*\s*[>#]$", s)
        if m and not m.group(1).lower().startswith("show"):
            return m.group(1)
    return fallback


def guess_management_ip(outputs: Dict[str, str], fallback: str) -> str:
    blob = "\n".join(outputs.values())
    m = re.search(r"Management\s+Address(?:\s*\([^)]*\))?\s*:\s*([0-9]+(?:\.[0-9]+){3})", blob, re.I)
    if m:
        return m.group(1)
    return fallback


def guess_identity(outputs: Dict[str, str]) -> tuple[str, str, str, str]:
    blob = "\n".join(outputs.values())
    low = blob.lower()
    vendor = "unknown"
    if "ruckus" in low or "brocade" in low or "icx" in low:
        vendor = "Ruckus ICX"
    elif "aruba" in low and "aos-cx" in low:
        vendor = "Aruba CX"
    elif "procurve" in low or "hewlett-packard" in low or re.search(r"\bya\.\d+|\bkb\.\d+|\bwc\.\d+", low):
        vendor = "HP/Aruba ProCurve"
    elif "cisco ios" in low or "catalyst" in low:
        vendor = "Cisco IOS"
    elif "extremexos" in low or "extreme networks" in low:
        vendor = "Extreme EXOS"
    model = first_identity(blob, [r"System\s+Type\s*:\s*(.+)", r"HW\s*:\s*(.+)", r"Model\s*[:=]\s*(.+)", r"Product\s+Name\s*:\s*(.+)"])
    version = first_identity(blob, [r"SW\s*:\s*Version\s*([^\s,]+)", r"Version\s*[:=]?\s*([^\s,]+)", r"AOS-CX\s+Version\s*:\s*(\S+)", r"ExtremeXOS\s+version\s+(\S+)"])
    serial = first_identity(blob, [r"Serial\s+Number\s*[:=]\s*(\S+)", r"Serial\s*[:=]\s*(\S+)"])
    return vendor, model.strip(), version.strip(), serial.strip()


def first_identity(text: str, patterns: Iterable[str]) -> str:
    for pat in patterns:
        m = re.search(pat, text, re.I)
        if m:
            return m.group(1).strip()
    return ""


def build_tree(devices: List[Dict], links: List[Dict]) -> List[Dict]:
    switches = {d["name"]: d for d in devices if d.get("role") == "switch"}
    if not switches:
        return []
    adjacency: Dict[str, List[Dict]] = {name: [] for name in switches}
    incoming: Dict[str, int] = {name: 0 for name in switches}
    for l in links:
        a = l.get("source_device", "")
        b = l.get("target_device", "")
        if a in switches and b in switches:
            adjacency.setdefault(a, []).append(l)
            incoming[b] = incoming.get(b, 0) + 1
    roots = [name for name, d in switches.items() if re.search(r"mdf|core", name, re.I)]
    if not roots:
        roots = [name for name, count in incoming.items() if count == 0]
    if not roots:
        roots = sorted(switches, key=lambda n: (-len(adjacency.get(n, [])), n))[:1]

    visited = set()

    def node(name: str, via: Dict | None = None) -> Dict:
        visited.add(name)
        d = switches[name]
        out = {"name": name, "ip": d.get("management_ip", ""), "local_port": "", "remote_port": "", "children": []}
        if via:
            out["local_port"] = via.get("source_port", "")
            out["remote_port"] = via.get("target_port", "")
        for link in sorted(adjacency.get(name, []), key=lambda x: (x.get("source_port", ""), x.get("target_device", ""))):
            child = link.get("target_device", "")
            if child in switches and child not in visited:
                out["children"].append(node(child, link))
        return out

    tree = [node(r) for r in roots if r in switches and r not in visited]
    for orphan in sorted(set(switches) - visited):
        tree.append(node(orphan))
    return tree
