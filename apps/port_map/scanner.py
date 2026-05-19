from __future__ import annotations

import asyncio
import ipaddress
import json
import secrets
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from .commands import mac_command, rename_commands
from shared.commands import get_interface_inventory_command, get_lldp_detail_command
from .models import SwitchScan
from .parsers import merge_scan, normalize_vendor

DATA_DIR = Path(__file__).resolve().parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)


def expand_targets(targets: str, subnet_only: bool = False) -> List[str]:
    out: List[str] = []
    for token in (targets or "").replace(",", "\n").splitlines():
        token = token.strip()
        if not token:
            continue
        if "/" in token:
            net = ipaddress.ip_network(token, strict=False)
            out.extend(str(ip) for ip in net.hosts())
        elif not subnet_only:
            out.append(token)
    return list(dict.fromkeys(out))


async def run_scan(
    targets: str,
    username: str = "",
    password: str = "",
    subnet_only: bool = False,
    include_macs: bool = True,
    concurrency: int = 10,
    status_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """Run a port-map scan.

    This module first attempts to use the shell shared SSH/vendor libraries. If the shell has not wired
    them yet, it returns a structured empty result instead of crashing, allowing UI/export development.
    """
    import time

    target_list = expand_targets(targets, subnet_only=subnet_only)
    job_id = secrets.token_urlsafe(24)
    sem = asyncio.Semaphore(max(1, min(concurrency, 25)))
    started = time.time()
    total = len(target_list)
    completed = 0
    scanned = 0
    failed = 0
    discovered_neighbors = 0

    def emit(**extra: Any) -> None:
        if not status_cb:
            return
        base = {
            "job_id": job_id,
            "state": "running",
            "total_targets": total,
            "completed_targets": completed,
            "devices_scanned": scanned,
            "failed_targets": failed,
            "neighbors_found": discovered_neighbors,
            "queue_remaining": max(total - completed, 0),
            "elapsed_seconds": round(time.time() - started, 1),
        }
        base.update(extra)
        status_cb(base)

    emit(current_device="", current_command="Preparing target list", last_result=f"Queued {total} target(s)")

    async def one(ip: str) -> Optional[SwitchScan]:
        nonlocal completed, scanned, failed, discovered_neighbors
        async with sem:
            emit(current_device=ip, current_command="Connecting", last_result=f"Starting {ip}")
            try:
                scan = await scan_one(ip, username, password, include_macs=include_macs, status_cb=emit)
                completed += 1
                if scan:
                    scanned += 1
                    discovered_neighbors += sum(1 for p in scan.ports if getattr(p, "lldp", None))
                    emit(current_device=ip, current_command="Complete", last_result=f"Completed {ip}")
                else:
                    failed += 1
                    emit(current_device=ip, current_command="Complete", last_result=f"No usable data from {ip}")
                return scan
            except Exception as exc:
                completed += 1
                failed += 1
                emit(current_device=ip, current_command="Error", last_result=f"{ip}: {exc}")
                return None

    scans = [s for s in await asyncio.gather(*(one(t) for t in target_list)) if s]
    result = {"job_id": job_id, "targets": target_list, "switches": [s.to_dict() for s in scans]}
    save_job(job_id, result)
    emit(state="complete", current_device="", current_command="Complete", last_result=f"Scan complete: {len(scans)} switch(es) mapped")
    return result


async def scan_one(ip: str, username: str, password: str, include_macs: bool = True, status_cb: Optional[Callable[..., None]] = None) -> Optional[SwitchScan]:
    def emit(**kwargs: Any) -> None:
        if status_cb:
            status_cb(**kwargs)

    try:
        from shared.ssh import run_commands  # type: ignore
        from shared.vendors import detect_vendor  # type: ignore
    except Exception:
        emit(current_device=ip, current_command="Shared SSH unavailable", last_result="shared.ssh/shared.vendors not available")
        return None

    base_cmds = ["show version", "show interface brief", "show lldp neighbors detail"]
    emit(current_device=ip, current_command="show version", last_result="Collecting identity")
    outputs = await _maybe_await(run_commands(ip, username=username, password=password, commands=base_cmds))
    version = outputs.get("show version", "") if isinstance(outputs, dict) else ""
    vendor = normalize_vendor(await _maybe_await(detect_vendor(version=version, host=ip)))
    emit(current_device=ip, current_command="Vendor detection", last_result=f"Detected {vendor or 'unknown'}")
    int_cmd = preferred_interface_command(vendor)
    lldp_cmd = preferred_lldp_command(vendor)
    emit(current_device=ip, current_command=f"{int_cmd} / {lldp_cmd}", last_result="Collecting interfaces and LLDP")
    outputs = await _maybe_await(run_commands(ip, username=username, password=password, commands=[int_cmd, lldp_cmd]))
    interface_text = outputs.get(int_cmd, "")
    lldp_text = outputs.get(lldp_cmd, "")
    provisional = merge_scan(ip=ip, hostname=_hostname_from_output(version) or ip, vendor=vendor, interface_text=interface_text, lldp_text=lldp_text)

    mac_by_port: Dict[str, str] = {}
    if include_macs:
        mac_cmds = [mac_command(vendor, p.port) for p in provisional.ports if mac_command(vendor, p.port)]
        emit(current_device=ip, current_command="MAC table visibility", last_result=f"Collecting MAC data for {len(mac_cmds)} port(s)")
        mac_outputs = await _maybe_await(run_commands(ip, username=username, password=password, commands=mac_cmds))
        reverse = {mac_command(vendor, p.port): p.port for p in provisional.ports if mac_command(vendor, p.port)}
        for cmd, text in (mac_outputs or {}).items():
            if cmd in reverse:
                mac_by_port[reverse[cmd]] = text
    return merge_scan(ip=ip, hostname=provisional.hostname, vendor=vendor, interface_text=interface_text, lldp_text=lldp_text, mac_by_port=mac_by_port)


async def push_renames(job: Dict[str, Any], selected: List[Dict[str, str]], username: str, password: str, dry_run: bool = True) -> Dict[str, Any]:
    plan = []
    for item in selected:
        vendor = item.get("vendor", "")
        port = item.get("port", "")
        name = item.get("name", "")
        switch_ip = item.get("switch_ip", "")
        cmds = rename_commands(vendor, port, name)
        if cmds:
            plan.append({"switch_ip": switch_ip, "vendor": vendor, "port": port, "name": name, "commands": cmds})
    if dry_run:
        return {"dry_run": True, "plan": plan, "pushed": []}
    try:
        from shared.ssh import run_commands  # type: ignore
    except Exception as exc:
        return {"dry_run": False, "plan": plan, "pushed": [], "error": f"shared.ssh.run_commands unavailable: {exc}"}
    pushed = []
    for row in plan:
        result = await _maybe_await(run_commands(row["switch_ip"], username=username, password=password, commands=row["commands"]))
        pushed.append({**row, "result": result})
    return {"dry_run": False, "plan": plan, "pushed": pushed}


def preferred_interface_command(vendor: str) -> str:
    return get_interface_inventory_command(vendor)


def preferred_lldp_command(vendor: str) -> str:
    return get_lldp_detail_command(vendor)


def _hostname_from_output(text: str) -> str:
    import re
    for pat in (r"^\s*Hostname\s*[:=]\s*(\S+)", r"^\s*System Name\s*[:=]\s*(\S+)"):
        m = re.search(pat, text or "", re.I | re.M)
        if m:
            return m.group(1)
    return ""


async def _maybe_await(value: Any) -> Any:
    if asyncio.iscoroutine(value):
        return await value
    return value


def save_job(job_id: str, data: Dict[str, Any]) -> Path:
    path = DATA_DIR / f"{job_id}.json"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def load_job(job_id: str) -> Dict[str, Any]:
    path = DATA_DIR / f"{job_id}.json"
    return json.loads(path.read_text(encoding="utf-8"))
