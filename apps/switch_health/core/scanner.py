from __future__ import annotations

import asyncio
import ipaddress
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from ..models import Finding, SwitchResult
from .commands import BASE_COMMANDS, SHOW_TECH_COMMANDS, CABLE_TRIGGER_COMMANDS, get_switch_health_commands, get_cable_diagnostic_commands
from .parsers import parse_all


def expand_targets(raw: str) -> List[str]:
    targets: List[str] = []
    for token in re.split(r"[\s,;]+", raw.strip()):
        if not token:
            continue
        try:
            if "/" in token and not token.count(":") > 1:
                net = ipaddress.ip_network(token, strict=False)
                targets.extend(str(ip) for ip in net.hosts())
            else:
                targets.append(token)
        except ValueError:
            targets.append(token)
    seen = set()
    ordered = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            ordered.append(t)
    return ordered


def normalize_vendor(vendor: str) -> str:
    v = (vendor or "unknown").lower().replace("-", "_").replace(" ", "_")
    if "ruckus" in v or "icx" in v or "brocade" in v:
        return "ruckus"
    if "cx" in v or "aos_cx" in v or "aruba_cx" in v:
        return "aruba_cx"
    if "procurve" in v or "pro_curve" in v or "hpe" in v and "cx" not in v:
        return "procurve"
    if "cisco" in v or "ios" in v:
        return "cisco_ios"
    if "extreme" in v or "exos" in v or "switch_engine" in v:
        return "extreme_exos"
    return v if v in BASE_COMMANDS else "unknown"


def detect_vendor_from_text(text: str) -> str:
    low = text.lower()
    if "ruckus" in low or "brocade" in low or "icx" in low:
        return "ruckus"
    if "aos-cx" in low or "arubaos-cx" in low or "service os version" in low:
        return "aruba_cx"
    if "procurve" in low or "image stamp" in low or "hewlett packard enterprise" in low:
        return "procurve"
    if "cisco ios" in low or "catalyst" in low:
        return "cisco_ios"
    if "extremexos" in low or "extreme networks" in low or "switch engine" in low:
        return "extreme_exos"
    return "unknown"


def extract_hostname(outputs: Dict[str, str], target: str) -> str:
    combined = "\n".join(outputs.values())
    for pattern in [r"(?:hostname|system name|switch name)\s*[:=]\s*([A-Za-z0-9_.-]+)", r"^([A-Za-z0-9_.-]+)[>#]\s*$"]:
        m = re.search(pattern, combined, re.I | re.M)
        if m:
            return m.group(1)
    return target


class SharedSSHAdapter:
    """Thin compatibility wrapper around the shell shared SSH library.

    Expected shared module options, in order:
    - shared.ssh.run_commands(target, username, password, commands, ...)
    - shared.ssh.SSHRunner(...).run_commands(target, commands)
    - shared.ssh.SwitchSSH(...).run_commands(commands)

    This keeps the module usable while the shell shared libraries continue to evolve.
    """

    def __init__(self, username: str, password: str, timeout: int = 20, debug: bool = False):
        self.username = username
        self.password = password
        self.timeout = timeout
        self.debug = debug

    async def run_commands(self, target: str, commands: List[str]) -> Dict[str, str]:
        return await asyncio.to_thread(self._run_commands_sync, target, commands)

    def _run_commands_sync(self, target: str, commands: List[str]) -> Dict[str, str]:
        try:
            from shared import ssh as shared_ssh  # type: ignore
        except Exception as exc:
            raise RuntimeError("shared.ssh library is not available. Install this module inside the Single Digits Engineering Platform shell.") from exc

        if hasattr(shared_ssh, "run_commands"):
            result = shared_ssh.run_commands(
                target=target,
                username=self.username,
                password=self.password,
                commands=commands,
                timeout=self.timeout,
                debug=self.debug,
                suppress_tracebacks=not self.debug,
            )
            return _coerce_outputs(result, commands)

        for cls_name in ("SSHRunner", "SwitchSSH", "SSHClient"):
            cls = getattr(shared_ssh, cls_name, None)
            if not cls:
                continue
            try:
                runner = cls(username=self.username, password=self.password, timeout=self.timeout, debug=self.debug)
            except TypeError:
                runner = cls(target=target, username=self.username, password=self.password, timeout=self.timeout, debug=self.debug)
            if hasattr(runner, "run_commands"):
                try:
                    return _coerce_outputs(runner.run_commands(target, commands), commands)
                except TypeError:
                    return _coerce_outputs(runner.run_commands(commands), commands)

        raise RuntimeError("No compatible shared SSH command runner was found in shared.ssh.")


def _coerce_outputs(result: Any, commands: List[str]) -> Dict[str, str]:
    if isinstance(result, dict):
        if "outputs" in result and isinstance(result["outputs"], dict):
            return {str(k): str(v) for k, v in result["outputs"].items()}
        return {str(k): str(v) for k, v in result.items()}
    if isinstance(result, list):
        return {cmd: str(result[i]) if i < len(result) else "" for i, cmd in enumerate(commands)}
    return {"raw": str(result)}


async def scan_switch(target: str, username: str, password: str, *, show_tech: bool = False, cable_diagnostics: bool = False, cable_ports: Optional[List[str]] = None, timeout: int = 20, debug: bool = False) -> SwitchResult:
    result = SwitchResult(target=target)
    adapter = SharedSSHAdapter(username, password, timeout=timeout, debug=debug)
    try:
        probe_commands = ["show version", "show system", "show system-information"]
        probe = await adapter.run_commands(target, probe_commands)
        vendor = detect_vendor_from_text("\n".join(probe.values()))
        result.vendor = vendor

        commands = get_switch_health_commands(vendor, show_tech=show_tech)
        outputs = dict(probe)
        outputs.update(await adapter.run_commands(target, commands))

        if cable_diagnostics and vendor in CABLE_TRIGGER_COMMANDS:
            for port in cable_ports or _candidate_ports(outputs):
                port_cmds = get_cable_diagnostic_commands(vendor, port)
                outputs.update(await adapter.run_commands(target, port_cmds))

        result.connected = True
        result.command_outputs = outputs
        result.hostname = extract_hostname(outputs, target)
        result.findings = parse_all(vendor, outputs)
        if not result.findings:
            result.findings.append(Finding("info", "Summary", "No major findings detected", "No critical or warning findings were detected by the current ruleset."))
    except Exception as exc:
        result.connected = False
        result.error = str(exc) if debug else _safe_error(str(exc))
        result.findings.append(Finding("critical", "Connectivity", "Could not complete switch scan", result.error))
    finally:
        result.completed_at = datetime.now().isoformat(timespec="seconds")
    return result


def _safe_error(err: str) -> str:
    if re.search(r"auth|password|login|credential", err, re.I):
        return "Login failed or credentials were rejected. Enable debug for detailed troubleshooting."
    return err.splitlines()[0][:300]


def _candidate_ports(outputs: Dict[str, str]) -> List[str]:
    combined = "\n".join(outputs.values())
    ports = []
    for m in re.finditer(r"\b(\d+/\d+/\d+|\d+/\d+)\b", combined):
        p = m.group(1)
        if p not in ports:
            ports.append(p)
        if len(ports) >= 24:
            break
    return ports


async def scan_many(raw_targets: str, username: str, password: str, *, concurrency: int = 10, show_tech: bool = False, cable_diagnostics: bool = False, cable_ports_raw: str = "", timeout: int = 20, debug: bool = False) -> List[SwitchResult]:
    targets = expand_targets(raw_targets)
    limit = max(1, min(int(concurrency or 10), 25))
    semaphore = asyncio.Semaphore(limit)
    cable_ports = [p.strip() for p in re.split(r"[\s,;]+", cable_ports_raw or "") if p.strip()]

    async def worker(t: str) -> SwitchResult:
        async with semaphore:
            return await scan_switch(t, username, password, show_tech=show_tech, cable_diagnostics=cable_diagnostics, cable_ports=cable_ports, timeout=timeout, debug=debug)

    return await asyncio.gather(*(worker(t) for t in targets))
