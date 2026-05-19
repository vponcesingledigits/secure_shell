from __future__ import annotations

import ipaddress
import socket
import threading
import time
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

from .commands import SHOW_TECH_COMMANDS, CABLE_DIAG_START, CABLE_DIAG_SHOW, commands_for, normalize_platform
from .models import ScanJob, SwitchResult, CommandResult
from .parsers import analyze, detect_vendor_from_text, hostname_from_output

try:
    from shared.security.redaction import safe_client_error
    from shared.ssh import SSHRunner, SSHOptions  # shell shared library path
except Exception:  # module can still import before shared libs exist
    SSHRunner = None
    SSHOptions = None
    def safe_client_error(exc, *args, **kwargs):
        return "Operation failed. See server log for details."

try:
    from shared.vendors import detect_vendor as shared_detect_vendor
except Exception:
    shared_detect_vendor = None


def parse_targets(raw: str, default_port: int = 22, max_subnet_hosts: int = 512) -> list[str]:
    targets: list[str] = []
    for token in (raw or "").replace(",", "\n").splitlines():
        token = token.strip()
        if not token or token.startswith("#"):
            continue
        if "/" in token:
            try:
                net = ipaddress.ip_network(token, strict=False)
                hosts = list(net.hosts())
                if len(hosts) > max_subnet_hosts:
                    hosts = hosts[:max_subnet_hosts]
                targets.extend(str(h) for h in hosts)
                continue
            except ValueError:
                pass
        targets.append(token)
    return list(dict.fromkeys(targets))


def split_host_port(target: str, default_port: int = 22) -> tuple[str, int]:
    target = target.strip()
    if target.count(":") == 1 and not target.startswith("["):
        host, port_s = target.rsplit(":", 1)
        if port_s.isdigit():
            return host.strip(), int(port_s)
    return target, default_port


class ParamikoFallbackRunner:
    def __init__(self, username: str, password: str, timeout: int = 10, debug: bool = False):
        self.username = username
        self.password = password
        self.timeout = timeout
        self.debug = debug

    def run_commands(self, host: str, port: int, commands: list[str]) -> dict[str, CommandResult]:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        results: dict[str, CommandResult] = {}
        client.connect(host, port=port, username=self.username, password=self.password, timeout=self.timeout, look_for_keys=False, allow_agent=False)
        chan = client.invoke_shell(width=200, height=2000)
        time.sleep(0.8)
        if chan.recv_ready():
            chan.recv(65535)
        for pager_off in ["terminal length 0", "no page", "skip-page-display", "page-off"]:
            try:
                chan.send(pager_off + "\n")
                time.sleep(0.25)
                if chan.recv_ready():
                    chan.recv(65535)
            except Exception:
                pass
        for cmd in commands:
            out = self._send(chan, cmd)
            ok = not any(x in out.lower() for x in ["invalid input", "unknown command", "ambiguous command"])
            results[cmd] = CommandResult(command=cmd, output=out, ok=ok, error="" if ok else "command may be unsupported")
        client.close()
        return results

    def _send(self, chan, cmd: str) -> str:
        chan.send(cmd + "\n")
        deadline = time.time() + self.timeout
        chunks: list[str] = []
        last = time.time()
        while time.time() < deadline:
            if chan.recv_ready():
                data = chan.recv(65535).decode(errors="ignore")
                chunks.append(data)
                last = time.time()
                if "--More--" in data or "Press any key" in data:
                    chan.send(" ")
            elif time.time() - last > 1.0:
                break
            time.sleep(0.1)
        return "".join(chunks)


class SwitchHealthEngine:
    def __init__(self):
        self.jobs: dict[str, ScanJob] = {}
        self.lock = threading.Lock()

    def create_job(self, targets: list[str], options: dict[str, Any]) -> ScanJob:
        job = ScanJob(job_id=secrets.token_urlsafe(16), targets=targets, options=options)
        with self.lock:
            self.jobs[job.job_id] = job
        return job

    def get_job(self, job_id: str) -> ScanJob | None:
        with self.lock:
            return self.jobs.get(job_id)

    def list_jobs(self) -> list[ScanJob]:
        with self.lock:
            return sorted(self.jobs.values(), key=lambda j: j.created_at, reverse=True)

    def append_log(self, job: ScanJob, msg: str) -> None:
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        with self.lock:
            job.log.append(line)
            job.log = job.log[-1000:]

    def run_job(self, job_id: str) -> None:
        job = self.get_job(job_id)
        if not job:
            return
        job.status = "running"
        job.started_at = datetime.now().isoformat(timespec="seconds")
        username = job.options.get("username", "")
        password = job.options.get("password", "")
        default_port = int(job.options.get("port", 22) or 22)
        concurrency = max(1, min(int(job.options.get("concurrency", 10) or 10), 25))
        self.append_log(job, f"Started Switch Health scan with {concurrency} worker(s)")
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = [ex.submit(self.scan_target, t, username, password, default_port, job.options) for t in job.targets]
            for fut in as_completed(futures):
                res = fut.result()
                with self.lock:
                    job.results.append(res)
                self.append_log(job, f"Completed {res.target}: {len(res.findings)} finding(s)")
        job.status = "completed"
        job.completed_at = datetime.now().isoformat(timespec="seconds")
        self.append_log(job, "Switch Health scan completed")

    def scan_target(self, target: str, username: str, password: str, default_port: int, options: dict[str, Any]) -> SwitchResult:
        host, port = split_host_port(target, default_port)
        result = SwitchResult(target=target, host=host, port=port, status="running")
        try:
            if not self._tcp_open(host, port, timeout=5):
                result.status = "unreachable"
                result.summary = "SSH port unavailable"
                result.completed_at = datetime.now().isoformat(timespec="seconds")
                return result

            probe_cmds = ["show version", "show system", "show system-information"]
            probe = self._run(host, port, username, password, probe_cmds, options)
            probe_text = "\n".join(cr.output for cr in probe.values())
            vendor, platform = detect_vendor_from_text(probe_text)
            platform = normalize_platform(platform)
            if platform == "generic" and shared_detect_vendor:
                try:
                    detected = shared_detect_vendor(probe_text)
                    platform = normalize_platform(getattr(detected, "key", platform) or platform)
                    vendor = getattr(detected, "vendor", vendor) or vendor
                except Exception:
                    pass
            result.vendor = vendor
            result.platform = platform
            result.hostname = hostname_from_output(probe_text, fallback=host)

            selected_sets = options.get("command_sets") or None
            commands = commands_for(platform, selected_sets)
            if options.get("show_tech"):
                tech = SHOW_TECH_COMMANDS.get(platform)
                if tech:
                    commands.append(tech)
            command_results = self._run(host, port, username, password, commands, options)
            result.commands = command_results
            result.raw = {cmd: cr.output for cmd, cr in command_results.items()}
            result.raw.update({f"probe:{cmd}": cr.output for cmd, cr in probe.items()})

            cable_ports = [p.strip() for p in (options.get("cable_ports") or "").replace(",", "\n").splitlines() if p.strip()]
            if cable_ports and platform in CABLE_DIAG_START:
                diag_cmds = []
                for p in cable_ports[:48]:
                    diag_cmds.append(CABLE_DIAG_START[platform].format(port=p))
                    diag_cmds.append(CABLE_DIAG_SHOW[platform].format(port=p))
                diag = self._run(host, port, username, password, diag_cmds, options)
                result.commands.update(diag)
                result.raw.update({cmd: cr.output for cmd, cr in diag.items()})

            result.findings = analyze(result)
            crit = sum(1 for f in result.findings if f.severity == "critical")
            warn = sum(1 for f in result.findings if f.severity == "warning")
            result.status = "critical" if crit else ("warning" if warn else "healthy")
            result.summary = f"{crit} critical, {warn} warning, {len(result.findings)-crit-warn} info"
        except Exception as exc:
            result.status = "error"
            result.summary = safe_client_error(exc)
            result.logs.append(safe_client_error(exc))
        finally:
            result.completed_at = datetime.now().isoformat(timespec="seconds")
        return result

    def _run(self, host: str, port: int, username: str, password: str, commands: list[str], options: dict[str, Any]) -> dict[str, CommandResult]:
        if SSHRunner and SSHOptions:
            try:
                runner = SSHRunner(SSHOptions(username=username, password=password, port=port, timeout=int(options.get("timeout", 12)), debug=bool(options.get("debug"))))
                data = runner.run_commands(host, commands)
                out: dict[str, CommandResult] = {}
                for cmd in commands:
                    value = data.get(cmd, "") if isinstance(data, dict) else ""
                    out[cmd] = CommandResult(command=cmd, output=str(value), ok=True)
                return out
            except Exception:
                if options.get("debug"):
                    raise
        return ParamikoFallbackRunner(username, password, int(options.get("timeout", 12)), bool(options.get("debug"))).run_commands(host, port, commands)

    @staticmethod
    def _tcp_open(host: str, port: int, timeout: int = 5) -> bool:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            return s.connect_ex((host, port)) == 0
        finally:
            s.close()

engine = SwitchHealthEngine()
