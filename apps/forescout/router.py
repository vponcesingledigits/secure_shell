from __future__ import annotations

import io
import ipaddress
import os
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from shared.security.redaction import safe_client_error
from typing import Any
import secrets

try:
    import paramiko
except ImportError:  # pragma: no cover - startup should not fail before deps are installed
    paramiko = None
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from app.config import APP_NAME, APP_VERSION, FAVICON_URL
from shared.commands import get_paging_disable_commands, get_forescout_collection_commands

router = APIRouter(tags=["forescout"])
templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")
BASE_DIR = Path(__file__).resolve().parents[2]
ENV_PATHS = [BASE_DIR / ".env", BASE_DIR / "apps" / "forescout" / ".env"]

JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()
SECRET_KEYS = ("password", "secret", "community", "snmp", "trap")


@dataclass
class ForeScoutSettings:
    forescout_username: str = ""
    forescout_password: str = ""
    forescout_snmp: str = ""
    trap_hosts: list[str] = field(default_factory=list)
    traps_required: bool = True
    debug: bool = False


@dataclass
class Target:
    host: str
    port: int = 22


@dataclass
class Finding:
    severity: str
    check: str
    status: str
    detail: str
    remediation: str = ""


@dataclass
class DeviceResult:
    target: str
    host: str
    port: int
    vendor: str = "Unknown"
    hostname: str = ""
    actual_ip: str = ""
    group: str = "Could Not Connect"
    connected: bool = False
    remediated: bool = False
    error: str = ""
    findings: list[Finding] = field(default_factory=list)
    raw: dict[str, str] = field(default_factory=dict)


def load_env() -> ForeScoutSettings:
    data: dict[str, str] = {}
    for path in ENV_PATHS:
        if not path.exists():
            continue
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip().strip('"').strip("'")
    return ForeScoutSettings(
        forescout_username=data.get("FORESCOUT_USERNAME", ""),
        forescout_password=data.get("FORESCOUT_PASSWORD", ""),
        forescout_snmp=data.get("FORESCOUT_SNMP", ""),
        trap_hosts=[h.strip() for h in data.get("FORESCOUT_TRAP_HOSTS", "").replace(";", ",").split(",") if h.strip()],
        traps_required=data.get("FORESCOUT_TRAPS_REQUIRED", "true").lower() not in {"0", "false", "no", "off"},
        debug=data.get("DEBUG", "false").lower() in {"1", "true", "yes", "on"},
    )


def redact(value: str | None) -> str:
    if not value:
        return ""
    text = str(value)
    # Redact common config lines while preserving structure enough for troubleshooting.
    patterns = [
        r"(password\s+)(\S+)",
        r"(community\s+)(\S+)",
        r"(snmp-server\s+community\s+)(\S+)",
        r'(community\s+")([^"]+)(")',
        r"(key\s+)(\S+)",
        r"(secret\s+)(\S+)",
    ]
    for pat in patterns:
        text = re.sub(pat, lambda m: m.group(1) + "<redacted>" + (m.group(3) if m.lastindex and m.lastindex >= 3 else ""), text, flags=re.I)
    return text


def parse_targets(raw: str, default_port: int = 22, max_hosts: int = 512) -> list[Target]:
    targets: list[Target] = []
    seen: set[tuple[str, int]] = set()
    tokens = re.split(r"[\s,;]+", raw.strip())
    for token in tokens:
        if not token:
            continue
        token = token.strip()
        if "/" in token:
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError:
                continue
            for ip in list(net.hosts())[:max_hosts]:
                key = (str(ip), default_port)
                if key not in seen:
                    seen.add(key)
                    targets.append(Target(str(ip), default_port))
            continue
        host, port = token, default_port
        if token.count(":") == 1 and not token.startswith("["):
            left, right = token.rsplit(":", 1)
            if right.isdigit():
                host, port = left, int(right)
        key = (host, port)
        if key not in seen:
            seen.add(key)
            targets.append(Target(host, port))
    return targets


def tcp_open(host: str, port: int, timeout: float = 4) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


class SSHSession:
    def __init__(self, host: str, port: int, username: str, password: str, debug: bool = False):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.debug = debug
        self.client: paramiko.SSHClient | None = None
        self.channel = None

    def __enter__(self) -> "SSHSession":
        if paramiko is None:
            raise RuntimeError("Paramiko is not installed. Run start.bat to install requirements.")
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=8,
            auth_timeout=8,
            banner_timeout=12,
            look_for_keys=False,
            allow_agent=False,
        )
        self.channel = self.client.invoke_shell(width=200, height=80)
        self.channel.settimeout(8)
        time.sleep(0.8)
        self.drain()
        return self

    def __exit__(self, *_args):
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass

    def drain(self) -> str:
        out = ""
        if not self.channel:
            return out
        while self.channel.recv_ready():
            out += self.channel.recv(65535).decode(errors="ignore")
        return out

    def run(self, cmd: str, wait: float = 0.7, quiet_cycles: int = 4) -> str:
        if not self.channel:
            return ""
        self.channel.send(cmd + "\n")
        time.sleep(wait)
        out = ""
        quiet = 0
        while quiet < quiet_cycles:
            if self.channel.recv_ready():
                out += self.channel.recv(65535).decode(errors="ignore")
                quiet = 0
            else:
                quiet += 1
                time.sleep(0.35)
        return clean_output(out)

    def prep_terminal(self):
        for cmd in ("no page", "terminal length 0", "terminal datadump", "screen-length disable"):
            try:
                self.run(cmd, wait=0.25, quiet_cycles=1)
            except Exception:
                pass


def clean_output(output: str) -> str:
    output = output.replace("\r", "")
    output = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", output)
    output = re.sub(r"--More--.*", "", output)
    return output


def detect_vendor(show_version: str) -> str:
    text = show_version.lower()
    if "ruckus" in text or "brocade" in text or "icx" in text:
        return "Ruckus ICX"
    if "aos-cx" in text or "arubaos-cx" in text or "service os version" in text:
        return "Aruba CXOS"
    if "procurve" in text or "hewlett-packard" in text or re.search(r"\b(ya|yb|yc|kb|wc)\.\d+", text):
        return "HP/Aruba ProCurve"
    if "cisco ios" in text or "cisco ios software" in text or "c2960" in text or "catalyst" in text:
        return "Cisco IOS"
    return "Unknown"


def parse_hostname(output: str, fallback: str) -> str:
    for pat in (r"hostname\s+([A-Za-z0-9_.-]+)", r"switchname\s+([A-Za-z0-9_.-]+)", r"@([A-Za-z0-9_.-]+)[#>]", r"^([A-Za-z0-9_.-]+)[#>]",):
        m = re.search(pat, output, re.I | re.M)
        if m:
            return m.group(1)
    return fallback


def vendor_commands(vendor: str) -> dict[str, str]:
    if vendor == "Aruba CXOS":
        return {
            "run": "show running-config",
            "hostname": "show hostname",
            "central": "show aruba-central",
            "remediate_enter": "configure terminal",
            "remediate_exit": "end",
            "save": "write memory",
        }
    if vendor == "HP/Aruba ProCurve":
        return {"run": "show running-config", "hostname": "show system-information", "remediate_enter": "configure", "remediate_exit": "end", "save": "write memory"}
    if vendor == "Cisco IOS":
        return {"run": "show running-config", "hostname": "show running-config | include hostname", "remediate_enter": "configure terminal", "remediate_exit": "end", "save": "write memory"}
    return {"run": "show running-config", "hostname": "show running-config | include hostname", "remediate_enter": "configure terminal", "remediate_exit": "end", "save": "write memory"}


def validate_config(vendor: str, cfg: str, settings: ForeScoutSettings) -> list[Finding]:
    findings: list[Finding] = []
    lower = cfg.lower()
    fs_user = settings.forescout_username.strip()
    snmp = settings.forescout_snmp.strip()

    if vendor != "HP/Aruba ProCurve" and fs_user:
        if re.search(rf"\busername\s+{re.escape(fs_user)}\b|\buser\s+{re.escape(fs_user)}\b", cfg, re.I):
            findings.append(Finding("info", "ForeScout username", "passed", "Expected ForeScout username is present."))
        else:
            findings.append(Finding("critical", "ForeScout username", "failed", "Expected ForeScout username is missing.", build_user_remediation(vendor, settings)))
    elif vendor == "HP/Aruba ProCurve":
        findings.append(Finding("info", "ForeScout username", "skipped", "ProCurve username validation is intentionally skipped."))

    if snmp:
        community_lines = [line.strip() for line in cfg.splitlines() if snmp in line and "snmp-server" in line.lower()]
        if community_lines:
            rw_lines = [line for line in community_lines if re.search(r"\b(rw|unrestricted|write)\b", line, re.I)]
            ro_lines = [line for line in community_lines if re.search(r"\b(ro|operator|restricted|read)\b", line, re.I)]
            if rw_lines:
                findings.append(Finding("critical", "SNMP RW community", "failed", "Expected SNMP community appears to be configured with RW/unrestricted access. Do not auto-remediate RW removal.", "Manual review required; no automatic removal is performed."))
            elif ro_lines or vendor in {"Ruckus ICX", "Cisco IOS", "Aruba CXOS"}:
                findings.append(Finding("info", "SNMP community", "passed", "Expected SNMP community is present and not detected as RW."))
            else:
                findings.append(Finding("warning", "SNMP community", "review", "Expected SNMP community is present but access level could not be confidently parsed."))
        else:
            findings.append(Finding("critical", "SNMP community", "failed", "Expected SNMP community is missing.", build_snmp_remediation(vendor, settings)))

    if settings.traps_required and settings.trap_hosts:
        for host in settings.trap_hosts:
            host_found = host in cfg
            snmp_found = bool(snmp and snmp in cfg)
            if host_found and snmp_found:
                findings.append(Finding("info", f"SNMP trap host {host}", "passed", "Expected trap host is present."))
            elif host_found:
                findings.append(Finding("warning", f"SNMP trap host {host}", "review", "Trap host IP is present, but community association could not be confirmed."))
            else:
                findings.append(Finding("critical", f"SNMP trap host {host}", "failed", "Expected SNMP trap host is missing.", build_trap_remediation(vendor, settings, host)))

    if vendor == "Cisco IOS":
        if "snmp-server group" in lower and "snmp-server view" in lower:
            findings.append(Finding("info", "Cisco SNMP view/group", "passed", "Cisco SNMP view/group lines detected."))
        else:
            findings.append(Finding("warning", "Cisco SNMP view/group", "review", "Cisco SNMP view/group validation did not find the expected view/group structure."))

    if vendor == "Aruba CXOS" and "central connection status" in lower:
        findings.append(Finding("info", "Aruba Central", "review", "Aruba Central status was detected. Remediation should enter support-mode if connected."))

    return findings


def build_user_remediation(vendor: str, s: ForeScoutSettings) -> str:
    if not s.forescout_username:
        return ""
    if vendor == "Aruba CXOS":
        return f"user {s.forescout_username} group administrators password <redacted>"
    return f"username {s.forescout_username} password <redacted>"


def build_snmp_remediation(vendor: str, s: ForeScoutSettings) -> str:
    if not s.forescout_snmp:
        return ""
    if vendor == "Cisco IOS":
        return "snmp-server community <redacted> view NO_BAD_SNMP RO"
    if vendor == "Aruba CXOS":
        return "snmp-server community <redacted>"
    if vendor == "HP/Aruba ProCurve":
        return "snmp-server community <redacted> operator"
    return "snmp-server community <redacted> ro"


def build_trap_remediation(vendor: str, s: ForeScoutSettings, host: str) -> str:
    if vendor == "Aruba CXOS":
        return f"snmp-server host {host} trap version v2c community <redacted>"
    if vendor == "HP/Aruba ProCurve":
        return f"snmp-server host {host} community \"<redacted>\" trap-level critical"
    if vendor == "Cisco IOS":
        return f"snmp-server host {host} version 2c <redacted>"
    return f"snmp-server host {host} version v2c <redacted> port 162"


def remediation_commands(vendor: str, findings: list[Finding], settings: ForeScoutSettings, raw: dict[str, str]) -> list[str]:
    cmds: list[str] = []
    if vendor == "Aruba CXOS" and "central connection status" in raw.get("central", "").lower() and "connected" in raw.get("central", "").lower():
        cmds.append("aruba-central support-mode")
    if any(f.check == "ForeScout username" and f.status == "failed" for f in findings) and settings.forescout_username and settings.forescout_password:
        if vendor == "Aruba CXOS":
            cmds.append(f"user {settings.forescout_username} group administrators password plaintext {settings.forescout_password}")
        elif vendor != "HP/Aruba ProCurve":
            cmds.append(f"username {settings.forescout_username} password {settings.forescout_password}")
    if any(f.check == "SNMP community" and f.status == "failed" for f in findings) and settings.forescout_snmp:
        if vendor == "Cisco IOS":
            cmds.extend(["snmp-server view NO_BAD_SNMP iso included", "snmp-server group ro v3 priv read NO_BAD_SNMP", f"snmp-server community {settings.forescout_snmp} view NO_BAD_SNMP RO"])
        elif vendor == "Aruba CXOS":
            cmds.append(f"snmp-server community {settings.forescout_snmp}")
        elif vendor == "HP/Aruba ProCurve":
            cmds.append(f"snmp-server community {settings.forescout_snmp} operator")
        else:
            cmds.append(f"snmp-server community {settings.forescout_snmp} ro")
    for host in settings.trap_hosts:
        if any(f.check == f"SNMP trap host {host}" and f.status == "failed" for f in findings) and settings.forescout_snmp:
            if vendor == "Aruba CXOS":
                cmds.append(f"snmp-server host {host} trap version v2c community {settings.forescout_snmp}")
            elif vendor == "HP/Aruba ProCurve":
                cmds.append(f"snmp-server host {host} community \"{settings.forescout_snmp}\" trap-level critical")
            elif vendor == "Cisco IOS":
                cmds.append(f"snmp-server host {host} version 2c {settings.forescout_snmp}")
            else:
                cmds.append(f"snmp-server host {host} version v2c {settings.forescout_snmp} port 162")
    return cmds


def scan_one(target: Target, username: str, password: str, settings: ForeScoutSettings, remediate: bool = False, retry: int = 1) -> DeviceResult:
    result = DeviceResult(target=f"{target.host}:{target.port}", host=target.host, port=target.port)
    for attempt in range(1, retry + 2):
        try:
            if not tcp_open(target.host, target.port):
                result.error = f"No TCP response on port {target.port}"
                return result
            with SSHSession(target.host, target.port, username, password, settings.debug) as ssh:
                result.connected = True
                ssh.prep_terminal()
                version = ssh.run("show version", wait=1.2, quiet_cycles=5)
                vendor = detect_vendor(version)
                result.vendor = vendor
                cmds = vendor_commands(vendor)
                hostname_out = ssh.run(cmds["hostname"], wait=0.8, quiet_cycles=3)
                cfg = ssh.run(cmds["run"], wait=1.4, quiet_cycles=8)
                central = ""
                if vendor == "Aruba CXOS":
                    central = ssh.run(cmds.get("central", "show aruba-central"), wait=0.8, quiet_cycles=3)
                    cfg = cfg + "\n" + central
                result.hostname = parse_hostname(hostname_out + "\n" + cfg, target.host)
                result.actual_ip = target.host
                result.raw = {"show_version": redact(version), "running_config": redact(cfg), "central": redact(central)}
                result.findings = validate_config(vendor, cfg, settings)
                failed = [f for f in result.findings if f.status == "failed"]
                result.group = "Needs Remediation" if failed else "Passed"
                if remediate and failed:
                    # Never auto-remediate detected RW community removal.
                    safe_failed = [f for f in failed if f.check != "SNMP RW community"]
                    commands = remediation_commands(vendor, safe_failed, settings, {"central": central})
                    if commands:
                        ssh.run(cmds["remediate_enter"], wait=0.4, quiet_cycles=2)
                        for cmd in commands:
                            ssh.run(cmd, wait=0.35, quiet_cycles=2)
                        ssh.run(cmds["remediate_exit"], wait=0.4, quiet_cycles=2)
                        ssh.run(cmds["save"], wait=1.0, quiet_cycles=5)
                        result.remediated = True
                return result
        except Exception as exc:
            if paramiko is not None and isinstance(exc, paramiko.AuthenticationException):
                result.error = "Authentication failed"
                return result
            result.error = safe_client_error(exc, [password], default="SSH/session error. Enable debug for details.")
            if attempt <= retry:
                time.sleep(0.8)
                continue
            return result
    return result


def update_job(job_id: str, **changes):
    with JOBS_LOCK:
        if job_id in JOBS:
            JOBS[job_id].update(changes)


def append_result(job_id: str, result: DeviceResult):
    with JOBS_LOCK:
        job = JOBS[job_id]
        job["results"].append(asdict(result))
        job["completed"] += 1


def run_job(job_id: str, targets: list[Target], username: str, password: str, settings: ForeScoutSettings, remediate: bool, threads: int, retry: int):
    update_job(job_id, status="running", started=datetime.now().isoformat(timespec="seconds"))
    try:
        with ThreadPoolExecutor(max_workers=max(1, min(25, threads))) as pool:
            futures = [pool.submit(scan_one, t, username, password, settings, remediate, retry) for t in targets]
            for fut in as_completed(futures):
                append_result(job_id, fut.result())
        update_job(job_id, status="complete", finished=datetime.now().isoformat(timespec="seconds"))
    except Exception as exc:
        update_job(job_id, status="error", error=safe_client_error(exc, [password], default="ForeScout job failed. See server log for details."))


def grouped(results: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups = {"Needs Remediation": [], "Passed": [], "Could Not Connect": []}
    for r in results:
        groups.setdefault(r.get("group", "Could Not Connect"), []).append(r)
    return groups


@router.get("", response_class=HTMLResponse)
def home(request: Request):
    settings = load_env()
    return templates.TemplateResponse("forescout.html", {
        "request": request,
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "favicon_url": FAVICON_URL,
        "settings": settings,
    })


@router.post("/scan")
def start_scan(
    targets: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    threads: int = Form(10),
    remediate: str | None = Form(None),
    retry: int = Form(1),
):
    settings = load_env()
    parsed = parse_targets(targets)
    if not parsed:
        return JSONResponse({"error": "No valid targets were provided."}, status_code=400)
    threads = max(1, min(25, int(threads or 10)))
    retry = max(0, min(3, int(retry or 1)))
    job_id = secrets.token_urlsafe(24)
    with JOBS_LOCK:
        JOBS[job_id] = {"id": job_id, "status": "queued", "total": len(parsed), "completed": 0, "results": [], "error": "", "created": datetime.now().isoformat(timespec="seconds"), "remediate": bool(remediate)}
    thread = threading.Thread(target=run_job, args=(job_id, parsed, username, password, settings, bool(remediate), threads, retry), daemon=True)
    thread.start()
    return {"job_id": job_id, "total": len(parsed)}


@router.get("/job/{job_id}")
def job_status(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return JSONResponse({"error": "Unknown job"}, status_code=404)
        payload = dict(job)
    payload["groups"] = grouped(payload.get("results", []))
    return payload


@router.get("/job/{job_id}/pdf")
def export_pdf(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return JSONResponse({"error": "Unknown job"}, status_code=404)
        payload = dict(job)
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
    except Exception:
        return JSONResponse({"error": "reportlab is not installed"}, status_code=500)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title="ForeScout Verifier Report")
    styles = getSampleStyleSheet()
    story = [Paragraph("Single Digits ForeScout Verifier", styles["Title"]), Paragraph(f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]), Spacer(1, 12)]
    results = payload.get("results", [])
    counts = grouped(results)
    summary = [["Group", "Count"], ["Needs Remediation", len(counts["Needs Remediation"])], ["Passed", len(counts["Passed"])], ["Could Not Connect", len(counts["Could Not Connect"])]]
    table = Table(summary, hAlign="LEFT")
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#174a7c")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("GRID", (0,0), (-1,-1), 0.25, colors.grey), ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold")]))
    story += [table, Spacer(1, 14)]
    for group_name, rows in counts.items():
        story.append(Paragraph(group_name, styles["Heading2"]))
        if not rows:
            story.append(Paragraph("None", styles["Normal"]))
            continue
        data = [["Target", "Vendor", "Hostname", "Findings"]]
        for r in rows:
            failed = [f for f in r.get("findings", []) if f.get("status") in {"failed", "review"}]
            detail = "; ".join(redact(f"{f.get('check')}: {f.get('detail')}") for f in failed[:4]) or "Passed"
            if r.get("error"):
                detail = redact(r.get("error"))
            data.append([r.get("target", ""), r.get("vendor", ""), r.get("hostname", ""), detail])
        t = Table(data, colWidths=[90, 90, 100, 300], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#f58220")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("GRID", (0,0), (-1,-1), 0.25, colors.grey), ("VALIGN", (0,0), (-1,-1), "TOP"), ("FONTSIZE", (0,0), (-1,-1), 8)]))
        story += [t, Spacer(1, 12)]
    doc.build(story)
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=forescout_verifier_{job_id}.pdf"})
