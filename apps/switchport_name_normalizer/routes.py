from __future__ import annotations

import csv
import io
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any
import secrets

from shared.security.redaction import safe_client_error
from fastapi import APIRouter, Form, HTTPException, Request
from shared.security.redaction import safe_client_error
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from shared.security.redaction import safe_client_error
from fastapi.templating import Jinja2Templates

from .core import (
    DEFAULT_SSH_PORT,
    MAX_HOSTS,
    VENDOR_LABELS,
    PortRow,
    build_rename_commands,
    compact_push_commands,
    parse_targets,
    scan_switch,
)

MODULE_NAME = "Switchport Name Normalizer"
MODULE_VERSION = "0.3.0-alpha"
MOUNT = "/apps/switchport-normalizer"
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))

router = APIRouter(prefix=MOUNT, tags=[MODULE_NAME])

jobs: dict[str, dict[str, Any]] = {}
jobs_lock = threading.Lock()


def redact(value: str) -> str:
    return "********" if value else ""


def log(job: dict[str, Any], message: str) -> None:
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    job.setdefault("logs", []).append(f"[{stamp}] {message}")
    job["logs"] = job["logs"][-800:]


def flatten_rows(job: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for result in job.get("results", []):
        for row in result.get("rows", []):
            rows.append(row)
    return rows


def row_key(row: dict[str, Any]) -> str:
    return f"{row.get('switch_ip','')}|{row.get('local_port','')}|{row.get('suggested_name','')}"


def run_scan_job(job_id: str) -> None:
    with jobs_lock:
        job = jobs[job_id]
    job["status"] = "running"
    targets = job["targets"]
    log(job, f"Starting scan against {len(targets)} target(s).")
    max_workers = max(1, min(int(job.get("concurrency", 10)), 25))
    results: list[dict[str, Any]] = []
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(scan_switch, host, port, job["username"], job["password"], job.get("vendor", "auto")): (host, port)
                for host, port in targets
            }
            for future in as_completed(futures):
                host, port = futures[future]
                try:
                    result = future.result()
                    result_dict = asdict(result)
                    results.append(result_dict)
                    if result.success:
                        actionable = sum(1 for r in result_dict.get("rows", []) if r.get("status") in {"new", "change"})
                        log(job, f"{host}: {result.vendor} / {result.hostname}; {len(result.rows)} port row(s), {actionable} actionable rename(s).")
                    else:
                        log(job, f"{host}: failed - {result.error}")
                except Exception as exc:
                    results.append({"target": host, "port": port, "success": False, "error": safe_client_error(exc), "rows": []})
                    log(job, f"{host}: failed - {exc}")
        job["results"] = sorted(results, key=lambda r: (r.get("hostname") or r.get("target") or ""))
        job["status"] = "complete"
        total_rows = len(flatten_rows(job))
        total_actionable = sum(1 for r in flatten_rows(job) if r.get("status") in {"new", "change"})
        log(job, f"Scan complete. {total_rows} total port row(s), {total_actionable} proposed rename(s).")
    except Exception as exc:
        job["status"] = "failed"
        job["error"] = safe_client_error(exc)
        log(job, f"Job failed: {exc}")


@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return TEMPLATES.TemplateResponse(
        "index.html",
        {
            "request": request,
            "module_name": MODULE_NAME,
            "module_version": MODULE_VERSION,
            "mount": MOUNT,
            "vendors": VENDOR_LABELS,
            "default_ssh_port": DEFAULT_SSH_PORT,
            "max_hosts": MAX_HOSTS,
        },
    )


@router.post("/scan")
def start_scan(
    targets: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    vendor: str = Form("auto"),
    concurrency: int = Form(10),
) -> JSONResponse:
    parsed = parse_targets(targets, DEFAULT_SSH_PORT)
    if not parsed:
        raise HTTPException(status_code=400, detail="Enter at least one switch IP, IP:port, or CIDR subnet.")
    job_id = secrets.token_urlsafe(24)
    job = {
        "job_id": job_id,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "queued",
        "targets": parsed,
        "username": username.strip(),
        "password": password,
        "vendor": vendor,
        "concurrency": max(1, min(int(concurrency or 10), 25)),
        "logs": [],
        "results": [],
        "push_logs": [],
    }
    log(job, f"Created job. Username={username.strip()} Password={redact(password)} Vendor={vendor}.")
    with jobs_lock:
        jobs[job_id] = job
    threading.Thread(target=run_scan_job, args=(job_id,), daemon=True).start()
    return JSONResponse({"job_id": job_id, "url": f"{MOUNT}/job/{job_id}"})


@router.get("/job/{job_id}", response_class=HTMLResponse)
def job_page(request: Request, job_id: str) -> HTMLResponse:
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return TEMPLATES.TemplateResponse("job.html", {"request": request, "job": job, "mount": MOUNT, "module_name": MODULE_NAME})


@router.get("/api/job/{job_id}")
def job_status(job_id: str) -> JSONResponse:
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    safe = {k: v for k, v in job.items() if k not in {"password"}}
    safe["summary"] = {
        "switches": len(job.get("results", [])),
        "rows": len(flatten_rows(job)),
        "actionable": sum(1 for r in flatten_rows(job) if r.get("status") in {"new", "change"}),
        "failed": sum(1 for r in job.get("results", []) if not r.get("success")),
    }
    return JSONResponse(safe)


@router.post("/api/job/{job_id}/push")
def push_selected(job_id: str, selected_keys: str = Form(...), proposed_overrides: str = Form("{}")) -> JSONResponse:
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    try:
        selected = set(json.loads(selected_keys))
        overrides = json.loads(proposed_overrides or "{}")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid selection payload: {exc}") from exc

    by_switch: dict[str, list[PortRow]] = {}
    for row in flatten_rows(job):
        key = row_key(row)
        if key not in selected:
            continue
        if key in overrides and overrides[key].strip():
            row["suggested_name"] = overrides[key].strip()
        if not row.get("suggested_name"):
            continue
        by_switch.setdefault(row["switch_ip"], []).append(PortRow(**{k: row.get(k, "") for k in PortRow.__dataclass_fields__.keys()}))

    # Alpha 0.7.5 safety: compile commands and record the intended push. The actual SSH execution hook is isolated here
    # so the shared/ssh.py module can be swapped in when this is folded into the main shell.
    push_plan: list[dict[str, Any]] = []
    for switch_ip, rows in by_switch.items():
        push_plan.append({"switch_ip": switch_ip, "commands": compact_push_commands(rows), "rows": [asdict(r) for r in rows]})
    job["push_logs"].append({"at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "mode": "preview_only_alpha", "plan": push_plan})
    log(job, f"Prepared push plan for {sum(len(v) for v in by_switch.values())} selected row(s). Actual SSH push is intentionally disabled in Alpha 0.7.5 until shared SSH is wired in.")
    return JSONResponse({"mode": "preview_only_alpha", "push_plan": push_plan})


@router.get("/api/job/{job_id}/commands.txt")
def download_commands(job_id: str) -> PlainTextResponse:
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    lines: list[str] = []
    for result in job.get("results", []):
        actionable = [PortRow(**{k: r.get(k, "") for k in PortRow.__dataclass_fields__.keys()}) for r in result.get("rows", []) if r.get("status") in {"new", "change"}]
        if not actionable:
            continue
        lines.append(f"! {result.get('hostname') or result.get('target')} ({result.get('target')}) - {result.get('vendor')}")
        lines.extend(compact_push_commands(actionable))
        lines.append("")
    return PlainTextResponse("\n".join(lines) or "# No actionable commands generated.")


@router.get("/api/job/{job_id}/export.csv")
def export_csv(job_id: str) -> StreamingResponse:
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Switch Name", "Local Port ID", "Local Port Name", "Patch Panel Port", "Remote Hostname", "Remote IP", "Suggested Port Name", "Switch IP", "Vendor", "Link State", "Remote Port", "Remote Type", "Status", "Reason"])
    for row in flatten_rows(job):
        writer.writerow([
            row.get("switch_name", ""), row.get("local_port", ""), row.get("current_name", ""), row.get("patch_panel_port", ""), row.get("neighbor_hostname", ""), row.get("neighbor_ip", ""), row.get("suggested_name", ""), row.get("switch_ip", ""), row.get("vendor", ""), row.get("link_state", ""), row.get("neighbor_port", ""), row.get("neighbor_type", ""), row.get("status", ""), row.get("reason", ""),
        ])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=switchport_name_normalizer_{job_id}.csv"})

@router.get("/api/job/{job_id}/export.tsv")
def export_tsv(job_id: str) -> StreamingResponse:
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    output = io.StringIO()
    writer = csv.writer(output, delimiter="\t", lineterminator="\n")
    writer.writerow(["Switch Name", "Local Port ID", "Local Port Name", "Patch Panel Port", "Remote Hostname", "Remote IP", "Suggested Port Name"])
    for row in flatten_rows(job):
        writer.writerow([
            row.get("switch_name", ""),
            row.get("local_port", ""),
            row.get("current_name", ""),
            row.get("patch_panel_port", ""),
            row.get("neighbor_hostname", ""),
            row.get("neighbor_ip", ""),
            row.get("suggested_name", ""),
        ])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/tab-separated-values", headers={"Content-Disposition": f"attachment; filename=switchport_name_normalizer_{job_id}.tsv"})



@router.get("/health")
def health() -> dict[str, str]:
    return {"app": MODULE_NAME, "version": MODULE_VERSION, "status": "ok"}
