from __future__ import annotations

import json
import threading
import time
import secrets
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Body, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates

from .lib.exporters import merge_project, ncm_ai_export, port_sheet_tsv, salesforce_preview_export, zabbix_preview_export
from .lib.pdf_report import build_asbuilt_pdf
from .lib.scanner import scan_topology
from shared.security.redaction import safe_client_error, redact_text

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
router = APIRouter(prefix="/apps/topology", tags=["Topology"])

_LOCK = threading.Lock()
_JOBS: Dict[str, Dict[str, Any]] = {}
_LAST_SCAN: Dict[str, Any] = {}
_LAST_MANUAL: Dict[str, Any] = {}

DEFAULT_FORM = {
    "targets": "",
    "username": "",
    "timeout": 20,
    "port": 22,
    "concurrency": 10,
    "include_aps": False,
    "include_all_devices": False,
}


def empty_project() -> Dict[str, Any]:
    return {
        "schema": "single_digits.topology_asbuilt.v1",
        "generated_at": "",
        "site": {},
        "scan_settings": {},
        "devices": [],
        "links": [],
        "ports": [],
        "raw_neighbors": [],
        "topology_tree": [],
        "summary": {"devices": 0, "switches": 0, "links": 0, "ports": 0, "raw_neighbors": 0},
        "isp_circuits": [],
        "manual_firewalls": [],
        "manual_gateways": [],
        "manual_esxi_hosts": [],
        "manual_pga_interfaces": [],
        "manual_rpm_vms": [],
        "vlans": [],
        "manual_links": [],
        "documentation_checklist": {},
        "revision_history": [],
    }


def current_project() -> Dict[str, Any]:
    with _LOCK:
        return merge_project(_LAST_SCAN or empty_project(), _LAST_MANUAL or {})


@router.get("/static/{path:path}")
async def topology_static(path: str):
    file_path = (BASE_DIR / "static" / path).resolve()
    static_root = (BASE_DIR / "static").resolve()
    if not str(file_path).startswith(str(static_root)) or not file_path.exists() or not file_path.is_file():
        return JSONResponse({"ok": False, "error": "Static file not found."}, status_code=404)
    return FileResponse(str(file_path))


@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def topology_home(request: Request):
    return templates.TemplateResponse("topology.html", {"request": request, "project": current_project(), "form": DEFAULT_FORM})


@router.post("/scan/start")
async def start_scan(
    targets: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    timeout: int = Form(20),
    port: int = Form(22),
    concurrency: int = Form(10),
    include_aps: bool = Form(False),
    include_all_devices: bool = Form(False),
):
    if not targets.strip() or not username.strip() or not password:
        return JSONResponse({"ok": False, "error": "Targets, username, and password are required to scan."}, status_code=400)
    concurrency = max(1, min(int(concurrency or 10), 25))
    job_id = secrets.token_urlsafe(24)
    with _LOCK:
        _JOBS[job_id] = {"state": "queued", "logs": ["Topology scan queued."], "data": empty_project(), "error": "", "started_at": time.time()}

    def emit(message: str) -> None:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with _LOCK:
            if job_id in _JOBS:
                _JOBS[job_id].setdefault("logs", []).append(f"{stamp} | {message}")

    def worker() -> None:
        global _LAST_SCAN
        try:
            with _LOCK:
                _JOBS[job_id]["state"] = "running"
            result = scan_topology(
                targets=targets,
                username=username,
                password=password,
                timeout=timeout,
                port=port,
                concurrency=concurrency,
                include_aps=include_aps,
                include_all_devices=include_all_devices,
                log_callback=emit,
            )
            with _LOCK:
                _LAST_SCAN = result.data
                _JOBS[job_id]["state"] = "complete"
                _JOBS[job_id]["data"] = merge_project(_LAST_SCAN, _LAST_MANUAL)
                _JOBS[job_id]["finished_at"] = time.time()
        except Exception as exc:
            with _LOCK:
                _JOBS[job_id]["state"] = "error"
                _JOBS[job_id]["error"] = safe_client_error(exc, [password], default="Topology scan failed. See server log for details.")
                _JOBS[job_id].setdefault("logs", []).append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | ERROR | Topology scan failed.")

    threading.Thread(target=worker, daemon=True).start()
    return {"ok": True, "job_id": job_id}


@router.get("/scan/status/{job_id}")
async def scan_status(job_id: str):
    with _LOCK:
        job = dict(_JOBS.get(job_id) or {})
    if not job:
        return JSONResponse({"ok": False, "error": "Unknown scan job."}, status_code=404)
    return {"ok": True, **job}


@router.post("/project/manual")
async def save_manual_data(payload: Dict[str, Any] = Body(default_factory=dict)):
    global _LAST_MANUAL
    with _LOCK:
        _LAST_MANUAL = payload or {}
        project = merge_project(_LAST_SCAN or empty_project(), _LAST_MANUAL)
    return {"ok": True, "project": project}


@router.get("/data")
async def get_data():
    return JSONResponse(current_project())


@router.post("/export/project-json")
async def export_project_json(payload: Dict[str, Any] = Body(default_factory=dict)):
    project = merge_project(current_project(), payload or {})
    return JSONResponse(project, headers={"Content-Disposition": "attachment; filename=single_digits_asbuilt_project.json"})


@router.post("/export/ncm-ai-json")
async def export_ncm(payload: Dict[str, Any] = Body(default_factory=dict)):
    project = merge_project(current_project(), payload or {})
    return JSONResponse(ncm_ai_export(project), headers={"Content-Disposition": "attachment; filename=single_digits_ncm_ai_topology.json"})


@router.post("/export/salesforce-preview")
async def export_salesforce(payload: Dict[str, Any] = Body(default_factory=dict)):
    project = merge_project(current_project(), payload or {})
    return JSONResponse(salesforce_preview_export(project), headers={"Content-Disposition": "attachment; filename=single_digits_salesforce_preview.json"})


@router.post("/export/zabbix-preview")
async def export_zabbix(payload: Dict[str, Any] = Body(default_factory=dict)):
    project = merge_project(current_project(), payload or {})
    return JSONResponse(zabbix_preview_export(project), headers={"Content-Disposition": "attachment; filename=single_digits_zabbix_preview.json"})


@router.post("/export/port-sheet.tsv")
async def export_ports(payload: Dict[str, Any] = Body(default_factory=dict)):
    project = merge_project(current_project(), payload or {})
    return Response(port_sheet_tsv(project), media_type="text/tab-separated-values; charset=utf-8", headers={"Content-Disposition": "attachment; filename=single_digits_port_sheet.tsv"})


@router.post("/export/asbuilt-pdf")
async def export_pdf(payload: Dict[str, Any] = Body(default_factory=dict)):
    project = merge_project(current_project(), payload or {})
    pdf_bytes = build_asbuilt_pdf(project)
    return Response(pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=single_digits_asbuilt_topology.pdf"})


# Compatibility GET endpoints for older buttons/bookmarks. These export the latest server-side project.
@router.get("/export/json")
async def export_project_get():
    return JSONResponse(current_project(), headers={"Content-Disposition": "attachment; filename=single_digits_asbuilt_project.json"})


@router.get("/export/port-sheet.tsv")
async def export_ports_get():
    return Response(port_sheet_tsv(current_project()), media_type="text/tab-separated-values; charset=utf-8", headers={"Content-Disposition": "attachment; filename=single_digits_port_sheet.tsv"})
