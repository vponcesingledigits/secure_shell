from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from .exporters import export_excel, export_json, export_pdf
from .scanner import load_job, push_renames, run_scan, save_job

BASE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE / "templates"))
router = APIRouter(prefix="/apps/port-map", tags=["Port Map"])

LAST_JOB: Dict[str, Any] = {"job_id": "none", "switches": [], "targets": []}
LAST_STATUS: Dict[str, Any] = {
    "job_id": "none",
    "state": "idle",
    "current_device": "",
    "current_command": "Idle",
    "devices_scanned": 0,
    "neighbors_found": 0,
    "queue_remaining": 0,
    "last_result": "No scan running.",
    "elapsed_seconds": 0,
}


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("port_map.html", {"request": request, "job": LAST_JOB})


@router.post("/scan")
async def scan(
    targets: str = Form(...),
    username: str = Form(""),
    password: str = Form(""),
    subnet_only: bool = Form(False),
    include_macs: bool = Form(True),
    concurrency: int = Form(10),
):
    global LAST_JOB, LAST_STATUS
    LAST_STATUS = {
        "job_id": "starting",
        "state": "running",
        "current_device": "",
        "current_command": "Starting",
        "devices_scanned": 0,
        "neighbors_found": 0,
        "queue_remaining": 0,
        "last_result": "Scan request received.",
        "elapsed_seconds": 0,
    }

    def update_status(payload: Dict[str, Any]) -> None:
        global LAST_STATUS
        LAST_STATUS = {**LAST_STATUS, **payload}

    LAST_JOB = await run_scan(
        targets,
        username,
        password,
        subnet_only=subnet_only,
        include_macs=include_macs,
        concurrency=concurrency,
        status_cb=update_status,
    )
    LAST_STATUS = {**LAST_STATUS, "state": "complete", "job_id": LAST_JOB.get("job_id", "complete")}
    return JSONResponse(LAST_JOB)


@router.get("/status")
async def scan_status():
    return JSONResponse(LAST_STATUS)


@router.post("/load-json")
async def load_json(payload: Dict[str, Any]):
    global LAST_JOB, LAST_STATUS
    if "job_id" not in payload:
        payload["job_id"] = "uploaded"
    LAST_JOB = payload
    save_job(str(payload["job_id"]), payload)
    LAST_STATUS = {
        "job_id": LAST_JOB.get("job_id", "uploaded"),
        "state": "complete",
        "current_device": "",
        "current_command": "Loaded JSON",
        "devices_scanned": len(LAST_JOB.get("switches", [])),
        "neighbors_found": sum(len(sw.get("ports", [])) for sw in LAST_JOB.get("switches", [])),
        "queue_remaining": 0,
        "last_result": "Imported previous JSON successfully.",
        "elapsed_seconds": 0,
    }
    return JSONResponse({"ok": True, "job_id": LAST_JOB["job_id"]})


@router.get("/job/{job_id}")
async def get_job(job_id: str):
    return JSONResponse(load_job(job_id))


@router.post("/rename-preview")
async def rename_preview(payload: Dict[str, Any]):
    selected = payload.get("selected", [])
    return JSONResponse(await push_renames(LAST_JOB, selected, username="", password="", dry_run=True))


@router.post("/rename-push")
async def rename_push(payload: Dict[str, Any]):
    selected = payload.get("selected", [])
    username = payload.get("username", "")
    password = payload.get("password", "")
    return JSONResponse(await push_renames(LAST_JOB, selected, username=username, password=password, dry_run=False))


@router.get("/export/json")
async def export_job_json():
    return FileResponse(export_json(LAST_JOB), filename=f"port_map_{LAST_JOB.get('job_id','export')}.json")


@router.get("/export/excel")
async def export_job_excel():
    return FileResponse(export_excel(LAST_JOB), filename=f"port_map_{LAST_JOB.get('job_id','export')}.xlsx")


@router.get("/export/pdf")
async def export_job_pdf():
    return FileResponse(export_pdf(LAST_JOB), filename=f"port_map_executive_{LAST_JOB.get('job_id','export')}.pdf")
