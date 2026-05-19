
from __future__ import annotations

from datetime import datetime
from pathlib import Path
import json
import secrets

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from jinja2 import ChoiceLoader, FileSystemLoader

from app.config import APP_NAME, APP_VERSION, FAVICON_URL
from shared.core.paths import platform_data_root
from shared.monitoring import run_down_device_troubleshooter

router = APIRouter(prefix="/apps/monitoring", tags=["monitoring"])
templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")
templates.env.loader = ChoiceLoader([
    FileSystemLoader(str(Path(__file__).resolve().parent / "templates")),
    FileSystemLoader(str(Path(__file__).resolve().parents[2] / "app" / "templates")),
])

DATA_DIR = platform_data_root() / "Monitoring"
RUNS_DIR = DATA_DIR / "runs"
RUNS_DIR.mkdir(parents=True, exist_ok=True)
SESSION_LOG: list[dict[str, str]] = []


def add_event(category: str, message: str, details: str = "") -> None:
    SESSION_LOG.append({
        "when": datetime.now().isoformat(timespec="seconds"),
        "category": category,
        "message": message,
        "details": details,
    })
    del SESSION_LOG[:-200]


def ctx(request: Request, **kwargs):
    base = {
        "request": request,
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "favicon_url": FAVICON_URL,
        "module_name": "Monitoring Tool",
        "module_version": "Alpha 0.7.5",
    }
    base.update(kwargs)
    return base


@router.get("", response_class=HTMLResponse)
def monitoring_home(request: Request):
    recent_runs = []
    for path in sorted(RUNS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:10]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            recent_runs.append(data)
        except Exception:
            continue
    return templates.TemplateResponse("monitoring.html", ctx(request, events=list(reversed(SESSION_LOG[-10:])), recent_runs=recent_runs))


@router.get("/down-device", response_class=HTMLResponse)
def down_device_form(request: Request):
    return templates.TemplateResponse("down_device.html", ctx(request, input_values=None, result=None, run_id=None))


@router.post("/down-device", response_class=HTMLResponse)
def down_device_run(
    request: Request,
    down_device_ip: str = Form(""),
    down_device_mac: str = Form(""),
    down_device_hostname: str = Form(""),
    parent_ip: str = Form(...),
    parent_username: str = Form(...),
    parent_password: str = Form(...),
    is_access_point: str | None = Form(None),
    debug: str | None = Form(None),
):
    input_values = {
        "down_device_ip": down_device_ip,
        "down_device_mac": down_device_mac,
        "down_device_hostname": down_device_hostname,
        "parent_ip": parent_ip,
        "parent_username": parent_username,
        "is_access_point": bool(is_access_point),
        "debug": bool(debug),
    }
    result_obj = run_down_device_troubleshooter(
        parent_ip=parent_ip,
        username=parent_username,
        password=parent_password,
        down_device_ip=down_device_ip,
        down_device_mac=down_device_mac,
        down_device_hostname=down_device_hostname,
        is_access_point=bool(is_access_point),
        debug=bool(debug),
    )
    result = result_obj.to_dict()
    run_id = secrets.token_urlsafe(24)
    saved = {
        "run_id": run_id,
        "type": "down-device",
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "input": input_values,
        "result": result,
    }
    (RUNS_DIR / f"{run_id}.json").write_text(json.dumps(saved, indent=2), encoding="utf-8")
    add_event("down-device", f"Ran down-device troubleshooting against {parent_ip}", f"status={result.get('status')} port={result.get('identified_port') or 'unknown'}")
    return templates.TemplateResponse("down_device.html", ctx(request, input_values=input_values, result=result, run_id=run_id))


@router.get("/session-log", response_class=HTMLResponse)
def session_log(request: Request):
    return templates.TemplateResponse("session_log.html", ctx(request, events=list(reversed(SESSION_LOG[-100:]))))


@router.get("/runs/{run_id}", response_class=HTMLResponse)
def run_detail(request: Request, run_id: str):
    path = RUNS_DIR / f"{run_id}.json"
    if not path.exists():
        return templates.TemplateResponse("job_detail.html", ctx(request, run=None, error="Run not found"), status_code=404)
    run = json.loads(path.read_text(encoding="utf-8"))
    return templates.TemplateResponse("job_detail.html", ctx(request, run=run, error=None))


@router.get("/export/{run_id}.json")
def export_run(run_id: str):
    path = RUNS_DIR / f"{run_id}.json"
    if not path.exists():
        return JSONResponse({"error": "Run not found"}, status_code=404)
    return JSONResponse(json.loads(path.read_text(encoding="utf-8")))


@router.get("/health-summary", response_class=HTMLResponse)
def health_summary(request: Request):
    runs = []
    for path in sorted(RUNS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            runs.append(json.loads(path.read_text(encoding="utf-8")))
        except Exception:
            pass
    counts: dict[str, int] = {}
    cause_counts: dict[str, int] = {}
    for run in runs:
        result = run.get("result", {})
        vendor = result.get("parent_vendor") or "Unknown"
        counts[vendor] = counts.get(vendor, 0) + 1
        status = result.get("status") or "Unknown"
        cause_counts[status] = cause_counts.get(status, 0) + 1
    return templates.TemplateResponse("health_summary.html", ctx(request, runs=runs[:50], counts=counts, cause_counts=cause_counts))
