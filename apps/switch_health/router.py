from __future__ import annotations

import json
from dataclasses import asdict
from fastapi import APIRouter, BackgroundTasks, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from .scanner import engine, parse_targets
from .commands import available_command_sets, DEFAULT_COMMAND_SETS, COMMANDS_BY_SET, COMMAND_SET_LABELS

router = APIRouter(prefix="/apps/switch-health", tags=["Switch Health"])
templates = Jinja2Templates(directory="apps/switch_health/templates")

APP_TITLE = "Switch Health"


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("switch_health_index.html", {"request": request, "jobs": engine.list_jobs(), "app_title": APP_TITLE, "command_sets": available_command_sets()})


@router.post("/scan")
def start_scan(
    background_tasks: BackgroundTasks,
    targets: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    port: int = Form(22),
    concurrency: int = Form(10),
    timeout: int = Form(12),
    show_tech: bool = Form(False),
    debug: bool = Form(False),
    cable_ports: str = Form(""),
    command_sets: list[str] = Form(DEFAULT_COMMAND_SETS),
):
    parsed = parse_targets(targets, default_port=port)
    if not parsed:
        raise HTTPException(status_code=400, detail="No targets provided")
    opts = {
        "username": username,
        "password": password,
        "port": port,
        "concurrency": concurrency,
        "timeout": timeout,
        "show_tech": show_tech,
        "debug": debug,
        "cable_ports": cable_ports,
        "command_sets": command_sets or DEFAULT_COMMAND_SETS,
    }
    job = engine.create_job(parsed, opts)
    background_tasks.add_task(engine.run_job, job.job_id)
    return RedirectResponse(url=f"/apps/switch-health/job/{job.job_id}", status_code=303)


@router.get("/job/{job_id}", response_class=HTMLResponse)
def job_view(request: Request, job_id: str):
    job = engine.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return templates.TemplateResponse("switch_health_job.html", {"request": request, "job": job, "app_title": APP_TITLE})


@router.get("/job/{job_id}.json")
def job_json(job_id: str):
    job = engine.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    clean = asdict(job)
    if "password" in clean.get("options", {}):
        clean["options"]["password"] = "REDACTED"
    return JSONResponse(clean)


@router.get("/job/{job_id}/raw/{target:path}", response_class=PlainTextResponse)
def raw_output(job_id: str, target: str):
    job = engine.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    for res in job.results:
        if res.target == target or res.host == target:
            return "\n\n".join([f"===== {cmd} =====\n{out}" for cmd, out in res.raw.items()])
    raise HTTPException(status_code=404, detail="Target not found")


@router.get("/api/command-sets")
def command_sets_api():
    return {
        "labels": COMMAND_SET_LABELS,
        "defaults": DEFAULT_COMMAND_SETS,
        "platforms": COMMANDS_BY_SET,
    }


def register(app):
    app.include_router(router)
