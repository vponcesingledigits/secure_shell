from __future__ import annotations

import json
from typing import Dict, List, Optional, Sequence

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from shared.investigation import (
    TraceTarget,
    analyze_path_health,
    parse_target,
    render_path_summary,
    trace_mac_path,
)

router = APIRouter(prefix="/apps/traffic-analyzer", tags=["Traffic Analyzer"])
templates = Jinja2Templates(directory="apps/traffic_analyzer/templates")


def _split_targets(value: str) -> List[str]:
    targets = []
    for chunk in (value or "").replace(",", "\n").splitlines():
        item = chunk.strip()
        if item:
            targets.append(item)
    return targets


def _shared_runner_placeholder(target_ip: str, commands: Sequence[str], vendor: Optional[str] = None) -> Dict[str, str]:
    """Adapter point.

    Replace this with your existing shared/ssh.py session runner. This route is intentionally
    built around shared.investigation so MAC Trace and Traffic Analyzer use the same locate logic.

    Expected real implementation pattern:
        return shared.ssh.run_commands(target_ip, commands, vendor=vendor, ...)
    """
    raise RuntimeError(
        "Traffic Analyzer route is scaffolded. Wire _shared_runner_placeholder() to shared/ssh.py run_commands/session manager."
    )


@router.get("/", response_class=HTMLResponse)
def page(request: Request):
    return templates.TemplateResponse(
        "traffic_analyzer.html",
        {
            "request": request,
            "title": "Traffic Analyzer",
            "result": None,
            "error": None,
        },
    )


@router.post("/scan", response_class=HTMLResponse)
def scan(
    request: Request,
    targets: str = Form(...),
    mac: str = Form(""),
    ip: str = Form(""),
    vlan: str = Form(""),
    mode: str = Form("traffic_quick"),
    max_hops: int = Form(8),
):
    try:
        target = parse_target(mac=mac, ip=ip, vlan=vlan)
        path = trace_mac_path(
            seed_targets=_split_targets(targets),
            runner=_shared_runner_placeholder,
            target=target,
            mode=mode,
            max_hops=max_hops,
        )
        findings = analyze_path_health(path, mode=mode)
        result = path.to_dict()
        result["findings"] = [f.__dict__ for f in findings]
        result["path_summary"] = render_path_summary(path)
        return templates.TemplateResponse(
            "traffic_analyzer.html",
            {"request": request, "title": "Traffic Analyzer", "result": result, "error": None},
        )
    except Exception as exc:
        return templates.TemplateResponse(
            "traffic_analyzer.html",
            {"request": request, "title": "Traffic Analyzer", "result": None, "error": str(exc)},
        )


@router.post("/api/scan")
def api_scan(
    targets: str = Form(...),
    mac: str = Form(""),
    ip: str = Form(""),
    vlan: str = Form(""),
    mode: str = Form("traffic_quick"),
    max_hops: int = Form(8),
):
    target = parse_target(mac=mac, ip=ip, vlan=vlan)
    path = trace_mac_path(
        seed_targets=_split_targets(targets),
        runner=_shared_runner_placeholder,
        target=target,
        mode=mode,
        max_hops=max_hops,
    )
    payload = path.to_dict()
    payload["path_summary"] = render_path_summary(path)
    return JSONResponse(payload)


@router.post("/api/export-json")
def export_json(payload: str = Form(...)):
    return PlainTextResponse(payload, media_type="application/json")
