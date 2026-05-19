
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates

from .smartzone_client import (
    SmartZoneClient,
    build_evidence_zip,
    load_api_profiles,
    extract_mac_trace_records,
    normalize_mac,
    redact,
    summarize_findings,
)

router = APIRouter()
templates = Jinja2Templates(directory="apps/smartzone_ap_investigator/templates")

LAST_RESULTS: Dict[str, Any] = {}


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("smartzone_ap_investigator.html", {"request": request, "api_profiles": load_api_profiles().get("profiles", [])})


@router.post("/parse-mac-trace")
async def parse_mac_trace(file: UploadFile = File(...)):
    content = await file.read()
    records = extract_mac_trace_records(content, file.filename or "")
    return JSONResponse({"records": records})


@router.post("/investigate")
async def investigate(
    request: Request,
    controller_url: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    api_version: str = Form("v11_1"),
    profile_id: str = Form("vszh-6.1.2"),
    verify_ssl: str = Form("false"),
    domain_id: str = Form(""),
    zone_id: str = Form(""),
    ap_mac: str = Form(""),
    ap_name: str = Form(""),
    ap_ip: str = Form(""),
    client_mac: str = Form(""),
    download_support_log: str = Form("false"),
):
    client = SmartZoneClient(
        base_url=controller_url,
        username=username,
        password=password,
        api_version=api_version or "v11_1",
        profile_id=profile_id or "vszh-6.1.2",
        verify_ssl=verify_ssl.lower() == "true",
        debug=False,
    )

    login = client.login()
    support_log_bytes: Optional[bytes] = None

    if not login.ok:
        payload = {
            "ok": False,
            "error": login.error or "SmartZone login failed.",
            "login": redact(login.data),
            "transcript": redact(client.transcript),
        }
        return JSONResponse(payload, status_code=400)

    target_search = normalize_mac(ap_mac) if ap_mac else ap_name or ap_ip
    ap_query = client.query_aps(target_search, domain_id, zone_id)
    ap_summary = client.get_ap_summary(ap_mac) if ap_mac else {"note": "AP MAC not supplied; operational summary requires AP MAC."}
    ap_config = client.get_ap_config(ap_mac) if ap_mac else {"note": "AP MAC not supplied; AP config lookup requires AP MAC."}

    client_query = client.query_clients(client_mac=client_mac, ap_mac=ap_mac, domain_id=domain_id, zone_id=zone_id) if client_mac else {"note": "No client MAC supplied."}

    # Search alarms/events with the most precise term available first. The UI still surfaces raw output so false negatives are visible.
    search_terms = [x for x in [normalize_mac(client_mac), normalize_mac(ap_mac), ap_name, ap_ip] if x]
    alert_search = " ".join(search_terms[:2]) if search_terms else target_search
    alarms = client.query_alerts("alarm", alert_search, domain_id, zone_id)
    events = client.query_alerts("event", alert_search, domain_id, zone_id)

    if download_support_log.lower() == "true" and ap_mac:
        slog = client.download_support_log(ap_mac)
        if slog.ok and isinstance(slog.data, (bytes, bytearray)):
            support_log_bytes = bytes(slog.data)

    payload: Dict[str, Any] = {
        "ok": True,
        "target": {
            "ap_name": ap_name,
            "ap_ip": ap_ip,
            "ap_mac": normalize_mac(ap_mac),
            "client_mac": normalize_mac(client_mac),
        },
        "api": {
            "controller_url": controller_url,
            "api_version": client.api_version,
            "profile_id": profile_id,
            "active_prefix": client.active_prefix,
            "domain_id": domain_id,
            "zone_id": zone_id,
        },
        "findings": summarize_findings(
            data_of(ap_summary),
            data_of(ap_config),
            data_of(client_query),
            data_of(alarms),
            data_of(events),
            client_mac,
        ),
        "ap_query": result_to_dict(ap_query),
        "ap_summary": result_to_dict(ap_summary),
        "ap_config": result_to_dict(ap_config),
        "client_query": result_to_dict(client_query),
        "alarms": result_to_dict(alarms),
        "events": result_to_dict(events),
        "support_log_downloaded": bool(support_log_bytes),
        "transcript": redact(client.transcript),
    }

    LAST_RESULTS["latest"] = payload
    LAST_RESULTS["support_log"] = support_log_bytes
    return JSONResponse(redact(payload))


@router.get("/download/latest")
async def download_latest():
    payload = LAST_RESULTS.get("latest")
    if not payload:
        return JSONResponse({"error": "No investigation has been run yet."}, status_code=404)
    zip_bytes = build_evidence_zip(payload, LAST_RESULTS.get("support_log"))
    return Response(
        zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="smartzone_ap_investigation.zip"'},
    )


def data_of(obj: Any) -> Any:
    return obj.data if hasattr(obj, "data") else obj


def result_to_dict(obj: Any) -> Dict[str, Any]:
    if hasattr(obj, "ok"):
        return {
            "ok": obj.ok,
            "status_code": obj.status_code,
            "endpoint": obj.endpoint,
            "error": obj.error,
            "data": redact(obj.data),
        }
    return {"ok": True, "data": redact(obj)}
