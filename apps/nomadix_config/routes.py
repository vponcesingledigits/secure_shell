from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from .model_engine import (
    analyze_baseline_zip,
    compose_desired_config,
    create_config_export_zip,
    expected_file_manifest,
    get_profile,
    get_sftp_pull_zip,
    load_model,
    main_configuration_schema,
    model_summary,
    pull_baseline_via_sftp,
)

router = APIRouter()
MODULE_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(MODULE_DIR / "templates"))


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return TEMPLATES.TemplateResponse("nomadix_config/index.html", {"request": request})


@router.get("/api/model")
async def api_model():
    return JSONResponse(load_model())


@router.get("/api/model/summary")
async def api_model_summary():
    return JSONResponse(model_summary())




@router.get("/api/files/expected")
async def api_expected_files():
    return JSONResponse(expected_file_manifest())


@router.get("/api/main-config/schema")
async def api_main_config_schema():
    return JSONResponse(main_configuration_schema())

@router.get("/api/profiles")
async def api_profiles():
    summary = model_summary()
    return JSONResponse({"profiles": summary["profiles"], "selector": summary.get("profile_selector", {})})


@router.get("/api/profiles/{profile_id}")
async def api_profile(profile_id: str):
    try:
        return JSONResponse(get_profile(profile_id))
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown profile: {profile_id}")


@router.post("/api/compose/{profile_id}")
async def api_compose(profile_id: str, request: Request):
    try:
        payload: Dict[str, Any] = await request.json()
    except Exception:
        payload = {}
    try:
        return JSONResponse(compose_desired_config(profile_id, payload))
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown profile: {profile_id}")


@router.post("/api/export/{profile_id}")
async def api_export_config(profile_id: str, request: Request):
    try:
        payload: Dict[str, Any] = await request.json()
    except Exception:
        payload = {}
    try:
        path = create_config_export_zip(profile_id, payload)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown profile: {profile_id}")
    return FileResponse(path, filename=path.name, media_type="application/zip")


@router.post("/api/analyze-baseline")
async def api_analyze_baseline(baseline_zip: UploadFile = File(...)):
    content = await baseline_zip.read()
    return JSONResponse(analyze_baseline_zip(content))


@router.post("/api/pull-baseline-sftp")
async def api_pull_baseline_sftp(request: Request):
    try:
        payload: Dict[str, Any] = await request.json()
    except Exception:
        payload = {}
    return JSONResponse(pull_baseline_via_sftp(payload))


@router.get("/api/pull-baseline-sftp/{job_id}/download")
async def api_download_sftp_baseline(job_id: str):
    try:
        path = get_sftp_pull_zip(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown SFTP pull job")
    except FileNotFoundError:
        raise HTTPException(status_code=410, detail="Pulled baseline ZIP is no longer available")
    return FileResponse(path, filename=path.name, media_type="application/zip")
