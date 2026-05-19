from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from .services.collectors import DEFAULT_HISTORY_ROOT, collect_session, list_sessions, resolve_session_path
from .services.exporters import build_zip

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
router = APIRouter(prefix="/apps/evidence", tags=["Evidence Pack"])


@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def evidence_home(request: Request):
    sessions = list_sessions(DEFAULT_HISTORY_ROOT)
    return templates.TemplateResponse(
        "evidence/index.html",
        {
            "request": request,
            "sessions": sessions,
            "history_root": "History",
        },
    )


@router.get("/sessions")
async def evidence_sessions():
    return JSONResponse({"history_root": "History", "sessions": list_sessions(DEFAULT_HISTORY_ROOT)})


@router.post("/export")
async def evidence_export(session_path: Optional[str] = Form(default=None)):
    try:
        source = collect_session(resolve_session_path(session_path) if session_path else None)
        zip_path = build_zip(source)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Evidence session not found.") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=400, detail="Invalid evidence session selection.") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Evidence Pack export failed. See server log for details.") from exc

    return FileResponse(
        path=str(zip_path),
        filename=zip_path.name,
        media_type="application/zip",
    )
