from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.config import APP_NAME, APP_VERSION, FAVICON_URL
from app.module_registry import modules_for, get_module

router = APIRouter(prefix="/configuration", tags=["configuration"])
templates = Jinja2Templates(directory=Path(__file__).resolve().parents[1] / "templates")

@router.get("", response_class=HTMLResponse)
def configuration_home(request: Request):
    return templates.TemplateResponse("section.html", {"request": request, "app_name": APP_NAME, "app_version": APP_VERSION, "favicon_url": FAVICON_URL, "section_title": "Configuration Builder", "section_description": "Build complete, brand-aware site configurations and implementation documentation.", "modules": modules_for("configuration")})

@router.get("/{module_id}", response_class=HTMLResponse)
def configuration_module(request: Request, module_id: str):
    module = get_module(module_id)
    return templates.TemplateResponse("module_placeholder.html", {"request": request, "app_name": APP_NAME, "app_version": APP_VERSION, "favicon_url": FAVICON_URL, "module": module, "section": "Configuration Builder"})

@router.get("/{module_id}/status", response_class=PlainTextResponse)
def configuration_module_status(module_id: str):
    module = get_module(module_id)
    if not module:
        return "Unknown module"
    return f"{module.name}: {module.status}"
