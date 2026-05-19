from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.config import APP_NAME, APP_VERSION, FAVICON_URL
from app.module_registry import modules_for

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).resolve().parents[1] / "templates")

@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "favicon_url": FAVICON_URL,
        "config_modules": modules_for("configuration"),
        "diagnostic_modules": modules_for("diagnostics"),
    })
