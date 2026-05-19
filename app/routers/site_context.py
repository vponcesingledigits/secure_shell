from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import APP_NAME, APP_VERSION, FAVICON_URL
from shared.site_context import SiteProfile, load_site_profile, save_site_profile

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).resolve().parents[1] / "templates")


@router.get("/site-context", response_class=HTMLResponse)
def site_context_page(request: Request):
    return templates.TemplateResponse("site_context.html", {
        "request": request,
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "favicon_url": FAVICON_URL,
        "profile": load_site_profile(),
        "saved": False,
    })


@router.post("/site-context", response_class=HTMLResponse)
async def save_site_context_page(request: Request):
    form = await request.form()
    payload = {k: str(form.get(k) or "").strip() for k in SiteProfile.__dataclass_fields__.keys()}
    # Keep safe defaults when fields are omitted or blank.
    payload["brand"] = payload.get("brand") or "Generic / NonBranded"
    payload["deployment_model"] = payload.get("deployment_model") or "Standard"
    payload["country"] = payload.get("country") or "US"
    payload["default_switch_ip_start"] = payload.get("default_switch_ip_start") or "10.0.3.130"
    payload["default_switch_mask"] = payload.get("default_switch_mask") or "255.255.255.128"
    payload["default_switch_gateway"] = payload.get("default_switch_gateway") or "10.0.3.129"
    payload["default_mgmt_vlan"] = payload.get("default_mgmt_vlan") or "100"
    payload["default_ap_mgmt_vlan"] = payload.get("default_ap_mgmt_vlan") or "101"
    profile = save_site_profile(SiteProfile(**payload))
    return templates.TemplateResponse("site_context.html", {
        "request": request,
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "favicon_url": FAVICON_URL,
        "profile": profile,
        "saved": True,
    })


@router.get("/api/site-context")
def api_site_context():
    return load_site_profile().__dict__
