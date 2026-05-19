from __future__ import annotations

import html
from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

try:
    from shared.offservice_commands import (
        DEFAULT_VENDOR_USERNAME,
        OffServiceOptions,
        generate_password,
        generic_preview_commands,
    )
except Exception:  # pragma: no cover - keeps module page from hard-failing if shared file is missing
    DEFAULT_VENDOR_USERNAME = "vendor"

    class OffServiceOptions:  # type: ignore[no-redef]
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    def generate_password() -> str:
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$%*-_+"
        return "".join(secrets.choice(alphabet) for _ in range(18))

    def generic_preview_commands(opts: OffServiceOptions) -> list[str]:
        return [
            "! shared.offservice_commands was not available",
            "! Install shared/offservice_commands.py from the Alpha.0.8.0 Off-Service fix package.",
        ]

try:
    from shared.redaction import redact
except Exception:  # pragma: no cover
    def redact(text: str, extra_secrets: list[str] | None = None) -> str:
        for secret in extra_secrets or []:
            if secret:
                text = text.replace(secret, "***REDACTED***")
        return text

router = APIRouter(prefix="/apps/off-service", tags=["Off-Service"])
MODULE_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(MODULE_DIR / "templates"))


def _inline_page(title: str, body: str) -> str:
    """Fallback for unusual installs where Jinja templates are unavailable."""
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<link rel="stylesheet" href="/static/css/sd-platform.css">
<link rel="stylesheet" href="/static/css/sd-module-unified.css">
<link rel="stylesheet" href="/apps/off-service/static/off_service.css">
</head><body><main class="sd-page offsvc"><section class="sd-hero"><div><p class="eyebrow">Configuration Builder</p><h1>{html.escape(title)}</h1><p>Preview, approve, and document Disconnect / Off-Service changes using shared shell command profiles.</p></div><a class="sd-button secondary" href="/">Shell Home</a></section>{body}</main><script src="/apps/off-service/static/off_service.js"></script></body></html>"""


def _render(request: Request, context: dict) -> HTMLResponse:
    template_path = MODULE_DIR / "templates" / "off_service.html"
    if template_path.exists():
        context = {"request": request, **context}
        return TEMPLATES.TemplateResponse("off_service.html", context)
    # Last-resort fallback; should not be used when this package is installed completely.
    return HTMLResponse(_inline_page(context.get("title", "Disconnect / Off-Service"), "<section class='sd-card'><p>Off-Service template missing.</p></section>"))


@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return _render(request, {"title": "Disconnect / Off-Service", "mode": "index"})


@router.post("/preview", response_class=HTMLResponse)
def preview(
    request: Request,
    targets: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    vendor: str = Form("auto"),
    credential_mode: str = Form("none"),
    handoff_username: str = Form(DEFAULT_VENDOR_USERNAME),
    target_username: str = Form("admin"),
    vlan_ids: str = Form("1000,1016,1025,1029,1030,1050,1400"),
) -> HTMLResponse:
    generated_password = ""
    if credential_mode in {"create_vendor_user", "update_admin_password"}:
        generated_password = generate_password()

    vlans = tuple(int(x.strip()) for x in vlan_ids.split(",") if x.strip().isdigit())
    opts = OffServiceOptions(
        vendor=vendor,
        credential_mode=credential_mode,
        handoff_username=handoff_username,
        handoff_password=generated_password,
        target_username=target_username,
        vlan_ids=vlans,
    )
    commands = generic_preview_commands(opts)
    redacted_commands = "\n".join(redact(c, [generated_password, password]) for c in commands)
    target_list = [t.strip() for t in targets.splitlines() if t.strip()]
    shown_user = ""
    shown_password = ""
    if generated_password:
        shown_user = handoff_username if credential_mode == "create_vendor_user" else target_username
        shown_password = generated_password

    return _render(
        request,
        {
            "title": "Off-Service Preview",
            "mode": "preview",
            "target_count": len(target_list),
            "vendor": vendor,
            "redacted_commands": redacted_commands,
            "handoff_username": shown_user,
            "handoff_password": shown_password,
        },
    )


@router.get("/api/health")
def health() -> dict[str, str]:
    return {"module": "off_service", "version": "Alpha.0.8.0", "status": "ok"}
