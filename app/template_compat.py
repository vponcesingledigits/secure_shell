"""
Compatibility helpers for FastAPI/Starlette template rendering.

Starlette 1.0 changed Jinja2Templates.TemplateResponse argument order from:
    TemplateResponse("template.html", {"request": request, ...})
to:
    TemplateResponse(request, "template.html", {"request": request, ...})

Several shell modules still use the older FastAPI style. This shim keeps the
shell working across Windows machines that may resolve newer FastAPI/Starlette
packages from the internet.
"""
from __future__ import annotations

from fastapi.templating import Jinja2Templates


_ORIGINAL_TEMPLATE_RESPONSE = Jinja2Templates.TemplateResponse


def _template_response_compat(self, *args, **kwargs):
    # Old style: TemplateResponse("name.html", {"request": request, ...})
    if len(args) >= 2 and isinstance(args[0], str) and isinstance(args[1], dict):
        name = args[0]
        context = args[1]
        request = context.get("request")
        if request is not None:
            # New Starlette/FastAPI style first.
            try:
                return _ORIGINAL_TEMPLATE_RESPONSE(self, request, name, context, **kwargs)
            except TypeError:
                # Older Starlette/FastAPI style.
                return _ORIGINAL_TEMPLATE_RESPONSE(self, name, context, **kwargs)

    return _ORIGINAL_TEMPLATE_RESPONSE(self, *args, **kwargs)


def install_template_response_compat() -> None:
    if getattr(Jinja2Templates.TemplateResponse, "_sd_compat_installed", False):
        return
    _template_response_compat._sd_compat_installed = True
    Jinja2Templates.TemplateResponse = _template_response_compat
