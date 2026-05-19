"""Route safety net for Alpha.0.8.0.

This does not replace real modules. It only prevents stale launcher links from returning raw 404s
and exposes a route status endpoint for troubleshooting.
"""
from __future__ import annotations

from html import escape
from typing import Any

EXPECTED_ROUTES = {
    "/apps/mac-trace": "MAC Trace",
    "/apps/switch-health": "Switch Health Dashboard",
    "/apps/port-map": "Port Map",
    "/apps/monitoring": "Monitoring Tool",
    "/apps/smartzone-ap-investigator": "SmartZone AP Investigator",
    "/apps/forescout": "ForeScout Verifier",
    "/apps/evidence": "Evidence Pack",
    "/apps/topology": "Topology Builder",
    "/apps/switchport-normalizer": "Switchport Name Normalizer",
    "/apps/switch-configurator": "Switch Configurator",
    "/apps/off-service": "Disconnect / Off-Service",
    "/apps/nomadix-config": "Nomadix Configurator",
    "/apps/mikrotik-router": "MikroTik Router Configurator",
}


def _existing_paths(app: Any) -> set[str]:
    paths = set()
    for route in getattr(app, "routes", []):
        path = getattr(route, "path", None)
        if path:
            paths.add(path.rstrip("/") or "/")
    return paths


def install_alpha_0_8_0_compat_routes(app: Any) -> None:
    try:
        from fastapi.responses import HTMLResponse, JSONResponse
    except Exception:
        return

    def status():
        current = _existing_paths(app)
        return JSONResponse({
            "version": "Alpha.0.8.0",
            "routes": [
                {"path": path, "name": name, "mounted": path in current or path + "/" in current}
                for path, name in EXPECTED_ROUTES.items()
            ],
        })

    if "/api/alpha-0-8-0/routes" not in _existing_paths(app):
        app.add_api_route("/api/alpha-0-8-0/routes", status, methods=["GET"])

    existing = _existing_paths(app)
    for path, name in EXPECTED_ROUTES.items():
        if path in existing or path + "/" in existing:
            continue

        async def missing_module(name=name, path=path):
            body = f"""
<!doctype html>
<html><head><meta charset='utf-8'><title>{escape(name)} — Alpha.0.8.0</title>
<link rel='stylesheet' href='/static/css/sd-platform.css'>
<link rel='stylesheet' href='/static/css/sd-module-unified.css'>
<style>body{{font-family:system-ui,Segoe UI,Arial;margin:0;background:#f6f8fb;color:#162033}}.wrap{{max-width:900px;margin:48px auto;padding:28px;background:white;border-radius:18px;box-shadow:0 12px 30px rgba(15,23,42,.08)}}code{{background:#f1f5f9;padding:2px 6px;border-radius:6px}}.warn{{border-left:4px solid #b45309;background:#fffbeb;padding:12px 16px;border-radius:12px}}</style>
</head><body><main class='wrap'>
<h1>{escape(name)}</h1>
<p class='warn'>This launcher link is valid for Alpha.0.8.0, but the real module router was not mounted at startup.</p>
<p>This usually means the app folder is missing from the shell source, its <code>module.json</code> points to the wrong Python package, or the module failed import during startup.</p>
<p>Check <code>ALPHA_0_8_0_REBUILD_REPORT.txt</code> in the rebuilt shell folder, then restore this app from the last fully working bundle if the report marks it missing.</p>
<p><a href='/'>Back to Shell Home</a> &nbsp; <a href='/api/alpha-0-8-0/routes'>Route Status JSON</a></p>
</main></body></html>
"""
            return HTMLResponse(body, status_code=200)

        app.add_api_route(path, missing_module, methods=["GET"])
        app.add_api_route(path + "/", missing_module, methods=["GET"])
