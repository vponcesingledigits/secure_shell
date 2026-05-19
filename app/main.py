from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, JSONResponse

from app.config import APP_NAME, APP_VERSION
from app.template_compat import install_template_response_compat

install_template_response_compat()
from app.routers import home, configuration_builder, diagnostics, site_context
from app.module_registry import discover_modules, include_enabled_modules

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

app = FastAPI(title=APP_NAME, version=APP_VERSION, debug=False)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.exception_handler(Exception)
async def shell_exception_handler(request: Request, exc: Exception):
    return JSONResponse({"ok": False, "error": "Internal server error. See server log for details."}, status_code=500)

app.include_router(home.router)
app.include_router(configuration_builder.router)
app.include_router(diagnostics.router)
app.include_router(site_context.router)

# Manifest-driven module discovery. Each module lives under apps/<module>/ and
# exposes APIRouter as `router` from the import path defined in module.json.
MODULES = discover_modules(PROJECT_DIR / "apps")
include_enabled_modules(app, MODULES, PROJECT_DIR)


@app.get("/api/modules")
def api_modules():
    return [m.launcher_dict() for m in MODULES if m.enabled and not m.error]


@app.get("/health")
def health():
    return {
        "status": "ok",
        "app": APP_NAME,
        "version": APP_VERSION,
        "port": 8010,
        "modules": [m.id for m in MODULES if m.enabled and not m.error],
        "module_errors": [{"id": m.id, "error": m.error} for m in MODULES if m.error],
    }


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return RedirectResponse("https://images.squarespace-cdn.com/content/v1/63eaba56d2bc1c0edd1199e0/6c87c44f-feae-44b2-a096-fea952fde4bf/favicon.ico?format=100w")
