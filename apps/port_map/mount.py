from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .router import router


def mount(app: FastAPI) -> None:
    """Call from the shell lazy loader."""
    app.include_router(router)
    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/apps/port-map/static", StaticFiles(directory=str(static_dir)), name="port_map_static")
