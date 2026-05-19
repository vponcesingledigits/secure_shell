from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

Section = Literal["configuration", "diagnostics"]
Status = Literal["shell", "legacy", "planned", "active"]

CATEGORY_SECTION = {
    "Configuration Builder": "configuration",
    "Support Diagnostics": "diagnostics",
}

@dataclass(frozen=True)
class PlatformModule:
    id: str
    name: str
    section: Section
    status: Status
    description: str
    route: str
    legacy_source: str | None = None

@dataclass
class ModuleManifest:
    id: str
    name: str
    version: str
    mount: str
    category: str
    description: str
    router: str
    enabled: bool = True
    folder: str = ""
    error: str | None = None

    @property
    def section(self) -> str:
        return CATEGORY_SECTION.get(self.category, self.category)

    def launcher_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "mount": self.mount,
            "route": self.mount,
            "category": self.category,
            "section": self.section,
            "description": self.description,
            "enabled": self.enabled,
        }


def discover_modules(apps_dir: Path) -> list[ModuleManifest]:
    modules: list[ModuleManifest] = []
    if not apps_dir.exists():
        return modules
    for manifest_path in sorted(apps_dir.glob("*/module.json")):
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            required = ["id", "name", "version", "mount", "category", "description", "router", "enabled"]
            missing = [key for key in required if key not in data]
            if missing:
                raise ValueError(f"missing required module.json fields: {', '.join(missing)}")
            modules.append(ModuleManifest(folder=manifest_path.parent.name, **{k: data[k] for k in required}))
        except Exception as exc:
            modules.append(ModuleManifest(
                id=manifest_path.parent.name,
                name=manifest_path.parent.name,
                version="unknown",
                mount=f"/apps/{manifest_path.parent.name.replace('_','-')}",
                category="Support Diagnostics",
                description="Module manifest could not be loaded.",
                router="",
                enabled=False,
                folder=manifest_path.parent.name,
                error=str(exc),
            ))
    return modules


def include_enabled_modules(app: FastAPI, modules: list[ModuleManifest], project_dir: Path) -> None:
    for module in modules:
        if not module.enabled or module.error:
            continue
        module_dir = project_dir / "apps" / module.folder
        static_dir = module_dir / "static"
        if static_dir.exists():
            mount_path = module.mount.rstrip("/") + "/static"
            app.mount(mount_path, StaticFiles(directory=static_dir), name=f"{module.id}_static")
        try:
            imported = importlib.import_module(module.router)
            router = getattr(imported, "router")
            # Modules with router prefixes should be included as-is. Prefixless
            # modules are mounted at the manifest path.
            existing_prefix = getattr(router, "prefix", "") or ""
            if existing_prefix:
                app.include_router(router)
            else:
                app.include_router(router, prefix=module.mount)
        except Exception as exc:
            module.error = str(exc)


def _platform_from_manifest(m: ModuleManifest) -> PlatformModule:
    return PlatformModule(
        id=m.id,
        name=m.name,
        section="configuration" if m.section == "configuration" else "diagnostics",
        status="active" if m.enabled and not m.error else "planned",
        description=m.description,
        route=m.mount,
    )

# Compatibility helpers used by older templates/routes.
MODULES: list[PlatformModule] = [_platform_from_manifest(m) for m in discover_modules(Path(__file__).resolve().parents[1] / "apps")]

def modules_for(section: Section) -> list[PlatformModule]:
    return [m for m in MODULES if m.section == section]

def get_module(module_id: str) -> PlatformModule | None:
    return next((m for m in MODULES if m.id == module_id), None)
