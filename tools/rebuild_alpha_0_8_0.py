from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

VERSION = "Alpha.0.8.0"
OUT_NAME = "Single_Digits_Engineering_Platform_Alpha.0.8.0"

EXPECTED = [
    {"id":"mac_trace","name":"MAC Trace","mount":"/apps/mac-trace","category":"diagnostics","folders":["mac_trace","mac-trace","mac_trace_rc1","mac_trace_rc1_0"],"router":"apps.mac_trace.routes"},
    {"id":"switch_health","name":"Switch Health Dashboard","mount":"/apps/switch-health","category":"diagnostics","folders":["switch_health","switch-health","switch_health_dashboard"],"router":"apps.switch_health.routes"},
    {"id":"port_map","name":"Port Map","mount":"/apps/port-map","category":"diagnostics","folders":["port_map","port-map","port_mapper"],"router":"apps.port_map.routes"},
    {"id":"monitoring","name":"Monitoring Tool","mount":"/apps/monitoring","category":"diagnostics","folders":["monitoring","monitoring_tool"],"router":"apps.monitoring.routes"},
    {"id":"smartzone_ap_investigator","name":"SmartZone AP Investigator","mount":"/apps/smartzone-ap-investigator","category":"diagnostics","folders":["smartzone_ap_investigator","smartzone-ap-investigator","smartzone"],"router":"apps.smartzone_ap_investigator.routes"},
    {"id":"forescout","name":"ForeScout Verifier","mount":"/apps/forescout","category":"diagnostics","folders":["forescout","forescout_verifier"],"router":"apps.forescout.routes"},
    {"id":"evidence","name":"Evidence Pack","mount":"/apps/evidence","category":"diagnostics","folders":["evidence","evidence_pack"],"router":"apps.evidence.routes"},
    {"id":"topology","name":"Topology Builder","mount":"/apps/topology","category":"diagnostics","folders":["topology","topology_builder"],"router":"apps.topology.routes"},
    {"id":"switchport_normalizer","name":"Switchport Name Normalizer","mount":"/apps/switchport-normalizer","category":"configuration","folders":["switchport_normalizer","switchport-normalizer","port_name_normalizer"],"router":"apps.switchport_normalizer.routes"},
    {"id":"switch_configurator","name":"Switch Configurator","mount":"/apps/switch-configurator","category":"configuration","folders":["switch_configurator","switch-configurator"],"router":"apps.switch_configurator.routes"},
    {"id":"off_service","name":"Disconnect / Off-Service","mount":"/apps/off-service","category":"configuration","folders":["off_service","off-service"],"router":"apps.off_service.routes"},
    {"id":"nomadix_config","name":"Nomadix Configurator","mount":"/apps/nomadix-config","category":"configuration","folders":["nomadix_config","nomadix-config","nomadix"],"router":"apps.nomadix_config.routes"},
    {"id":"mikrotik_router","name":"MikroTik Router Configurator","mount":"/apps/mikrotik-router","category":"configuration","folders":["mikrotik_router","mikrotik-router"],"router":"apps.mikrotik_router.routes"},
]

TEXT_EXTS = {".py", ".json", ".txt", ".md", ".html", ".css", ".js", ".bat", ".ps1", ".yaml", ".yml"}


def copytree(src: Path, dst: Path) -> None:
    ignore = shutil.ignore_patterns(".venv", "venv", "__pycache__", "*.pyc", ".git", "*.log")
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=ignore)


def install_kit_files(root: Path, kit_root: Path, report: list[str]) -> None:
    for rel in ["apps/off_service", "shared/offservice_commands.py", "shared/redaction.py", "shared/alpha_0_8_0_route_safety.py", ".env.offservice.example"]:
        src = kit_root / rel
        dst = root / rel
        if src.is_dir():
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
    report.append("Installed Off-Service and Alpha.0.8.0 route safety files without replacing shared/commands.py.")


def safe_replace_versions(root: Path, report: list[str]) -> None:
    patterns = [
        (re.compile(r"Alpha[ ._-]?0[ ._-]?7[ ._-]?5", re.I), VERSION),
        (re.compile(r"Alpha[ ._-]?0[ ._-]?7", re.I), VERSION),
        (re.compile(r"alpha_0_7_5", re.I), "alpha_0_8_0"),
    ]
    changed = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_EXTS:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        new = text
        for pat, repl in patterns:
            new = pat.sub(repl, new)
        if new != text:
            path.write_text(new, encoding="utf-8")
            changed += 1
    (root / "VERSION.txt").write_text(f"Single Digits Engineering Platform {VERSION}\n", encoding="utf-8")
    report.append(f"Updated version markers in {changed} text file(s).")


def folder_for_module(root: Path, spec: dict[str, Any]) -> Path | None:
    apps = root / "apps"
    if not apps.exists():
        return None
    for folder in spec["folders"]:
        p = apps / folder
        if p.exists() and p.is_dir():
            return p
    for modjson in apps.glob("*/module.json"):
        try:
            data = json.loads(modjson.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        if data.get("id") == spec["id"] or data.get("mount") == spec["mount"] or data.get("name") == spec["name"]:
            return modjson.parent
    return None


def find_in_known_good(root: Path, good: Path | None, spec: dict[str, Any], report: list[str]) -> Path | None:
    if not good:
        return None
    p = folder_for_module(good, spec)
    if not p:
        return None
    dst = root / "apps" / spec["folders"][0]
    if dst.exists():
        return dst
    shutil.copytree(p, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    report.append(f"Restored {spec['name']} from known-good folder: {p}")
    return dst


def normalize_module(root: Path, spec: dict[str, Any], known_good: Path | None, report: list[str]) -> None:
    apps = root / "apps"
    apps.mkdir(exist_ok=True)
    (apps / "__init__.py").touch()
    folder = folder_for_module(root, spec)
    if folder is None:
        folder = find_in_known_good(root, known_good, spec, report)
    if folder is None:
        report.append(f"MISSING: {spec['name']} ({spec['mount']}) - no app folder found. Route safety page will prevent raw 404, but full functionality requires restoring this app folder from last-good bundle.")
        return

    # Rename hyphenated package folders to underscore package folders when possible.
    preferred = root / "apps" / spec["folders"][0]
    if folder.name != preferred.name and "-" in folder.name and not preferred.exists():
        shutil.move(str(folder), str(preferred))
        report.append(f"Renamed Python-incompatible app folder {folder.name} -> {preferred.name}")
        folder = preferred

    (folder / "__init__.py").touch()
    module_pkg = f"apps.{folder.name}"
    router = spec.get("router")
    if folder.name != spec["folders"][0]:
        router = f"apps.{folder.name}.routes"

    existing = {}
    modjson = folder / "module.json"
    if modjson.exists():
        try:
            existing = json.loads(modjson.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            existing = {}
    data = {
        "id": spec["id"],
        "name": spec["name"],
        "version": VERSION,
        "mount": spec["mount"],
        "category": spec["category"],
        "description": existing.get("description") or f"{spec['name']} module for Single Digits Engineering Platform {VERSION}.",
        "router": existing.get("router") or router,
        "enabled": True,
    }
    # If existing router points at a hyphen folder, correct it.
    if "-" in str(data["router"]):
        data["router"] = router
    modjson.write_text(json.dumps(data, indent=2), encoding="utf-8")
    report.append(f"Normalized manifest: {spec['name']} -> {data['mount']} using {data['router']}")


def patch_main(root: Path, report: list[str]) -> None:
    candidates = [root / "main.py", root / "app.py", root / "server.py"]
    main = next((p for p in candidates if p.exists()), None)
    if not main:
        report.append("WARNING: Could not find main.py/app.py/server.py to install Alpha.0.8.0 route safety hook.")
        return
    text = main.read_text(encoding="utf-8", errors="ignore")
    marker = "install_alpha_0_8_0_compat_routes"
    if marker in text:
        report.append(f"Route safety hook already present in {main.name}.")
        return
    hook = """

# Alpha.0.8.0 route safety hook: keeps stale launcher links from returning raw 404s.
try:
    from shared.alpha_0_8_0_route_safety import install_alpha_0_8_0_compat_routes
    install_alpha_0_8_0_compat_routes(app)
except Exception as _alpha_0_8_0_route_safety_error:
    print(f"Alpha.0.8.0 route safety hook skipped: {_alpha_0_8_0_route_safety_error}")
"""
    main.write_text(text.rstrip() + hook + "\n", encoding="utf-8")
    report.append(f"Installed Alpha.0.8.0 route safety hook into {main.name}.")


def patch_start_bat(root: Path, report: list[str]) -> None:
    bat = root / "start.bat"
    if not bat.exists():
        return
    text = bat.read_text(encoding="utf-8", errors="ignore")
    text2 = re.sub(r"Alpha[ ._-]?0[ ._-]?7[ ._-]?5", VERSION, text, flags=re.I)
    text2 = text2.replace("Single Digits Engineering Platform", f"Single Digits Engineering Platform {VERSION}") if VERSION not in text2 else text2
    bat.write_text(text2, encoding="utf-8")
    report.append("Updated start.bat version labeling.")


def test_imports(root: Path, report: list[str]) -> None:
    sys.path.insert(0, str(root))
    for spec in EXPECTED:
        folder = folder_for_module(root, spec)
        if not folder:
            continue
        modjson = folder / "module.json"
        try:
            data = json.loads(modjson.read_text(encoding="utf-8"))
            router_path = data.get("router")
            if not router_path:
                raise ValueError("manifest has no router")
            mod = importlib.import_module(router_path)
            if not hasattr(mod, "router"):
                report.append(f"IMPORT WARNING: {spec['name']} imports but has no variable named router: {router_path}")
            else:
                report.append(f"IMPORT PASS: {spec['name']} ({router_path})")
        except Exception as exc:
            report.append(f"IMPORT FAIL: {spec['name']} - {type(exc).__name__}: {exc}")
    try:
        sys.path.remove(str(root))
    except ValueError:
        pass


def write_quick_check(root: Path) -> None:
    tools = root / "tools"
    tools.mkdir(exist_ok=True)
    (tools / "check_alpha_0_8_0_routes.py").write_text('''from __future__ import annotations\n\nimport json\nfrom pathlib import Path\n\nroot = Path(__file__).resolve().parents[1]\nfor modjson in sorted((root / "apps").glob("*/module.json")):\n    try:\n        data = json.loads(modjson.read_text(encoding="utf-8"))\n    except Exception as exc:\n        print(f"FAIL {modjson}: {exc}")\n        continue\n    print(f"{data.get('enabled')} {data.get('mount')} -> {data.get('router')} [{data.get('version')}]")\n''', encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Create clean Single Digits Engineering Platform Alpha.0.8.0 bundle")
    parser.add_argument("source", help="Current or last-working shell folder")
    parser.add_argument("--known-good", help="Optional last fully working shell folder to restore missing app folders from")
    parser.add_argument("--output", help="Optional output folder")
    args = parser.parse_args()

    source = Path(args.source).expanduser().resolve()
    known_good = Path(args.known_good).expanduser().resolve() if args.known_good else None
    if not source.exists():
        print(f"Source folder not found: {source}")
        return 2
    if known_good and not known_good.exists():
        print(f"Known-good folder not found: {known_good}")
        return 2
    kit_root = Path(__file__).resolve().parents[1]
    output = Path(args.output).expanduser().resolve() if args.output else source.parent / OUT_NAME
    report: list[str] = [f"Single Digits Engineering Platform {VERSION} rebuild report", f"Source: {source}", f"Known-good: {known_good or 'not provided'}", f"Output: {output}", ""]

    baseline = known_good or source
    copytree(baseline, output)
    report.append(f"Copied baseline folder from: {baseline}")
    if known_good and source != known_good:
        # Copy any apps that exist only in current source into output, but do not overwrite known-good apps.
        src_apps = source / "apps"
        out_apps = output / "apps"
        if src_apps.exists():
            out_apps.mkdir(exist_ok=True)
            for app_dir in src_apps.iterdir():
                if app_dir.is_dir() and not (out_apps / app_dir.name).exists():
                    shutil.copytree(app_dir, out_apps / app_dir.name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
                    report.append(f"Copied extra app from current source: {app_dir.name}")

    install_kit_files(output, kit_root, report)
    safe_replace_versions(output, report)
    for spec in EXPECTED:
        normalize_module(output, spec, known_good, report)
    patch_main(output, report)
    patch_start_bat(output, report)
    write_quick_check(output)
    test_imports(output, report)

    report_path = output / "ALPHA_0_8_0_REBUILD_REPORT.txt"
    report_path.write_text("\n".join(report) + "\n", encoding="utf-8")
    print(f"Created: {output}")
    print(f"Report:  {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
