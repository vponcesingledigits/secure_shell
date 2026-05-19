from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def copytree_contents(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        target = dst / item.name
        if item.is_dir():
            copytree_contents(item, target)
        else:
            shutil.copy2(item, target)


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python tools\\install_off_service_html_fix.py C:\\Path\\To\\Single_Digits_Engineering_Platform_Alpha.0.8.0")
        return 2
    shell = Path(sys.argv[1]).resolve()
    if not shell.exists():
        print(f"ERROR: shell path does not exist: {shell}")
        return 1
    if not (shell / "apps").exists():
        print(f"ERROR: {shell} does not look like a shell root; apps/ is missing")
        return 1

    app_src = ROOT / "apps" / "off_service"
    app_dst = shell / "apps" / "off_service"
    copytree_contents(app_src, app_dst)

    shared_src = ROOT / "shared"
    shared_dst = shell / "shared"
    copytree_contents(shared_src, shared_dst)

    env_src = ROOT / ".env.offservice.example"
    shutil.copy2(env_src, shell / ".env.offservice.example")

    print("Installed Off-Service Alpha.0.8.0 HTML/template fix.")
    print(f"Updated: {app_dst}")
    print("Verify: http://127.0.0.1:8010/apps/off-service")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
