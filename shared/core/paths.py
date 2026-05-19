from __future__ import annotations
import os
from pathlib import Path
APPDATA_FOLDER = "SingleDigitsEngineeringPlatform"
def platform_data_root() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    root = (Path(base) if base else Path.home()/".local"/"share") / APPDATA_FOLDER
    root.mkdir(parents=True, exist_ok=True)
    return root
def shell_root() -> Path:
    return Path(__file__).resolve().parents[2]
