"""Reporting helpers for PDF/JSON/text exports."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

SECRET_KEYS = ("password", "secret", "community", "snmp", "token", "key")

def redact_payload(payload: Any) -> Any:
    if isinstance(payload, dict):
        redacted = {}
        for key, value in payload.items():
            if any(s in str(key).lower() for s in SECRET_KEYS):
                redacted[key] = "********"
            else:
                redacted[key] = redact_payload(value)
        return redacted
    if isinstance(payload, list):
        return [redact_payload(item) for item in payload]
    return payload

def save_json_report(payload: dict[str, Any], export_dir: str | Path = "exports/json", prefix: str = "report") -> Path:
    export_path = Path(export_dir)
    export_path.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = export_path / f"{prefix}_{stamp}.json"
    path.write_text(json.dumps(redact_payload(payload), indent=2), encoding="utf-8")
    return path
