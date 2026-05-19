"""
Self-updating HP / ArubaOS-Switch / ProCurve model database.

This is intentionally local/offline:
- MAC Trace must not depend on internet access during support calls.
- Known J-models are mapped immediately.
- Unknown J-models are still classified as hp_aruba_procurve and saved to a
  local user cache for later mapping.

User cache:
  %LOCALAPPDATA%/SingleDigitsEngineeringPlatform/ModelCache/hp_models_user.json

Future shell apps can reuse this shared module.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


HP_MODEL_DB: Dict[str, Dict[str, Any]] = {
    "J9728A": {
        "vendor": "hp_aruba_procurve",
        "family": "Aruba/HP 2920",
        "platform": "2920-48G",
        "type": "fixed_switch",
        "poe": False,
        "ports": "48x copper",
        "source": "internal_observed",
        "notes": "Observed/expected 2920 48-port non-PoE model.",
    },
    "J9729A": {
        "vendor": "hp_aruba_procurve",
        "family": "Aruba/HP 2920",
        "platform": "2920-48G-PoE+",
        "type": "fixed_switch",
        "poe": True,
        "ports": "48x copper PoE+",
        "source": "internal_observed",
        "notes": "Observed in LLDP as HP J9729A 2920-48G-POE+ Switch.",
    },
    "J9850A": {
        "vendor": "hp_aruba_procurve",
        "family": "Aruba/HP 5400R zl2",
        "platform": "5406R zl2",
        "type": "chassis_switch",
        "poe": "module-dependent",
        "ports": "chassis/module-dependent",
        "source": "internal_observed",
        "notes": "Observed in LLDP as HP J9850A Switch 5406Rzl2.",
    },
}


MODEL_RE = re.compile(r"\b(?:HP\s*)?(J\d{4}[A-Z])\b", re.I)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def model_cache_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / "SingleDigitsEngineeringPlatform" / "ModelCache"
    return Path.home() / ".singledigits_engineering_platform" / "ModelCache"


def user_model_db_path() -> Path:
    return model_cache_dir() / "hp_models_user.json"


def normalize_hp_model(model: str | None) -> str:
    if not model:
        return ""
    m = MODEL_RE.search(str(model).upper().replace(" ", ""))
    return m.group(1).upper() if m else ""


def extract_hp_model(text: str | None) -> str:
    """Extract first HP/Aruba J-model from arbitrary CLI/LLDP text."""
    if not text:
        return ""
    m = MODEL_RE.search(str(text))
    return m.group(1).upper() if m else ""


def extract_all_hp_models(text: str | None) -> list[str]:
    if not text:
        return []
    models = [m.upper() for m in MODEL_RE.findall(str(text))]
    return list(dict.fromkeys(models))


def load_user_model_db() -> Dict[str, Dict[str, Any]]:
    path = user_model_db_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {str(k).upper(): v for k, v in data.items() if isinstance(v, dict)}
    except Exception:
        return {}
    return {}


def save_user_model_db(data: Dict[str, Dict[str, Any]]) -> None:
    path = user_model_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def get_hp_model_info(model: str | None, evidence: str | None = None, source: str = "runtime") -> Dict[str, Any]:
    """Return model metadata and self-register unknown J-models.

    Known model:
      returns internal/user metadata.

    Unknown J-model:
      returns vendor=hp_aruba_procurve with known_model=False and saves a
      pending entry to the user cache.
    """
    key = normalize_hp_model(model)
    if not key:
        return {}

    if key in HP_MODEL_DB:
        data = dict(HP_MODEL_DB[key])
        data["model"] = key
        data["known_model"] = True
        data["database"] = "internal"
        return data

    user_db = load_user_model_db()
    if key in user_db:
        data = dict(user_db[key])
        data.setdefault("vendor", "hp_aruba_procurve")
        data.setdefault("model", key)
        data.setdefault("known_model", bool(data.get("platform") and data.get("platform") != "unknown J-model"))
        data["database"] = "user"
        return data

    entry = {
        "model": key,
        "vendor": "hp_aruba_procurve",
        "family": "HP/Aruba ProCurve / ArubaOS-Switch",
        "platform": "unknown J-model",
        "type": "unknown_switch",
        "poe": "unknown",
        "ports": "unknown",
        "known_model": False,
        "database": "user_pending",
        "first_seen": _utc_now(),
        "last_seen": _utc_now(),
        "seen_count": 1,
        "source": source,
        "evidence": (evidence or "")[:2000],
        "notes": "J-model detected automatically; mapping needed.",
    }
    user_db[key] = entry
    save_user_model_db(user_db)
    return dict(entry)


def observe_hp_model_text(text: str | None, source: str = "runtime") -> list[Dict[str, Any]]:
    """Extract all J-models from text, update cache if needed, and return info."""
    results = []
    for model in extract_all_hp_models(text):
        key = normalize_hp_model(model)
        if not key:
            continue

        if key in HP_MODEL_DB:
            results.append(get_hp_model_info(key, text, source))
            continue

        user_db = load_user_model_db()
        if key in user_db:
            entry = dict(user_db[key])
            entry["last_seen"] = _utc_now()
            entry["seen_count"] = int(entry.get("seen_count", 0)) + 1
            if text and not entry.get("evidence"):
                entry["evidence"] = str(text)[:2000]
            user_db[key] = entry
            save_user_model_db(user_db)
            entry["database"] = "user"
            results.append(entry)
        else:
            results.append(get_hp_model_info(key, text, source))

    return results


def enrich_from_text(text: str | None, source: str = "runtime") -> Dict[str, Any]:
    """Extract the first model from text and return/update metadata."""
    model = extract_hp_model(text)
    return get_hp_model_info(model, text, source) if model else {}


def is_hp_aruba_model_text(text: str | None) -> bool:
    """True if text contains any HP/Aruba J-model."""
    return bool(extract_hp_model(text))


def update_user_model_mapping(model: str, **fields: Any) -> Dict[str, Any]:
    """Manually update a model mapping in the user cache.

    Example:
      update_user_model_mapping("J9999A", platform="Some Switch", family="Aruba")
    """
    key = normalize_hp_model(model)
    if not key:
        raise ValueError("No valid J-model supplied")

    user_db = load_user_model_db()
    entry = dict(user_db.get(key) or get_hp_model_info(key))
    entry.update({k: v for k, v in fields.items() if v is not None})
    entry["model"] = key
    entry.setdefault("vendor", "hp_aruba_procurve")
    entry["known_model"] = bool(entry.get("platform") and entry.get("platform") != "unknown J-model")
    entry["last_updated"] = _utc_now()
    user_db[key] = entry
    save_user_model_db(user_db)
    return dict(entry)


def export_combined_model_db() -> Dict[str, Dict[str, Any]]:
    """Return internal + user database, with user entries overriding internal."""
    data = {k: dict(v, model=k, database="internal") for k, v in HP_MODEL_DB.items()}
    for k, v in load_user_model_db().items():
        data[k] = dict(v, model=k, database=v.get("database", "user"))
    return data
