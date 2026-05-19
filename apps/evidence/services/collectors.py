from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .redaction import redact_json_text, redact_obj, redact_text

APPDATA_ROOT = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "SingleDigitsEngineeringPlatform"
DEFAULT_HISTORY_ROOT = APPDATA_ROOT / "History"
DEFAULT_EVIDENCE_ROOT = APPDATA_ROOT / "EvidencePacks"

KNOWN_ARTIFACT_NAMES = {
    "findings": ["findings.json", "compliance_findings.json", "switch_health_findings.json"],
    "topology": ["topology.json"],
    "port_map": ["port_map.json", "portmap.json"],
    "session_log": ["session.log", "scan.log", "events.log"],
}
RAW_DIR_NAMES = ["raw", "raw_cli", "raw_cli_output", "cli", "commands"]
EXCEL_NAMES = ["port_map.xlsx", "switch_port_map.xlsx", "portmap.xlsx"]
PDF_NAMES = ["topology.pdf", "port_map.pdf", "portmap.pdf"]


@dataclass
class EvidenceSource:
    session_id: str
    source_dir: Path
    work_dir: Path
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    findings: dict[str, Any] = field(default_factory=dict)
    topology: dict[str, Any] = field(default_factory=dict)
    port_map: dict[str, Any] = field(default_factory=dict)
    session_log: str = ""
    raw_files: list[Path] = field(default_factory=list)
    copied_files: dict[str, Path] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def list_sessions(history_root: Path = DEFAULT_HISTORY_ROOT) -> list[dict[str, str]]:
    history_root = Path(history_root)
    if not history_root.exists():
        return []
    sessions: list[dict[str, str]] = []
    for child in sorted(history_root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if not child.is_dir():
            continue
        sessions.append(
            {
                "id": child.name,
                "path": child.name,
                "modified": datetime.fromtimestamp(child.stat().st_mtime).isoformat(timespec="seconds"),
            }
        )
    return sessions


def resolve_session_path(session_id_or_path: str | Path | None, history_root: Path = DEFAULT_HISTORY_ROOT) -> Path | None:
    if not session_id_or_path:
        return None
    root = Path(history_root).resolve()
    requested = Path(session_id_or_path)
    # UI now submits relative session IDs. Absolute paths and traversal are rejected.
    if requested.is_absolute() or ".." in requested.parts:
        raise PermissionError("Session path must be a relative session id under the history root.")
    candidate = (root / requested).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise PermissionError("Session path escapes the history root.") from exc
    if not candidate.exists() or not candidate.is_dir():
        raise FileNotFoundError("Session not found.")
    return candidate


def latest_session(history_root: Path = DEFAULT_HISTORY_ROOT) -> Path | None:
    sessions = list_sessions(history_root)
    if not sessions:
        return None
    return resolve_session_path(sessions[0]["id"], history_root)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return redact_obj(json.loads(path.read_text(encoding="utf-8", errors="replace")))
    except Exception as exc:
        return {"_load_error": f"Could not parse {path.name}: {exc}"}


def _find_first(source_dir: Path, names: list[str]) -> Path | None:
    for name in names:
        direct = source_dir / name
        if direct.exists():
            return direct
    lower = {p.name.lower(): p for p in source_dir.rglob("*") if p.is_file()}
    for name in names:
        if name.lower() in lower:
            return lower[name.lower()]
    return None


def collect_session(session_dir: Path | None = None, history_root: Path = DEFAULT_HISTORY_ROOT) -> EvidenceSource:
    session_dir = Path(session_dir) if session_dir else latest_session(history_root)
    if session_dir is None or not session_dir.exists():
        raise FileNotFoundError(f"No scan session found under {history_root}")

    session_id = session_dir.name
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    work_dir = DEFAULT_EVIDENCE_ROOT / f"evidence_{session_id}_{stamp}"
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    source = EvidenceSource(session_id=session_id, source_dir=session_dir, work_dir=work_dir)

    for key, names in KNOWN_ARTIFACT_NAMES.items():
        path = _find_first(session_dir, names)
        if not path:
            source.warnings.append(f"Missing {key} artifact")
            continue
        if key == "findings":
            source.findings = _load_json(path)
        elif key == "topology":
            source.topology = _load_json(path)
        elif key == "port_map":
            source.port_map = _load_json(path)
        elif key == "session_log":
            source.session_log = redact_text(path.read_text(encoding="utf-8", errors="replace"))

    raw_out = work_dir / "raw_cli_output"
    raw_out.mkdir(exist_ok=True)
    for dirname in RAW_DIR_NAMES:
        raw_dir = session_dir / dirname
        if raw_dir.exists() and raw_dir.is_dir():
            for raw_file in raw_dir.rglob("*"):
                if raw_file.is_file():
                    dest = raw_out / raw_file.name
                    dest.write_text(redact_text(raw_file.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")
                    source.raw_files.append(dest)
    if not source.raw_files:
        # Fall back to any likely raw CLI text files.
        for raw_file in session_dir.rglob("*.txt"):
            if "raw" in raw_file.name.lower() or "cli" in raw_file.name.lower() or "show" in raw_file.name.lower():
                dest = raw_out / raw_file.name
                dest.write_text(redact_text(raw_file.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")
                source.raw_files.append(dest)

    # Copy already-generated PDFs/XLSX when present. PDFs are binary and cannot be safely redacted,
    # so generated reports from this module are preferred. Existing PDFs are copied only if their
    # names indicate topology/port-map exports and the UI warns that original PDFs should not include secrets.
    for name in EXCEL_NAMES:
        path = _find_first(session_dir, [name])
        if path:
            dest = work_dir / "excel_port_map_export.xlsx"
            shutil.copy2(path, dest)
            source.copied_files["excel_port_map_export.xlsx"] = dest
            break

    return source


def write_redacted_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(redact_obj(data), indent=2, ensure_ascii=False), encoding="utf-8")


def write_redacted_text(path: Path, text: str) -> None:
    path.write_text(redact_json_text(text), encoding="utf-8")
