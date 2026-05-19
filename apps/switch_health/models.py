from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    port: str = ""
    evidence: str = ""
    recommendation: str = ""


@dataclass
class CommandResult:
    command: str
    output: str
    ok: bool = True
    error: str = ""


@dataclass
class SwitchResult:
    target: str
    host: str
    port: int
    hostname: str = "Unknown"
    vendor: str = "unknown"
    platform: str = "unknown"
    status: str = "queued"
    started_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    completed_at: str | None = None
    findings: list[Finding] = field(default_factory=list)
    commands: dict[str, CommandResult] = field(default_factory=dict)
    raw: dict[str, str] = field(default_factory=dict)
    logs: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanJob:
    job_id: str
    targets: list[str]
    status: str = "queued"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    started_at: str | None = None
    completed_at: str | None = None
    results: list[SwitchResult] = field(default_factory=list)
    log: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
