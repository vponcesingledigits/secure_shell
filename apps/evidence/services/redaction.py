"""Central redaction helpers for Evidence Pack exports.

The evidence module must never expose passwords, SNMP strings, TACACS secrets,
community strings, tokens, API keys, or similar credentials in HTML, PDF, JSON,
logs, raw command output, or Excel exports.
"""
from __future__ import annotations

import json
import re
from typing import Any

REDACTION = "[REDACTED]"

_SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|community|snmp|string|tacacs|radius|key|credential|auth)"
)

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # username admin password plaintext foo / encrypted hash variants
    (re.compile(r"(?i)(\busername\s+\S+\s+(?:password|secret)\s+)(\S+)(.*)"), rf"\1{REDACTION}\3"),
    (re.compile(r"(?i)(\buser\s+\S+.*?\bpassword\s+)(\S+)(.*)"), rf"\1{REDACTION}\3"),
    # enable / shared secrets
    (re.compile(r"(?i)(\benable\s+(?:password|secret)\s+)(\S+)(.*)"), rf"\1{REDACTION}\3"),
    (re.compile(r"(?i)(\b(?:tacacs|radius).*(?:key|secret)\s+)(\S+)(.*)"), rf"\1{REDACTION}\3"),
    # SNMP communities and trap strings across vendors
    (re.compile(r"(?i)(\bsnmp-server\s+community\s+)(\S+)(.*)"), rf"\1{REDACTION}\3"),
    (re.compile(r"(?i)(\bcommunity\s+[\"']?)([^\s\"']+)([\"']?.*)"), rf"\1{REDACTION}\3"),
    (re.compile(r"(?i)(\bsnmp-server\s+host\s+\S+.*?\bcommunity\s+)(\S+)(.*)"), rf"\1{REDACTION}\3"),
    (re.compile(r"(?i)(\bsnmp-server\s+host\s+\S+.*?\bversion\s+\S+\s+)(\S+)(.*)"), rf"\1{REDACTION}\3"),
    # Generic key=value or JSON-ish secrets
    (re.compile(r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|community|string)\s*[:=]\s*)([^\s,;\}\]]+)"), rf"\1{REDACTION}"),
    # Basic auth URLs
    (re.compile(r"(?i)(https?://)([^:/\s]+):([^@/\s]+)@"), rf"\1{REDACTION}:{REDACTION}@"),
]


def redact_text(value: Any) -> str:
    """Return a redacted string representation of any value."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_obj(obj: Any) -> Any:
    """Recursively redact dictionaries/lists while preserving shape."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            if _SECRET_KEY_RE.search(str(key)):
                out[key] = REDACTION if value not in (None, "") else value
            else:
                out[key] = redact_obj(value)
        return out
    if isinstance(obj, list):
        return [redact_obj(item) for item in obj]
    if isinstance(obj, tuple):
        return [redact_obj(item) for item in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


def redact_json_text(text: str) -> str:
    try:
        return json.dumps(redact_obj(json.loads(text)), indent=2, ensure_ascii=False)
    except Exception:
        return redact_text(text)
