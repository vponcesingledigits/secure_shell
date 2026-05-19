from __future__ import annotations

import json
import re
from typing import Any, Iterable

REDACTION = "[REDACTED]"

_SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|community|token|api[_-]?key|apikey|credential|auth|private|snmp|tacacs|radius)"
)

# Redact key/value secrets through the end of the line.  The old \S+ style
# missed secrets containing spaces and several common delimiter styles.
_LINE_SECRET_PATTERNS = [
    re.compile(r"(?im)\b(password|passwd|pwd|secret|community|token|api[_-]?key|apikey|credential|auth|private|snmp|tacacs|radius)\b\s*([:=])\s*([^\r\n]+)"),
    re.compile(r"(?im)\b(snmp-server\s+community|community|password|secret)\s+(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\r\n]+)"),
]

def _redact_line_match(match: re.Match) -> str:
    if match.lastindex == 3:
        return f"{match.group(1)}{match.group(2)} {REDACTION}"
    return f"{match.group(1)} {REDACTION}"

def redact_text(value: Any, extra_secrets: Iterable[str] = ()) -> str:
    text = "" if value is None else str(value)

    # Replace known secret values first, longest-first, case-insensitive.
    secrets = [str(s) for s in (extra_secrets or []) if s]
    for secret in sorted(set(secrets), key=len, reverse=True):
        text = re.sub(re.escape(secret), REDACTION, text, flags=re.I)

    for pattern in _LINE_SECRET_PATTERNS:
        text = pattern.sub(_redact_line_match, text)
    return text

def redact_obj(obj: Any, extra_secrets: Iterable[str] = ()) -> Any:
    if isinstance(obj, dict):
        cleaned = {}
        for key, val in obj.items():
            if _SECRET_KEY_RE.search(str(key)):
                cleaned[key] = REDACTION
            else:
                cleaned[key] = redact_obj(val, extra_secrets)
        return cleaned
    if isinstance(obj, list):
        return [redact_obj(item, extra_secrets) for item in obj]
    if isinstance(obj, tuple):
        return tuple(redact_obj(item, extra_secrets) for item in obj)
    if isinstance(obj, str):
        return redact_text(obj, extra_secrets)
    return obj

def redact_json_text(text: str, extra_secrets: Iterable[str] = ()) -> str:
    try:
        return json.dumps(redact_obj(json.loads(text), extra_secrets), indent=2, ensure_ascii=False)
    except Exception:
        return redact_text(text, extra_secrets)

def safe_client_error(exc: Exception | str, extra_secrets: Iterable[str] = (), default: str = "Operation failed. See server log for details.") -> str:
    msg = redact_text(str(exc), extra_secrets)
    # Do not return detailed paths, tracebacks, or Paramiko internals to the browser.
    if any(marker in msg.lower() for marker in ("traceback", "paramiko", "password", "secret", "community", "c:\\", "/users/", "\\users\\")):
        return default
    return msg[:500] if msg else default
