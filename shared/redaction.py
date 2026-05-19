from __future__ import annotations

import os
import re

_SECRET_PATTERNS = [
    re.compile(r'(?i)(password\s+(?:manager\s+user-name\s+\S+\s+plaintext\s+))\S+'),
    re.compile(r'(?i)(password\s+plaintext\s+)\S+'),
    re.compile(r'(?i)(secret\s+)\S+'),
    re.compile(r'(?i)(community\s+"?)([^"\s]+)("?)'),
    re.compile(r'(?i)(snmp-server\s+community\s+"?)([^"\s]+)("?)'),
    re.compile(r'(?i)(tacacs-server\s+key\s+(?:7\s+)?)\S+'),
]


def _env_secrets() -> list[str]:
    tokens: list[str] = []
    for key, value in os.environ.items():
        if not value or len(value) < 4:
            continue
        if any(marker in key.upper() for marker in ("PASSWORD", "PASS", "SECRET", "COMMUNITY", "KEY", "TOKEN")):
            tokens.append(value)
    return tokens


def redact(text: str, extra_secrets: list[str] | tuple[str, ...] | None = None) -> str:
    value = text or ""
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub(lambda m: m.group(1) + "***REDACTED***" + (m.group(3) if len(m.groups()) >= 3 else ""), value)
    for secret in [*(_env_secrets()), *((extra_secrets or []))]:
        if secret:
            value = value.replace(secret, "***REDACTED***")
    return value
