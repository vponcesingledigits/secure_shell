"""Compatibility wrapper for root shared parsers plus legacy helper names."""
from shared.parsers import *  # noqa: F401,F403

try:
    from shared.vendors import extract_hostname as parse_hostname  # noqa: F401
except Exception:
    def parse_hostname(output: str):
        return None

def normalize_port(port: str) -> str:
    return (port or '').strip().replace('ethernet', '').replace('Ethernet', '').strip()
