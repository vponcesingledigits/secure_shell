from __future__ import annotations
import ipaddress
from dataclasses import dataclass
@dataclass(frozen=True)
class Target:
    host: str
    port: int = 22
    label: str = ""
def parse_target_line(line: str, default_port: int = 22) -> Target | None:
    raw = (line or '').strip()
    if not raw or raw.startswith('#'): return None
    if ':' in raw and raw.count(':') == 1 and '/' not in raw:
        host, port = raw.rsplit(':', 1)
        try: return Target(host.strip(), int(port), raw)
        except ValueError: return Target(raw, default_port, raw)
    return Target(raw, default_port, raw)
def expand_targets(text: str, default_port: int = 22, max_hosts: int = 4096) -> list[Target]:
    out: list[Target] = []
    for line in (text or '').replace(',', '\n').splitlines():
        line=line.strip()
        if not line: continue
        if '/' in line:
            try:
                for ip in list(ipaddress.ip_network(line, strict=False).hosts())[:max_hosts]:
                    out.append(Target(str(ip), default_port, line))
                continue
            except ValueError:
                pass
        t=parse_target_line(line, default_port)
        if t: out.append(t)
    return out
