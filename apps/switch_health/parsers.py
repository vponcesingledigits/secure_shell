from __future__ import annotations

import re
from collections import Counter, defaultdict
from .models import Finding

AUTH_NOISE = re.compile(r"(login|authentication|auth).*?(fail|reject|invalid|denied)|failed password|bad password", re.I)
PORT_RE = re.compile(r"(?P<port>(?:Gi|Te|Fa|Eth|Po|Trk|lag|mgmt)?\d+(?:/\d+){0,3}|\d+/\d+/\d+|\d+)", re.I)
SPEED_RE = re.compile(r"(?<!\d)(10|100|1000|2500|5000|10000|25000|40000|100000)\s*(?:M|Mb|Mbps|G|Gb|Gbps)?", re.I)

INFRA_HINTS = re.compile(r"(switch|core|uplink|trunk|fw|firewall|router|gateway|nomadix|icx|aruba|cisco|procurve|cx|lag|trk)", re.I)

def detect_vendor_from_text(text: str) -> tuple[str, str]:
    t = (text or "").lower()
    if "extremexos" in t or "extreme networks" in t or "exos" in t or "switchengine" in t:
        return "Extreme", "extreme_exos"
    if "aos-cx" in t or "arubaos-cx" in t or "service os version" in t:
        return "Aruba", "aruba_cx"
    if "ruckus" in t or "brocade" in t or "icx" in t or "fastiron" in t:
        return "Ruckus", "ruckus_icx"
    if "procurve" in t or "aruba 2530" in t or "aruba 2920" in t or "image stamp" in t:
        return "Aruba", "aruba_procurve"
    if "cisco ios" in t or "cisco" in t:
        return "Cisco", "cisco_ios"
    return "Unknown", "generic"


def hostname_from_output(text: str, fallback: str = "Unknown") -> str:
    patterns = [
        r"(?:System Name|Hostname|Name)\s*[:=]\s*([A-Za-z0-9_.-]+)",
        r"^\s*\*?\s*([A-Za-z0-9_.-]+)(?:\.\d+)?\s*[>#]\s*$",
        r"^\s*SSH@([A-Za-z0-9_.-]+)[>#]",
    ]
    for pat in patterns:
        m = re.search(pat, text or "", re.M | re.I)
        if m:
            return m.group(1).strip()
    return fallback


def add(findings: list[Finding], severity: str, category: str, title: str, detail: str, port: str = "", evidence: str = "", recommendation: str = "") -> None:
    findings.append(Finding(severity=severity, category=category, title=title, detail=detail, port=port, evidence=evidence[:500], recommendation=recommendation))


def analyze(result) -> list[Finding]:
    raw_joined = "\n".join(result.raw.values())
    findings: list[Finding] = []
    analyze_poe(raw_joined, findings)
    analyze_logs(raw_joined, findings)
    analyze_link_health(raw_joined, findings)
    analyze_environment(raw_joined, findings)
    analyze_resources(raw_joined, findings)
    if not findings:
        add(findings, "info", "summary", "No major health findings detected", "Collected commands did not match critical/warning health patterns.")
    return sorted(findings, key=lambda f: {"critical": 0, "warning": 1, "info": 2}.get(f.severity, 3))


def analyze_poe(text: str, findings: list[Finding]) -> None:
    if re.search(r"Device\s+vop\s+test\s+failed", text, re.I):
        add(findings, "critical", "PoE", "Ruckus pending PoE hardware failure", "`Device vop test failed` was found in inline power error messages. This is treated as a pending PoE hardware failure.", evidence="Device vop test failed", recommendation="Plan switch replacement/RMA or move powered devices before the failure becomes service-affecting.")

    counts = Counter()
    evidence = defaultdict(list)
    for line in text.splitlines():
        if AUTH_NOISE.search(line):
            continue
        if re.search(r"poe|power|inline", line, re.I) and re.search(r"overload|over load|denied|fault|short|class|PD overload", line, re.I):
            pm = PORT_RE.search(line)
            port = pm.group("port") if pm else "unknown"
            counts[port] += 1
            if len(evidence[port]) < 3:
                evidence[port].append(line.strip())
    for port, count in counts.items():
        sev = "critical" if re.search(r"fault|short", "\n".join(evidence[port]), re.I) else "warning"
        add(findings, sev, "PoE", f"PoE event deduplicated on {port}", f"Detected {count} PoE-related overload/fault event(s) for this port.", port=port, evidence="\n".join(evidence[port]), recommendation="Check endpoint power draw, cabling, requested class, and switch PoE budget.")


def analyze_logs(text: str, findings: list[Finding]) -> None:
    flaps = Counter(); evidence = defaultdict(list)
    for line in text.splitlines():
        if AUTH_NOISE.search(line):
            continue
        if re.search(r"flap|link.*down|down.*up|changed state|transition", line, re.I):
            pm = PORT_RE.search(line)
            port = pm.group("port") if pm else "unknown"
            flaps[port] += 1
            if len(evidence[port]) < 3:
                evidence[port].append(line.strip())
    for port, count in flaps.items():
        if count >= 2:
            add(findings, "warning", "Logs", f"Link flapping deduplicated on {port}", f"Detected {count} link transition/flap event(s).", port=port, evidence="\n".join(evidence[port]), recommendation="Check cable, optics, endpoint NIC, and the far-side port.")


def analyze_link_health(text: str, findings: list[Finding]) -> None:
    for line in text.splitlines():
        low = line.lower()
        if "half" in low and "duplex" in low:
            pm = PORT_RE.search(line)
            add(findings, "critical", "Link Health", "Half duplex detected", "Half duplex on a production switchport is treated as critical because it can cause severe performance issues.", port=pm.group("port") if pm else "", evidence=line.strip(), recommendation="Hard-check negotiation, cable, optics, and far-side port configuration.")
        if re.search(r"\b(10|100)\s*(?:m|mb|mbps)\b", low) and INFRA_HINTS.search(line):
            pm = PORT_RE.search(line)
            add(findings, "warning", "Link Health", "Low-speed infrastructure link", "A link that appears to be infrastructure/uplink is running below 1 Gbps.", port=pm.group("port") if pm else "", evidence=line.strip(), recommendation="Validate cabling/optic and far-side negotiation. Infrastructure links should normally be 1G/10G or better.")
        if re.search(r"crc|input error|output error|collision|queue drop|drops", low):
            nums = [int(n) for n in re.findall(r"\b\d+\b", line)]
            if any(n > 0 for n in nums):
                pm = PORT_RE.search(line)
                add(findings, "warning", "Link Health", "Interface errors detected", "The interface output includes non-zero CRC/error/drop counters.", port=pm.group("port") if pm else "", evidence=line.strip(), recommendation="Clear counters after maintenance, replace patching/optic as needed, and watch for recurrence.")


def analyze_environment(text: str, findings: list[Finding]) -> None:
    for line in text.splitlines():
        if re.search(r"fan|psu|power supply|temperature|temp|thermal", line, re.I) and re.search(r"fail|fault|bad|critical|shutdown|absent|not present|over", line, re.I):
            add(findings, "critical", "Environmental", "Environmental hardware fault", "Fan, PSU, or temperature output indicates a fault condition.", evidence=line.strip(), recommendation="Verify physical status, airflow, power supplies, and open vendor case if confirmed.")


def analyze_resources(text: str, findings: list[Finding]) -> None:
    for line in text.splitlines():
        if re.search(r"cpu|memory|resource", line, re.I):
            for val in re.findall(r"(\d{2,3})\s*%", line):
                pct = int(val)
                if pct >= 90:
                    add(findings, "critical", "Resources", "Very high Aruba CXOS/resource utilization", f"Resource utilization reached {pct}%.", evidence=line.strip(), recommendation="Check processes, logging storms, loops, and device software state.")
                elif pct >= 75:
                    add(findings, "warning", "Resources", "High Aruba CXOS/resource utilization", f"Resource utilization reached {pct}%.", evidence=line.strip(), recommendation="Monitor and investigate before it becomes service-affecting.")
