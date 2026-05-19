from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Tuple

from ..models import Finding

AUTH_NOISE = re.compile(r"(login failed|authentication failure|failed password|invalid user|aaa.*fail|radius.*reject|tacacs.*fail)", re.I)
PORT_RE = re.compile(r"(?:(?:eth|ethernet|gi|gigabitethernet|te|tengigabitethernet|port)\s*)?(\d+(?:/\d+){1,3}|[A-Za-z]+\d+/\d+/\d+|[A-Za-z]+\d+/\d+)", re.I)
SPEED_LOW_RE = re.compile(r"\b(10M|100M|10mb|100mb|10 Mbps|100 Mbps|a-100|100full|100half|10full|10half)\b", re.I)
HALF_RE = re.compile(r"\bhalf\b|\bHDX\b", re.I)
FAULT_RE = re.compile(r"\b(fail|failed|fault|faulty|critical|shutdown|overheat|overtemp|bad|not ok|absent|down)\b", re.I)
OK_FALSE_POSITIVE = re.compile(r"\b(no fault|not present|0 fault|OK|normal|good)\b", re.I)


def _port_from_line(line: str) -> str | None:
    m = PORT_RE.search(line)
    return m.group(1) if m else None


def _add(findings: List[Finding], severity: str, category: str, title: str, detail: str, evidence: str = "", port: str | None = None, count: int = 1) -> None:
    findings.append(Finding(severity=severity, category=category, title=title, detail=detail, evidence=evidence.strip()[:1200], port=port, count=count))


def parse_all(vendor: str, outputs: Dict[str, str]) -> List[Finding]:
    findings: List[Finding] = []
    text_by_command = {k: v or "" for k, v in outputs.items()}

    if vendor == "ruckus":
        parse_ruckus(findings, text_by_command)
    elif vendor == "aruba_cx":
        parse_aruba_cx(findings, text_by_command)
    elif vendor == "procurve":
        parse_procurve(findings, text_by_command)
    elif vendor == "cisco_ios":
        parse_cisco(findings, text_by_command)
    else:
        parse_generic(findings, text_by_command)

    dedupe_common(findings, text_by_command)
    return findings


def parse_ruckus(findings: List[Finding], outputs: Dict[str, str]) -> None:
    emesg = outputs.get("show inline power emesg", "")
    if re.search(r"Device\s+vop\s+test\s+failed", emesg, re.I):
        _add(findings, "critical", "PoE", "Pending PoE hardware failure", "Ruckus inline power event log contains 'Device vop test failed'. Treat as pending PoE hardware failure.", _matching_lines(emesg, r"Device\s+vop\s+test\s+failed"))
    _poe_overloads(findings, emesg + "\n" + outputs.get("show logging", ""))
    _environment(findings, outputs.get("show chassis", ""), "Environmental")
    _link_health(findings, outputs.get("show interfaces brief wide", "") or outputs.get("show interfaces brief", ""))


def parse_aruba_cx(findings: List[Finding], outputs: Dict[str, str]) -> None:
    _environment(findings, outputs.get("show environment", "") + "\n" + outputs.get("show environment temperature", ""), "Environmental")
    _link_health(findings, outputs.get("show interface brief", ""))
    _resource_utilization(findings, outputs.get("show system resource-utilization", ""))
    _poe_overloads(findings, outputs.get("show power-over-ethernet", "") + "\n" + outputs.get("show events", ""))


def parse_procurve(findings: List[Finding], outputs: Dict[str, str]) -> None:
    _link_health(findings, outputs.get("show interface brief", ""))
    _environment(findings, outputs.get("show system-information", ""), "Environmental")


def parse_cisco(findings: List[Finding], outputs: Dict[str, str]) -> None:
    _environment(findings, outputs.get("show environment all", ""), "Environmental")
    _link_health(findings, outputs.get("show interface status", ""))


def parse_generic(findings: List[Finding], outputs: Dict[str, str]) -> None:
    _environment(findings, "\n".join(outputs.values()), "Environmental")
    _link_health(findings, "\n".join(outputs.values()))


def dedupe_common(findings: List[Finding], outputs: Dict[str, str]) -> None:
    combined_logs = "\n".join(v for k, v in outputs.items() if re.search(r"log|event", k, re.I))
    _flapping(findings, combined_logs)


def _matching_lines(text: str, pattern: str, limit: int = 20) -> str:
    rx = re.compile(pattern, re.I)
    return "\n".join(line for line in text.splitlines() if rx.search(line))[:limit * 200]


def _poe_overloads(findings: List[Finding], text: str) -> None:
    counts: Counter[str] = Counter()
    evidence: dict[str, list[str]] = defaultdict(list)
    for line in text.splitlines():
        if AUTH_NOISE.search(line):
            continue
        if re.search(r"\b(overload|over current|over-current|denied|insufficient power|power.*fault|pd overload)\b", line, re.I):
            port = _port_from_line(line) or "unknown"
            counts[port] += 1
            if len(evidence[port]) < 8:
                evidence[port].append(line)
    for port, count in counts.items():
        sev = "critical" if re.search(r"fault|overload|over-current|over current", "\n".join(evidence[port]), re.I) else "warning"
        _add(findings, sev, "PoE", f"PoE fault/overload events on {port}", f"Detected {count} PoE overload/fault related events. Events are deduplicated by port.", "\n".join(evidence[port]), None if port == "unknown" else port, count)


def _flapping(findings: List[Finding], logs: str) -> None:
    counts: Counter[str] = Counter()
    evidence: dict[str, list[str]] = defaultdict(list)
    for line in logs.splitlines():
        if AUTH_NOISE.search(line):
            continue
        if re.search(r"\b(flapp|link.+down|down.+up|changed state to down|changed state to up|port.+down|port.+up)\b", line, re.I):
            port = _port_from_line(line) or "unknown"
            counts[port] += 1
            if len(evidence[port]) < 8:
                evidence[port].append(line)
    for port, count in counts.items():
        if count >= 2:
            _add(findings, "warning", "Link Health", f"Link flapping on {port}", f"Detected {count} link up/down or flapping log events. Login/authentication failures are ignored.", "\n".join(evidence[port]), None if port == "unknown" else port, count)


def _link_health(findings: List[Finding], text: str) -> None:
    for line in text.splitlines():
        if not line.strip() or re.search(r"port|interface", line, re.I) and re.search(r"status|speed|duplex", line, re.I):
            continue
        port = _port_from_line(line)
        if not port:
            continue
        if HALF_RE.search(line):
            _add(findings, "critical", "Link Health", f"Half duplex detected on {port}", "Half duplex links can cause severe performance issues and packet loss.", line, port)
        elif SPEED_LOW_RE.search(line) and re.search(r"\b(up|connected|forward|active)\b", line, re.I):
            _add(findings, "warning", "Link Health", f"Low-speed active link on {port}", "Active infrastructure link appears to be running below 1 Gbps. Validate expected endpoint type before remediation.", line, port)


def _environment(findings: List[Finding], text: str, category: str) -> None:
    for line in text.splitlines():
        lower = line.lower()
        if not any(word in lower for word in ("fan", "psu", "power supply", "temperature", "temp", "thermal", "chassis")):
            continue
        if FAULT_RE.search(line) and not OK_FALSE_POSITIVE.search(line):
            sev = "critical" if re.search(r"fail|failed|critical|overheat|overtemp|shutdown", line, re.I) else "warning"
            _add(findings, sev, category, "Environmental fault detected", "Fan, PSU, chassis, or temperature fault detected.", line)


def _resource_utilization(findings: List[Finding], text: str) -> None:
    for line in text.splitlines():
        percents = [int(p) for p in re.findall(r"(\d{1,3})\s*%", line)]
        if not percents:
            continue
        max_pct = max(p for p in percents if p <= 100)
        if max_pct >= 90:
            _add(findings, "critical", "Resources", "High resource utilization", f"Resource utilization reached {max_pct}%.", line)
        elif max_pct >= 75:
            _add(findings, "warning", "Resources", "Elevated resource utilization", f"Resource utilization reached {max_pct}%.", line)
