
from __future__ import annotations

import csv
import io
import json
import os
import re
import time
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin

import requests


MAC_RE = re.compile(r"\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b|\b[0-9a-f]{12}\b", re.I)


def normalize_mac(value: str | None, sep: str = ":") -> str:
    if not value:
        return ""
    raw = re.sub(r"[^0-9a-fA-F]", "", str(value))
    if len(raw) != 12:
        return str(value).strip()
    return sep.join(raw[i:i + 2] for i in range(0, 12, 2)).lower()


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if any(s in k.lower() for s in ("password", "ticket", "token", "cookie", "secret", "credential")):
                out[k] = "***REDACTED***"
            else:
                out[k] = redact(v)
        return out
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def load_api_profiles() -> Dict[str, Any]:
    here = os.path.dirname(__file__)
    path = os.path.join(here, "data", "smartzone_api_profiles.json")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def get_profile(profile_id: str = "", api_version: str = "") -> Dict[str, Any]:
    data = load_api_profiles()
    profiles = data.get("profiles", [])
    for p in profiles:
        if profile_id and p.get("id") == profile_id:
            return p
    # Infer a profile from the selected API version when possible.
    for p in profiles:
        if api_version and api_version in p.get("api_versions", []):
            return p
    return next((p for p in profiles if p.get("id") == "vszh-6.1.2"), profiles[0] if profiles else {})


@dataclass
class SmartZoneResult:
    ok: bool
    status_code: int = 0
    data: Any = None
    error: str = ""
    endpoint: str = ""


@dataclass
class SmartZoneClient:
    base_url: str
    username: str
    password: str
    api_version: str = "v11_1"
    profile_id: str = "vszh-6.1.2"
    verify_ssl: bool = False
    timeout: int = 30
    debug: bool = False
    service_ticket: str = ""
    session: requests.Session = field(default_factory=requests.Session)
    transcript: List[Dict[str, Any]] = field(default_factory=list)
    active_prefix: str = ""

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/") + "/"
        self.profile = get_profile(self.profile_id, self.api_version)
        if not self.api_version or self.api_version == "auto":
            self.api_version = self.profile.get("recommended_api_version", "v11_1")
        self.prefixes = self.profile.get("public_prefixes", ["wsg/api/public", "api/public"])
        self.session.verify = self.verify_ssl
        self.session.headers.update({"Content-Type": "application/json;charset=UTF-8", "Accept": "application/json"})

    def _url(self, path: str) -> str:
        path = path.lstrip("/")
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return urljoin(self.base_url, path)

    def _params(self, extra: Optional[Dict[str, Any]] = None, include_ticket: bool = True) -> Dict[str, Any]:
        params = dict(extra or {})
        if include_ticket and self.service_ticket:
            params.setdefault("serviceTicket", self.service_ticket)
        return params

    def candidate_paths(self, endpoint: str, include_bare: bool = True) -> List[str]:
        endpoint = endpoint.lstrip("/")
        paths = []
        if self.active_prefix:
            paths.append(f"{self.active_prefix.rstrip('/')}/{endpoint}")
        for prefix in self.prefixes:
            p = prefix.strip("/")
            paths.append(f"{p}/{endpoint}" if p else endpoint)
        if include_bare:
            paths.append(endpoint)
        # Preserve order while de-duplicating.
        seen, out = set(), []
        for p in paths:
            if p not in seen:
                out.append(p)
                seen.add(p)
        return out

    def request(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None,
                json_body: Any = None, stream: bool = False, include_ticket: bool = True) -> SmartZoneResult:
        url = self._url(path)
        started = time.time()
        rec = {"method": method.upper(), "path": path, "params": redact(params or {}), "json": redact(json_body)}
        try:
            r = self.session.request(
                method.upper(),
                url,
                params=self._params(params, include_ticket=include_ticket),
                json=json_body,
                timeout=self.timeout,
                stream=stream,
            )
            rec.update({"status_code": r.status_code, "elapsed_ms": int((time.time() - started) * 1000)})
            self.transcript.append(rec)
            if stream:
                if not r.ok:
                    return SmartZoneResult(False, r.status_code, error=r.text[:1000], endpoint=path)
                return SmartZoneResult(True, r.status_code, data=r.content, endpoint=path)
            if not r.text:
                return SmartZoneResult(r.ok, r.status_code, data=None, endpoint=path)
            ctype = r.headers.get("Content-Type", "")
            try:
                data = r.json() if "json" in ctype.lower() or r.text[:1] in "[{" else r.text
            except Exception:
                data = r.text
            return SmartZoneResult(r.ok, r.status_code, data=data, error="" if r.ok else str(data)[:1000], endpoint=path)
        except Exception as e:
            rec.update({"error": str(e)})
            self.transcript.append(rec)
            return SmartZoneResult(False, error=str(e), endpoint=path)

    def request_any(self, method: str, endpoint: str, *, params: Optional[Dict[str, Any]] = None,
                    json_body: Any = None, stream: bool = False, include_ticket: bool = True) -> SmartZoneResult:
        last = SmartZoneResult(False, error="No endpoint attempted.", endpoint=endpoint)
        for path in self.candidate_paths(endpoint):
            res = self.request(method, path, params=params, json_body=json_body, stream=stream, include_ticket=include_ticket)
            if res.ok:
                # Remember the working prefix for the rest of the investigation.
                if "/" in path and path.endswith(endpoint.lstrip("/")):
                    self.active_prefix = path[: -len(endpoint.lstrip("/"))].rstrip("/")
                return res
            last = res
        return last

    def login(self) -> SmartZoneResult:
        # Public API service-ticket logon; serviceTicket is then passed as URI parameter.
        res = self.request_any(
            "POST",
            f"{self.api_version}/serviceTicket",
            json_body={"username": self.username, "password": self.password},
            include_ticket=False,
        )
        if res.ok:
            data = res.data or {}
            ticket = ""
            if isinstance(data, dict):
                nested = data.get("data") if isinstance(data.get("data"), dict) else {}
                ticket = data.get("serviceTicket") or data.get("ticket") or nested.get("serviceTicket") or nested.get("ticket") or ""
            if not ticket:
                m = re.search(r'"serviceTicket"\s*:\s*"([^"]+)"', json.dumps(data))
                ticket = m.group(1) if m else ""
            self.service_ticket = ticket
            if not ticket:
                res.ok = False
                res.error = "Login succeeded but no serviceTicket was found in the response."
        return res

    def logout(self) -> SmartZoneResult:
        if not self.service_ticket:
            return SmartZoneResult(True, data={"message": "No active service ticket."})
        res = self.request_any("DELETE", f"{self.api_version}/serviceTicket")
        self.service_ticket = ""
        return res

    def get_api_info(self) -> SmartZoneResult:
        # Useful for validating controller/API compatibility.
        return self.request_any("GET", f"{self.api_version}/apiInfo")

    def query_aps(self, search: str = "", domain_id: str = "", zone_id: str = "", limit: int = 200) -> SmartZoneResult:
        body = query_criteria(search, domain_id, zone_id, limit)
        return self.request_any("POST", f"{self.api_version}/query/ap", json_body=body)

    def get_ap_list(self, domain_id: str = "", zone_id: str = "", limit: int = 1000) -> SmartZoneResult:
        params = {"listSize": str(limit)}
        if domain_id: params["domainId"] = domain_id
        if zone_id: params["zoneId"] = zone_id
        return self.request_any("GET", f"{self.api_version}/aps", params=params)

    def get_ap_summary(self, ap_mac: str) -> SmartZoneResult:
        ap_mac = normalize_mac(ap_mac)
        candidates = [
            f"{self.api_version}/aps/{ap_mac}/operational/summary",
            f"{self.api_version}/aps/{ap_mac}/operational",
        ]
        return first_ok(self, "GET", candidates)

    def get_ap_config(self, ap_mac: str) -> SmartZoneResult:
        ap_mac = normalize_mac(ap_mac)
        return self.request_any("GET", f"{self.api_version}/aps/{ap_mac}")

    def download_support_log(self, ap_mac: str) -> SmartZoneResult:
        ap_mac = normalize_mac(ap_mac)
        return self.request_any("GET", f"{self.api_version}/aps/{ap_mac}/supportLog", stream=True)

    def query_clients(self, client_mac: str = "", ap_mac: str = "", domain_id: str = "", zone_id: str = "", limit: int = 100) -> SmartZoneResult:
        search = normalize_mac(client_mac) if client_mac else ""
        body = query_criteria(search, domain_id, zone_id, limit)
        res = self.request_any("POST", f"{self.api_version}/query/client", json_body=body)
        if res.ok and ap_mac:
            res.data = filter_records_by_mac(res.data, ap_mac)
        return res

    def query_alerts(self, kind: str, search: str = "", domain_id: str = "", zone_id: str = "", limit: int = 100) -> SmartZoneResult:
        endpoint = "event/list" if kind == "event" else "alarm/list"
        body = query_criteria(search, domain_id, zone_id, limit)
        # Older/newer SmartZone builds expose alert endpoints with the same pattern but different API versions.
        return self.request_any("POST", f"{self.api_version}/alert/{endpoint}", json_body=body)


def first_ok(client: SmartZoneClient, method: str, endpoints: List[str]) -> SmartZoneResult:
    last = SmartZoneResult(False, error="No endpoint attempted.")
    for ep in endpoints:
        res = client.request_any(method, ep)
        if res.ok:
            return res
        last = res
    return last


def query_criteria(search: str = "", domain_id: str = "", zone_id: str = "", limit: int = 100) -> Dict[str, Any]:
    filters = []
    if domain_id:
        filters.append({"type": "DOMAIN", "value": domain_id})
    if zone_id:
        filters.append({"type": "ZONE", "value": zone_id})
    return {
        "filters": filters,
        "fullTextSearch": {"type": "AND", "value": search or ""},
        "page": 1,
        "limit": limit,
        "sortInfo": {"sortColumn": "name", "dir": "ASC"},
    }


def records_from_response(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if not isinstance(data, dict):
        return []
    if isinstance(data.get("data"), dict):
        nested = records_from_response(data["data"])
        if nested:
            return nested
    for key in ("list", "items", "results", "records"):
        val = data.get(key)
        if isinstance(val, list):
            return [x for x in val if isinstance(x, dict)]
        if isinstance(val, dict):
            nested = records_from_response(val)
            if nested:
                return nested
    return [data]


def filter_records_by_mac(data: Any, mac: str) -> Any:
    target = normalize_mac(mac)
    target_flat = target.replace(":", "")
    rows = records_from_response(data)
    out = []
    for row in rows:
        js = json.dumps(row, default=str).lower()
        js_flat = re.sub(r"[^0-9a-f]", "", js)
        if target in js or target_flat in js_flat:
            out.append(row)
    if isinstance(data, dict):
        clone = dict(data)
        if isinstance(clone.get("data"), dict) and isinstance(clone["data"].get("list"), list):
            clone["data"] = dict(clone["data"])
            clone["data"]["list"] = out
            clone["data"]["totalCount"] = len(out)
            return clone
        clone["list"] = out
        clone["totalCount"] = len(out)
        return clone
    return out


def extract_mac_trace_records(upload_bytes: bytes, filename: str = "") -> List[Dict[str, Any]]:
    name = (filename or "").lower()
    text = upload_bytes.decode("utf-8", errors="ignore")
    records: List[Dict[str, Any]] = []

    if name.endswith(".json") or text.lstrip().startswith(("{", "[")):
        try:
            obj = json.loads(text)
            candidates = []
            if isinstance(obj, list):
                candidates = obj
            elif isinstance(obj, dict):
                for key in ("aps", "access_points", "ap_results", "path", "hops", "records", "results", "trace", "devices"):
                    if isinstance(obj.get(key), list):
                        candidates.extend(obj[key])
            for item in candidates:
                if isinstance(item, dict):
                    records.append(item)
        except Exception:
            pass

    if not records and (name.endswith(".csv") or "," in text[:1000]):
        try:
            reader = csv.DictReader(io.StringIO(text))
            records = [dict(r) for r in reader]
        except Exception:
            records = []

    if not records:
        for line in text.splitlines():
            macs = [normalize_mac(m.group(0)) for m in MAC_RE.finditer(line)]
            if macs:
                records.append({"raw": line, "macs": macs})

    normalized = []
    for rec in records:
        js = json.dumps(rec, default=str)
        macs = [normalize_mac(m.group(0)) for m in MAC_RE.finditer(js)]
        ap_mac = first_value(rec, ("ap_mac", "apMac", "ap mac", "neighbor_mac", "neighborMac", "bssid", "radioMac", "apRadioMac"))
        client_mac = first_value(rec, ("client_mac", "clientMac", "target_mac", "targetMac", "mac", "station_mac"))
        ap_name = first_value(rec, ("ap_name", "apName", "neighbor", "neighbor_name", "device", "systemName", "hostname", "name"))
        ap_ip = first_value(rec, ("ap_ip", "apIp", "neighbor_ip", "neighborIp", "ip", "managementIp", "mgmtIp"))
        normalized.append({
            "ap_name": ap_name,
            "ap_ip": ap_ip,
            "ap_mac": normalize_mac(ap_mac) if ap_mac else (macs[0] if macs else ""),
            "client_mac": normalize_mac(client_mac) if client_mac and normalize_mac(client_mac) != normalize_mac(ap_mac) else "",
            "source": rec,
        })
    return normalized


def first_value(d: Dict[str, Any], keys: Iterable[str]) -> str:
    lowered = {str(k).lower().replace(" ", "_").replace("-", "_"): v for k, v in d.items()}
    for key in keys:
        k = key.lower().replace(" ", "_").replace("-", "_")
        if k in lowered and lowered[k] not in (None, ""):
            return str(lowered[k])
    return ""


def summarize_findings(ap_summary: Any, ap_config: Any, clients: Any, alarms: Any, events: Any, client_mac: str = "") -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    ap_rows = records_from_response(ap_summary)
    cfg_rows = records_from_response(ap_config)
    merged = {}
    for src in (cfg_rows + ap_rows):
        merged.update(src)
    state_blob = json.dumps(merged, default=str).lower()

    if not merged:
        findings.append({"severity": "warning", "title": "AP not found", "detail": "SmartZone did not return AP configuration or operational summary for this AP."})
    elif any(s in state_blob for s in ("disconnect", "offline", '"state": "down"', '"status": "down"', "heartbeat lost")):
        findings.append({"severity": "critical", "title": "AP appears offline or disconnected", "detail": "Operational/configuration data contains offline, down, disconnected, or heartbeat-loss indicators."})
    else:
        findings.append({"severity": "info", "title": "AP returned controller data", "detail": "SmartZone returned AP configuration and/or operational summary."})

    client_rows = records_from_response(clients)
    if client_mac:
        if client_rows:
            findings.append({"severity": "info", "title": "Client found in SmartZone", "detail": f"{len(client_rows)} matching client record(s) returned for {normalize_mac(client_mac)}."})
        else:
            findings.append({"severity": "warning", "title": "Client not found", "detail": f"No current client record was returned for {normalize_mac(client_mac)}."})

    alarm_rows = records_from_response(alarms)
    event_rows = records_from_response(events)
    if alarm_rows:
        findings.append({"severity": "warning", "title": "Relevant alarms returned", "detail": f"{len(alarm_rows)} alarm record(s) matched the AP/client search."})
    if event_rows:
        findings.append({"severity": "info", "title": "Relevant events returned", "detail": f"{len(event_rows)} event record(s) matched the AP/client search."})
    if not alarm_rows and not event_rows:
        findings.append({"severity": "info", "title": "No matching controller events/alarms", "detail": "SmartZone did not return matching alarm/event records for the AP/client search."})
    return findings


def build_evidence_zip(payload: Dict[str, Any], support_log: bytes | None = None) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("smartzone_investigation.json", json.dumps(redact(payload), indent=2, default=str))
        z.writestr("summary.txt", render_text_summary(payload))
        if support_log:
            z.writestr("ap_support_log.bin", support_log)
    return bio.getvalue()


def render_text_summary(payload: Dict[str, Any]) -> str:
    lines = ["SmartZone AP Investigation", "=" * 28, ""]
    target = payload.get("target", {})
    for k in ("ap_name", "ap_ip", "ap_mac", "client_mac"):
        if target.get(k):
            lines.append(f"{k}: {target[k]}")
    api = payload.get("api", {})
    lines.append("")
    lines.append(f"API profile: {api.get('profile_id','')}")
    lines.append(f"API version: {api.get('api_version','')}")
    lines.append(f"Working prefix: {api.get('active_prefix','')}")
    lines.append("")
    lines.append("Findings:")
    for f in payload.get("findings", []):
        lines.append(f"- [{f.get('severity','info').upper()}] {f.get('title')}: {f.get('detail')}")
    lines.append("")
    lines.append("API transcript is included in smartzone_investigation.json with credentials redacted.")
    return "\n".join(lines)
