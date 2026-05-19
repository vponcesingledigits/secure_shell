from __future__ import annotations

import csv
import io
from copy import deepcopy
from typing import Any, Dict, List


def merge_project(scan_data: Dict[str, Any], manual_data: Dict[str, Any] | None = None) -> Dict[str, Any]:
    project = deepcopy(scan_data or {})
    manual = manual_data or {}
    for key in [
        "site", "isp_circuits", "manual_firewalls", "manual_gateways", "manual_esxi_hosts",
        "manual_pga_interfaces", "manual_rpm_vms", "vlans", "manual_links",
        "documentation_checklist", "revision_history"
    ]:
        value = manual.get(key)
        if value not in (None, ""):
            project[key] = value
        else:
            project.setdefault(key, [] if key not in ("site", "documentation_checklist") else {})
    project["schema"] = "single_digits.topology_asbuilt.v1"
    project.setdefault("exports", {})
    return project


def port_sheet_tsv(project: Dict[str, Any]) -> str:
    rows = project.get("ports", []) or []
    out = io.StringIO()
    writer = csv.writer(out, delimiter="\t", lineterminator="\n")
    header = ["Switch Name", "Local Port ID", "Local Port Name", "Patch Panel Port", "Remote Hostname", "Remote IP", "Suggested Port Name"]
    current_switch = None
    writer.writerow(header)
    for row in sorted(rows, key=lambda r: (r.get("switch_name", ""), r.get("local_port_id", ""))):
        sw = row.get("switch_name", "")
        if current_switch is not None and sw != current_switch:
            writer.writerow([])  # hard line break between switches
            writer.writerow(header)
        current_switch = sw
        writer.writerow([
            sw,
            row.get("local_port_id", ""),
            row.get("local_port_name", ""),
            "",  # Patch Panel Port always blank
            row.get("remote_hostname", ""),
            row.get("remote_ip", ""),
            row.get("suggested_port_name", ""),
        ])
    return out.getvalue()


def ncm_ai_export(project: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema": "single_digits.ncm.topology.v1",
        "site": project.get("site", {}),
        "devices": project.get("devices", []),
        "links": project.get("links", []) + _manual_links_as_links(project),
        "ports": [{**p, "patch_panel_port": ""} for p in project.get("ports", [])],
        "vlans": project.get("vlans", []),
        "manual_objects": {
            "isp_circuits": project.get("isp_circuits", []),
            "firewalls": project.get("manual_firewalls", []),
            "gateways": project.get("manual_gateways", []),
            "esxi_hosts": project.get("manual_esxi_hosts", []),
            "pga_interfaces": project.get("manual_pga_interfaces", []),
            "rpm_vms": project.get("manual_rpm_vms", []),
        },
        "scan_metadata": project.get("scan_settings", {}),
        "assumptions": [
            "Patch Panel Port is intentionally blank unless populated manually outside the scanner.",
            "Remote Hostname is LLDP system-name only.",
            "SSH target IP may differ from switch management IP discovered from LLDP/device output.",
            "Salesforce and Zabbix exports are preview schemas pending final team-specific import requirements.",
        ],
    }


def salesforce_preview_export(project: Dict[str, Any]) -> Dict[str, Any]:
    site = project.get("site", {}) or {}
    site_code = site.get("site_code", "") or site.get("Site Code", "")
    records: List[Dict[str, Any]] = []

    def add_records(object_type: str, items: List[Dict[str, Any]]):
        for idx, item in enumerate(items, 1):
            records.append({
                "local_id": item.get("local_id") or f"{object_type.lower().replace(' ', '-')}-{idx:03d}",
                "object_type": object_type,
                "site_code": site_code,
                "salesforce_record_id": item.get("salesforce", {}).get("salesforce_record_id", "") if isinstance(item.get("salesforce"), dict) else "",
                "sync_status": "preview_only",
                "fields": item,
            })

    add_records("ISP Circuit", project.get("isp_circuits", []) or [])
    add_records("Firewall", project.get("manual_firewalls", []) or [])
    add_records("Gateway", project.get("manual_gateways", []) or [])
    add_records("ESXi Host", project.get("manual_esxi_hosts", []) or [])
    add_records("PGA VM", project.get("manual_pga_interfaces", []) or [])
    add_records("RPM VM", project.get("manual_rpm_vms", []) or [])
    add_records("VLAN", project.get("vlans", []) or [])
    add_records("Manual Link", project.get("manual_links", []) or [])
    return {
        "schema": "single_digits.salesforce.preview.v1",
        "note": "Preview export only. Final Salesforce object names/fields/import format must be confirmed with Salesforce team.",
        "site": site,
        "records": records,
    }


def zabbix_preview_export(project: Dict[str, Any]) -> Dict[str, Any]:
    site = project.get("site", {}) or {}
    site_code = site.get("site_code", "") or site.get("Site Code", "") or "UnknownSite"
    hosts: List[Dict[str, Any]] = []

    def add_host(name: str, ip: str, role: str, notes: str = ""):
        if not name and not ip:
            return
        hosts.append({
            "host": safe_host(name or ip),
            "visible_name": name or ip,
            "management_ip": ip,
            "role": role,
            "groups": [f"Single Digits/{site_code}", role_group(role)],
            "suggested_templates": suggested_templates(role),
            "notes": notes,
        })

    for d in project.get("devices", []) or []:
        add_host(d.get("name", ""), d.get("management_ip", ""), d.get("role", "unknown"), "Discovered by topology scan")
    for fw in project.get("manual_firewalls", []) or []:
        add_host(fw.get("hostname", ""), fw.get("wan1_ip", ""), "firewall", "Manual firewall card")
    for gw in project.get("manual_gateways", []) or []:
        add_host(gw.get("hostname", ""), gw.get("wan1_ip", ""), "gateway", "Manual gateway card")
    for esx in project.get("manual_esxi_hosts", []) or []:
        add_host(esx.get("hostname", ""), esx.get("management_ip", ""), "esxi", "Manual ESXi card")
    for pga in project.get("manual_pga_interfaces", []) or []:
        add_host(pga.get("pga_vm_name", ""), pga.get("pga_ip", ""), "pga_vm", "Manual PGA VM card")
    for rpm in project.get("manual_rpm_vms", []) or []:
        add_host(rpm.get("rpm_vm_name", ""), rpm.get("rpm_ip", ""), "rpm_vm", "Manual RPM VM card")

    return {
        "schema": "single_digits.zabbix.preview.v1",
        "note": "Preview export only. Final Zabbix import XML/API requirements must be confirmed with Zabbix team.",
        "site": site,
        "hosts": hosts,
    }


def _manual_links_as_links(project: Dict[str, Any]) -> List[Dict[str, Any]]:
    converted = []
    for i, link in enumerate(project.get("manual_links", []) or [], 1):
        converted.append({
            "local_id": link.get("local_id") or f"manual-link-{i:03d}",
            "source_device": link.get("from_device", ""),
            "source_port": link.get("from_interface", ""),
            "target_device": link.get("to_device", ""),
            "target_port": link.get("to_interface", ""),
            "target_role": link.get("link_type", "manual"),
            "source": "manual",
            "notes": link.get("notes", ""),
        })
    return converted


def safe_host(value: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in (value or "")).strip("_")


def role_group(role: str) -> str:
    mapping = {
        "switch": "Network/Switches",
        "firewall": "Network/Firewalls",
        "gateway": "Network/Gateways",
        "access_point": "Wireless/Access Points",
        "esxi": "Virtualization/ESXi",
        "pga_vm": "Virtualized Services/PGA",
        "rpm_vm": "Virtualized Services/RPM",
    }
    return mapping.get(role, f"Other/{role or 'unknown'}")


def suggested_templates(role: str) -> List[str]:
    mapping = {
        "switch": ["Template Module ICMP Ping", "Network Switch Generic SNMP"],
        "firewall": ["Template Module ICMP Ping", "Firewall Generic"],
        "gateway": ["Template Module ICMP Ping", "Gateway Generic"],
        "access_point": ["Template Module ICMP Ping", "Wireless AP Generic"],
        "esxi": ["Template Module ICMP Ping", "VMware Hypervisor"],
        "pga_vm": ["Template Module ICMP Ping", "TCP Service Check"],
        "rpm_vm": ["Template Module ICMP Ping"],
    }
    return mapping.get(role, ["Template Module ICMP Ping"])
