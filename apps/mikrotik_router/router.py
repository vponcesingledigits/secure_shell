from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from app.config import APP_NAME, APP_VERSION, FAVICON_URL

router = APIRouter(tags=["mikrotik-router"])
templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")


@dataclass
class MikroTikConfigRequest:
    site_name: str = ""
    router_identity: str = ""
    wan_interface: str = "ether1"
    wan_mode: str = "dhcp"
    wan_ip_cidr: str = ""
    wan_gateway: str = ""
    lan_bridge: str = "bridge-lan"
    lan_interfaces: str = "ether2, ether3, ether4, ether5"
    lan_ip_cidr: str = "192.168.88.1/24"
    dns_servers: str = "1.1.1.1, 8.8.8.8"
    sdacl_networks: str = ""
    admin_allow_networks: str = ""
    enable_dhcp_server: bool = False
    dhcp_pool_start: str = ""
    dhcp_pool_end: str = ""
    dhcp_lease_time: str = "8h"
    enable_snmp: bool = False
    snmp_community: str = ""
    snmp_location: str = ""
    snmp_contact: str = ""
    notes: str = ""


def _split_csv_lines(value: str) -> list[str]:
    tokens: list[str] = []
    for raw in (value or "").replace("\r", "\n").replace(",", "\n").split("\n"):
        item = raw.strip()
        if item:
            tokens.append(item)
    return tokens


def _safe_router_name(value: str, fallback: str = "SingleDigits-Router") -> str:
    cleaned = "".join(ch for ch in (value or "").strip() if ch.isalnum() or ch in "-_.")
    return cleaned or fallback


def _validate_networks(values: list[str]) -> list[str]:
    good: list[str] = []
    for value in values:
        try:
            good.append(str(ip_network(value, strict=False)))
        except Exception:
            # Keep generation forgiving; invalid inputs are emitted as comments instead of commands.
            good.append(f"INVALID:{value}")
    return good


def sanitize_config(config: str) -> str:
    """Remove sensitive values from generated/exported config."""
    redacted_lines: list[str] = []
    sensitive_keys = ("community=", "password=", "secret=", "authentication-password=", "encryption-password=")
    for line in config.splitlines():
        scrubbed = line
        for key in sensitive_keys:
            if key in scrubbed:
                prefix, _sep, _rest = scrubbed.partition(key)
                scrubbed = prefix + key + '"<REDACTED>"'
        redacted_lines.append(scrubbed)
    return "\n".join(redacted_lines)


def build_routeros_config(req: MikroTikConfigRequest) -> str:
    identity = _safe_router_name(req.router_identity or req.site_name)
    lan_ports = _split_csv_lines(req.lan_interfaces)
    sdacl = _validate_networks(_split_csv_lines(req.sdacl_networks))
    admin_allow = _validate_networks(_split_csv_lines(req.admin_allow_networks))
    dns = _split_csv_lines(req.dns_servers)

    lines: list[str] = []
    lines.append("# ============================================================")
    lines.append("# Single Digits Engineering Platform - MikroTik Router Builder")
    lines.append("# RouterOS v7 public circuit router config")
    lines.append("# Generate-only module. Review before paste/import.")
    lines.append("# ============================================================")
    if req.site_name:
        lines.append(f"# Site: {req.site_name}")
    if req.notes:
        lines.append(f"# Notes: {req.notes.replace(chr(10), ' | ')}")
    lines.append("")

    lines.append("/system identity")
    lines.append(f"set name=\"{identity}\"")
    lines.append("")

    lines.append("# LAN bridge")
    lines.append("/interface bridge")
    lines.append(f"add name={req.lan_bridge} protocol-mode=rstp comment=\"Single Digits LAN bridge\"")
    if lan_ports:
        lines.append("/interface bridge port")
        for port in lan_ports:
            lines.append(f"add bridge={req.lan_bridge} interface={port}")
    lines.append("")

    lines.append("# Addressing")
    lines.append("/ip address")
    lines.append(f"add address={req.lan_ip_cidr} interface={req.lan_bridge} comment=\"LAN gateway\"")
    if req.wan_mode == "static" and req.wan_ip_cidr:
        lines.append(f"add address={req.wan_ip_cidr} interface={req.wan_interface} comment=\"WAN public circuit\"")
    lines.append("")

    if req.wan_mode == "dhcp":
        lines.append("/ip dhcp-client")
        lines.append(f"add interface={req.wan_interface} add-default-route=yes use-peer-dns=no disabled=no comment=\"WAN DHCP client\"")
    elif req.wan_gateway:
        lines.append("/ip route")
        lines.append(f"add dst-address=0.0.0.0/0 gateway={req.wan_gateway} comment=\"WAN default route\"")
    lines.append("")

    if dns:
        lines.append("/ip dns")
        lines.append(f"set allow-remote-requests=no servers={','.join(dns)}")
        lines.append("")

    if req.enable_dhcp_server and req.dhcp_pool_start and req.dhcp_pool_end:
        lines.append("# Optional LAN DHCP server")
        lines.append("/ip pool")
        lines.append(f"add name=sd-lan-pool ranges={req.dhcp_pool_start}-{req.dhcp_pool_end}")
        lines.append("/ip dhcp-server")
        lines.append(f"add name=sd-lan-dhcp interface={req.lan_bridge} address-pool=sd-lan-pool lease-time={req.dhcp_lease_time} disabled=no")
        lines.append("# Review /ip dhcp-server network values before applying.")
        lines.append("")

    lines.append("# Single Digits management ACL address lists")
    lines.append("/ip firewall address-list")
    if sdacl:
        for net in sdacl:
            if net.startswith("INVALID:"):
                lines.append(f"# INVALID SDACL network skipped: {net[8:]}")
            else:
                lines.append(f"add list=SDACL address={net} comment=\"Single Digits ACL\"")
    else:
        lines.append("# Add SDACL networks before deployment, for example: add list=SDACL address=x.x.x.x/yy")
    if admin_allow:
        for net in admin_allow:
            if net.startswith("INVALID:"):
                lines.append(f"# INVALID ADMIN-ALLOW network skipped: {net[8:]}")
            else:
                lines.append(f"add list=ADMIN-ALLOW address={net} comment=\"Router admin access\"")
    else:
        lines.append("# Add ADMIN-ALLOW networks before enabling remote admin services.")
    lines.append("")

    lines.append("# Lock down management services")
    lines.append("/ip service")
    lines.append("set telnet disabled=yes")
    lines.append("set ftp disabled=yes")
    lines.append("set www disabled=yes")
    lines.append("set api disabled=yes")
    lines.append("set api-ssl disabled=yes")
    lines.append("set ssh address=0.0.0.0/0 disabled=no")
    lines.append("set winbox address=0.0.0.0/0 disabled=no")
    lines.append("# Firewall input rules below restrict SSH/Winbox to ADMIN-ALLOW/SDACL.")
    lines.append("")

    lines.append("# Baseline firewall policy")
    lines.append("/ip firewall filter")
    lines.append("add chain=input action=accept connection-state=established,related,untracked comment=\"allow established/related\"")
    lines.append("add chain=input action=drop connection-state=invalid comment=\"drop invalid\"")
    lines.append("add chain=input action=accept protocol=icmp src-address-list=SDACL comment=\"allow ICMP from SDACL\"")
    lines.append("add chain=input action=accept protocol=tcp dst-port=22,8291 src-address-list=ADMIN-ALLOW comment=\"allow admin services from ADMIN-ALLOW\"")
    lines.append("add chain=input action=accept protocol=tcp dst-port=22,8291 src-address-list=SDACL comment=\"allow admin services from SDACL\"")
    lines.append(f"add chain=input action=accept in-interface={req.lan_bridge} comment=\"allow LAN to router for local services as needed\"")
    lines.append(f"add chain=input action=drop in-interface={req.wan_interface} comment=\"drop unsolicited WAN input\"")
    lines.append("add chain=input action=drop comment=\"explicit input deny\"")
    lines.append("add chain=forward action=accept connection-state=established,related,untracked comment=\"allow established forward\"")
    lines.append("add chain=forward action=drop connection-state=invalid comment=\"drop invalid forward\"")
    lines.append(f"add chain=forward action=accept in-interface={req.lan_bridge} out-interface={req.wan_interface} comment=\"allow LAN to WAN\"")
    lines.append(f"add chain=forward action=drop in-interface={req.wan_interface} comment=\"drop unsolicited WAN forward\"")
    lines.append("add chain=forward action=drop comment=\"explicit forward deny\"")
    lines.append("")

    lines.append("# NAT for LAN egress")
    lines.append("/ip firewall nat")
    lines.append(f"add chain=srcnat out-interface={req.wan_interface} action=masquerade comment=\"LAN to public circuit NAT\"")
    lines.append("")

    if req.enable_snmp:
        lines.append("# Optional SNMP. Community is intentionally blank by default in the UI.")
        lines.append("/snmp")
        lines.append(f"set enabled=yes contact=\"{req.snmp_contact}\" location=\"{req.snmp_location}\"")
        if req.snmp_community:
            lines.append("/snmp community")
            lines.append(f"add name=\"sd-readonly\" addresses=0.0.0.0/0 read-access=yes write-access=no community=\"{req.snmp_community}\"")
            lines.append("# Restrict SNMP with firewall rules/address lists before production use.")
        else:
            lines.append("# SNMP enabled but no community was generated. Add a secure RO community manually if required.")
        lines.append("")
    else:
        lines.append("/snmp")
        lines.append("set enabled=no")
        lines.append("")

    lines.append("# Hardening notes")
    lines.append("# - Create named admin users manually using approved credential handling.")
    lines.append("# - Remove/disable any default accounts after controlled access is confirmed.")
    lines.append("# - Confirm ADMIN-ALLOW and SDACL before exposing WAN management paths.")
    lines.append("# - Review service, firewall, NAT, and DHCP behavior before production paste/import.")
    return "\n".join(lines).strip() + "\n"


def _request_from_form(form: dict[str, Any]) -> MikroTikConfigRequest:
    return MikroTikConfigRequest(
        site_name=str(form.get("site_name") or ""),
        router_identity=str(form.get("router_identity") or ""),
        wan_interface=str(form.get("wan_interface") or "ether1"),
        wan_mode=str(form.get("wan_mode") or "dhcp"),
        wan_ip_cidr=str(form.get("wan_ip_cidr") or ""),
        wan_gateway=str(form.get("wan_gateway") or ""),
        lan_bridge=str(form.get("lan_bridge") or "bridge-lan"),
        lan_interfaces=str(form.get("lan_interfaces") or ""),
        lan_ip_cidr=str(form.get("lan_ip_cidr") or ""),
        dns_servers=str(form.get("dns_servers") or ""),
        sdacl_networks=str(form.get("sdacl_networks") or ""),
        admin_allow_networks=str(form.get("admin_allow_networks") or ""),
        enable_dhcp_server=bool(form.get("enable_dhcp_server")),
        dhcp_pool_start=str(form.get("dhcp_pool_start") or ""),
        dhcp_pool_end=str(form.get("dhcp_pool_end") or ""),
        dhcp_lease_time=str(form.get("dhcp_lease_time") or "8h"),
        enable_snmp=bool(form.get("enable_snmp")),
        snmp_community=str(form.get("snmp_community") or ""),
        snmp_location=str(form.get("snmp_location") or ""),
        snmp_contact=str(form.get("snmp_contact") or ""),
        notes=str(form.get("notes") or ""),
    )


@router.get("", response_class=HTMLResponse)
def mikrotik_router_home(request: Request):
    req = MikroTikConfigRequest()
    return templates.TemplateResponse(
        "mikrotik_router.html",
        {
            "request": request,
            "app_name": APP_NAME,
            "app_version": APP_VERSION,
            "favicon_url": FAVICON_URL,
            "values": req,
            "config_text": "",
            "sanitized_text": "",
            "generated": False,
        },
    )


@router.post("", response_class=HTMLResponse)
async def mikrotik_router_generate(request: Request):
    form = dict(await request.form())
    req = _request_from_form(form)
    config_text = build_routeros_config(req)
    sanitized_text = sanitize_config(config_text)
    return templates.TemplateResponse(
        "mikrotik_router.html",
        {
            "request": request,
            "app_name": APP_NAME,
            "app_version": APP_VERSION,
            "favicon_url": FAVICON_URL,
            "values": req,
            "config_text": config_text,
            "sanitized_text": sanitized_text,
            "generated": True,
        },
    )


@router.post("/export", response_class=PlainTextResponse)
async def mikrotik_router_export(request: Request):
    form = dict(await request.form())
    req = _request_from_form(form)
    config_text = build_routeros_config(req)
    if form.get("sanitize_export"):
        config_text = sanitize_config(config_text)
    filename_base = _safe_router_name(req.router_identity or req.site_name, "mikrotik_router")
    headers = {"Content-Disposition": f'attachment; filename="{filename_base}_routeros_v7.rsc"'}
    return PlainTextResponse(config_text, headers=headers)
