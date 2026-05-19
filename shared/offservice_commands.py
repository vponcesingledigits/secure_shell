from __future__ import annotations

import os
import secrets
import string
from dataclasses import dataclass

DEFAULT_VENDOR_USERNAME = os.getenv("OFFSERVICE_DEFAULT_VENDOR_USERNAME", "vendor")


def _csv_env(name: str, default: str = "") -> tuple[str, ...]:
    raw = os.getenv(name, default)
    return tuple(x.strip() for x in raw.split(",") if x.strip())


@dataclass(frozen=True)
class OffServiceOptions:
    vendor: str = "auto"
    credential_mode: str = "none"
    handoff_username: str = DEFAULT_VENDOR_USERNAME
    handoff_password: str = ""
    target_username: str = "admin"
    vlan_ids: tuple[int, ...] = (1000, 1016, 1025, 1029, 1030, 1050, 1400)


def generate_password(length: int = 18) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%*-_+"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw) and any(c in "!@#$%*-_+" for c in pw):
            return pw


def _credential_commands(opts: OffServiceOptions) -> list[str]:
    if opts.credential_mode == "create_vendor_user" and opts.handoff_password:
        if opts.vendor == "cisco_ios":
            return [f"username {opts.handoff_username} privilege 15 secret {opts.handoff_password}"]
        if opts.vendor == "hp_procurve":
            return [f"password manager user-name {opts.handoff_username} plaintext {opts.handoff_password}"]
        return [f"! create handoff user {opts.handoff_username} with generated password manually for this vendor"]
    if opts.credential_mode == "update_admin_password" and opts.handoff_password:
        if opts.vendor == "cisco_ios":
            return [f"username {opts.target_username} privilege 15 secret {opts.handoff_password}"]
        if opts.vendor == "hp_procurve":
            return [f"password manager user-name {opts.target_username} plaintext {opts.handoff_password}"]
        return [f"! update {opts.target_username} password manually for this vendor"]
    return []


def hp_procurve_commands(opts: OffServiceOptions) -> list[str]:
    tacacs_hosts = _csv_env("OFFSERVICE_TACACS_HOSTS", "162.255.175.101,199.168.146.38")
    communities = _csv_env("OFFSERVICE_SNMP_COMMUNITIES_TO_REMOVE")
    trap_hosts = _csv_env("OFFSERVICE_SNMP_TRAP_HOSTS_TO_REMOVE", "162.130.146.60,10.224.10.70")
    trap_community = os.getenv("OFFSERVICE_SNMP_TRAP_COMMUNITY", "")
    cmds = ["conf t", "aaa authentication ssh login local"]
    cmds += [f"no tacacs-server host {host}" for host in tacacs_hosts]
    cmds += [f'no snmp-server community "{community}"' for community in communities]
    if trap_community:
        cmds += [f'no snmp-server host {host} community "{trap_community}"' for host in trap_hosts]
    cmds += _credential_commands(opts)
    cmds += ["end", "wr mem"]
    return cmds


def cisco_ios_commands(opts: OffServiceOptions) -> list[str]:
    communities = _csv_env("OFFSERVICE_SNMP_COMMUNITIES_TO_REMOVE")
    trap_hosts = _csv_env("OFFSERVICE_SNMP_TRAP_HOSTS_TO_REMOVE", "10.224.10.70,162.130.146.60")
    trap_community = os.getenv("OFFSERVICE_SNMP_TRAP_COMMUNITY", "")
    cmds = [
        "conf t",
        "no aaa group server tacacs+ SingleDigits",
        "no aaa authentication login SingleDigits enable group SingleDigits",
        "no aaa authentication enable default group SingleDigits enable",
        "no aaa authorization exec default group SingleDigits local if-authenticated",
        "no aaa accounting exec default start-stop group SingleDigits",
        "no aaa accounting commands 0 default start-stop group SingleDigits",
        "no aaa accounting commands 1 default start-stop group SingleDigits",
        "no aaa accounting commands 15 default start-stop group SingleDigits",
    ]
    cmds += [f"no snmp-server community {community} RO" for community in communities]
    cmds += [f"no snmp-server community {community} RW" for community in communities]
    if trap_community:
        cmds += [f"no snmp-server host {host} version 2c {trap_community}" for host in trap_hosts]
    cmds += [
        "no tacacs-server directed-request",
        "no tacacs-server key",
        "no tacacs server SD-ACS-PRI",
        "no tacacs server SD-ACS-SEC",
    ]
    cmds += _credential_commands(opts)
    cmds += ["end", "wr mem"]
    return cmds


def aruba_gateway_commands(opts: OffServiceOptions) -> list[str]:
    cmds = ["conf t"]
    for vlan in opts.vlan_ids:
        cmds += [f"vlan {vlan}", '    wired aaa-profile "NoAuthAAAProfile"', "!"]
    cmds += _credential_commands(opts)
    cmds += ["end", "wr mem"]
    return cmds


def generic_preview_commands(opts: OffServiceOptions) -> list[str]:
    if opts.vendor == "hp_procurve":
        return hp_procurve_commands(opts)
    if opts.vendor == "cisco_ios":
        return cisco_ios_commands(opts)
    if opts.vendor == "aruba_gateway":
        return aruba_gateway_commands(opts)
    return [
        "! Auto mode preview",
        "! Run vendor detection first, then use hp_procurve, cisco_ios, or aruba_gateway command profile.",
        "! No device-changing commands are generated in auto preview mode.",
    ]
