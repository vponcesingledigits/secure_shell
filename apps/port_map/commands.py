from __future__ import annotations

from typing import List

from shared.commands import get_port_mac_command, get_port_rename_commands, sanitize_port_name


def mac_command(vendor: str, port: str) -> str:
    return get_port_mac_command(vendor, port)


def rename_commands(vendor: str, port: str, name: str) -> List[str]:
    return get_port_rename_commands(vendor, port, name)


def sanitize_name(name: str) -> str:
    return sanitize_port_name(name)
