"""Shared topology models and future cache hooks."""
from __future__ import annotations

from dataclasses import dataclass

@dataclass
class TopologyEdge:
    local_device: str
    local_port: str
    neighbor_device: str
    neighbor_port: str | None = None
    source: str = "lldp"
