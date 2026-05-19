"""Optional helper for merging traffic command profiles into shared/commands.py."""
from .investigation import TRAFFIC_COMMAND_PROFILES, get_command_profile

__all__ = ["TRAFFIC_COMMAND_PROFILES", "get_command_profile"]
