from __future__ import annotations

# Compatibility wrapper.  Switch Health now consumes the shell-wide command
# catalog from shared.commands so new vendor command updates flow to this app.

from shared.commands import (
    COMMAND_SET_LABELS_SHARED as COMMAND_SET_LABELS,
    DEFAULT_SWITCH_HEALTH_SETS_SHARED as DEFAULT_COMMAND_SETS,
    UNIFIED_COMMANDS_BY_SET as COMMANDS_BY_SET,
    SHOW_TECH_COMMANDS_SHARED,
    CABLE_TRIGGER_COMMANDS_SHARED,
    get_available_command_sets,
    get_commands_for_sets,
    normalize_vendor_key,
)

PLATFORM_ALIASES = {
    "ruckus": "ruckus",
    "icx": "ruckus",
    "ruckus_icx": "ruckus",
    "aruba-cx": "aruba_cx",
    "aruba_cxos": "aruba_cx",
    "cxos": "aruba_cx",
    "procurve": "procurve",
    "hp_procurve": "procurve",
    "hp_aruba_procurve": "procurve",
    "hp-aruba-procurve": "procurve",
    "cisco": "cisco_ios",
    "ios": "cisco_ios",
    "extreme": "extreme_exos",
    "exos": "extreme_exos",
    "switchengine": "extreme_exos",
    "tp-link": "tplink",
    "tp_link": "tplink",
    "tplink_media_panel": "tplink",
}

SHOW_TECH_COMMANDS = {k: (v[0] if isinstance(v, list) and v else v) for k, v in SHOW_TECH_COMMANDS_SHARED.items()}
CABLE_DIAG_START = {k: v[0] for k, v in CABLE_TRIGGER_COMMANDS_SHARED.items()}
CABLE_DIAG_SHOW = {k: v[1] for k, v in CABLE_TRIGGER_COMMANDS_SHARED.items()}


def normalize_platform(platform: str | None) -> str:
    key = (platform or "unknown").strip().lower().replace(" ", "_")
    return PLATFORM_ALIASES.get(key, normalize_vendor_key(key))


def available_command_sets() -> list[dict[str, object]]:
    return get_available_command_sets()


def commands_for(platform: str, selected_sets: list[str] | None = None) -> list[str]:
    return get_commands_for_sets(normalize_platform(platform), selected_sets)
