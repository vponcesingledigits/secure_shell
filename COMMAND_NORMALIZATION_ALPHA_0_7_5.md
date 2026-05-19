# Command Normalization Pass - Alpha 0.7.5

This bundle integrates Switch Configurator directly into the existing shell and moves command selection toward one shared source of truth.

## Integrated modules/pages

- `/apps/switch-configurator`
  - Switch Configurator shell module.
  - Uses shell-wide site context defaults.
  - Simple single-page configuration flow; guided config removed.
- `/site-context`
  - Shell-wide site profile page.
  - Stores site name, site code, brand/deployment, address/contact, and default switch addressing.
  - Defaults: first switch `10.0.3.130`, mask `255.255.255.128`, gateway `10.0.3.129`, management VLAN `100`, AP management VLAN `101`.

## Shared command changes

Primary shared command file:

```text
shared/commands.py
```

Added normalized helpers:

```text
get_commands_for_sets(vendor, selected_sets)
get_available_command_sets()
get_switchport_collection_profile(vendor)
get_switchport_collection_commands(vendor, intents)
get_config_session_commands(vendor)
get_running_config_command(vendor)
get_hostname_command(vendor)
get_forescout_collection_commands(vendor)
dedupe_commands(commands)
```

Updated compatibility wrappers:

```text
apps/switch_health/commands.py
apps/port_map/commands.py
apps/switch_health/core/commands.py
```

The Switch Health command selector now uses `shared.commands.UNIFIED_COMMANDS_BY_SET` instead of maintaining a separate command catalog.

## Apps touched in this pass

- Switch Configurator: integrated as shell module.
- Switch Health: command catalog wrapper now points at `shared.commands`.
- Port Map: already using shared interface/LLDP/rename helpers.
- Switchport Name Normalizer: rename commands now use `shared.commands.get_port_rename_commands`; collection profiles remain bridged through `shared.switchport_commands`.
- ForeScout: running-config, hostname, config-enter, save, and Aruba Central commands now resolve through `shared.commands.get_forescout_collection_commands`.
- MAC Trace: already using shared MAC/LLDP/PoE command helpers; SSH timing was tightened for faster recursive tracing.
- Monitoring: already uses shared monitoring command helpers.
- Topology: already uses shared SSH/vendor pieces and should be a next candidate for deeper command-profile consumption.

## MAC Trace speed improvements

Reduced fixed waits during recursive switch-to-switch SSH and tightened shared SSH prompt polling:

- Shared SSH prompt polling interval reduced.
- Shared SSH initial shell settle shortened.
- MAC Trace nested SSH fixed sleeps reduced.
- Post-login prompt settling now uses fewer blank enters and shorter settle windows.

The tracing logic still waits for real prompts and authentication output, so slower devices should continue to work, but normal paths should feel more responsive between commands.

## Legacy spreadsheet command references

Uploaded configuration spreadsheets were inspected and summarized into:

```text
shared/config_reference/legacy_switch_scripts_summary.json
```

Switch Configurator exposes this data at:

```text
/apps/switch-configurator/api/legacy-script-reference
```

This is a reference bridge, not a direct paste-everything generator. The current config flow still generates clean normalized configs, while the extracted legacy script references preserve command coverage from the existing spreadsheets for future shared config profile expansion.

## Remaining recommended cleanup

1. Move `shared/switchport_commands.py` into `shared.commands` fully after one more validation pass.
2. Move Switch Configurator VLAN/profile catalogs into a new `shared/config_profiles.py` so Nomadix, firewall, compliance, and documentation tools can reuse the same profile data.
3. Move naming helpers into `shared/naming.py` for SW/GW/AP naming across all tools.
4. Move generated config fragments into vendor-specific builders, likely:

```text
shared/config_builders/ruckus_icx.py
shared/config_builders/aruba_cx.py
shared/config_builders/procurve.py
shared/config_builders/cisco_ios.py
```

5. Continue replacing local command literals with `shared.commands` in Topology and any future Compliance/Evidence collectors.
