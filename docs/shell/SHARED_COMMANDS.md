# Shared Command Catalog

Command sets that are reused by Port Map, MAC Trace, Switch Health, Topology, Compliance, and Evidence Pack should live in `shared/commands.py`.

Current shared helpers include:

- `get_interface_inventory_command(vendor)`
- `get_lldp_detail_command(vendor, port=None)`
- `get_port_mac_command(vendor, port)`
- `get_port_rename_commands(vendor, port, name)`
- `get_switch_health_commands(vendor, show_tech=False)`
- `get_cable_diagnostic_commands(vendor, port)`
- MAC Trace lookup/detail/AP power command helpers

Supported vendor keys:

- `ruckus`
- `aruba_cx`
- `procurve`
- `cisco_ios`
- `tplink`
- `extreme_exos`

All future modules should call the shared helpers instead of creating new local command maps.
