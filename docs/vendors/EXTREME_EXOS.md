# Extreme EXOS / Switch Engine Support

Extreme EXOS/Switch Engine is supported as an internal shell-wide vendor capability.

It should not appear as a user-facing launcher module.

Shared implementation locations:

- `shared/extreme_exos.py`
- `shared/commands.py`
- `shared/vendors.py`
- `shared/parsers.py`

Tools that should consume these commands/parsers:

- MAC Trace
- Switch Health
- Port Map
- Topology
- Compliance
- Evidence Pack

Important behavior:

- EXOS commands are selected automatically after vendor detection.
- EXOS is not exposed as a standalone app in `/api/modules`.
- EXOS does not have an `apps/extreme_exos/module.json` entry.

Core command references:

```text
show system
show ports no-refresh
show ports txerrors no-refresh port-number
show lldp neighbors detailed
show lldp neighbors detailed | include Name|Address
show fdb
show log
```

Do not append an individual port number to:

```text
show ports txerrors no-refresh port-number
```
