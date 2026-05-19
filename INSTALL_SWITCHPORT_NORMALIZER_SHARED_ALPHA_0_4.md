# Switchport Name Normalizer Alpha 0.4 - Shared Parser Integration

Unzip this patch into the root of the Single Digits Engineering Platform shell and restart the shell.

Expected route:

```text
/apps/switchport-normalizer
```

## What changed

- Keeps the module under **Configuration Builder**.
- Uses shared shell switchport command profiles instead of module-local command-only logic.
- Adds shared LLDP parser module for:
  - Ruckus ICX
  - Aruba CXOS
  - HP / Aruba ProCurve
  - Cisco IOS / Catalyst
  - TP-Link media panel / JetStream-style switches
  - Extreme EXOS / Switch Engine
- Keeps the Topology Builder worksheet interface:
  - Switch Name
  - Local Port ID
  - Local Port Name
  - Patch Panel Port
  - Remote Hostname
  - Remote IP
  - Suggested Port Name
- Avoids the previous generic-parser issue where command echoes like `show lldp neighbors` could become a fake remote hostname.

## New shared files

```text
shared/switchport_commands.py
shared/switchport_lldp.py
```

These are intentionally additive so they do not overwrite your existing shared `commands.py` or `parsers.py`. Later we can fold them directly into the main shared library once this module is validated.

## Vendor command profile note

Ruckus still supports both bulk and targeted filtered LLDP:

```text
show lldp neighbors
show lldp neighbors detail
show lldp neighbor detail port eth {port} | include name|add|desc
```

The Normalizer uses bulk commands first because they preserve local-port context for the worksheet. The filtered command remains in the shared profile for future targeted enrichment / LLDP Renamer workflows.
