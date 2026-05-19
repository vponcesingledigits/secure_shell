# Extreme EXOS / Switch Engine Add-on RC0.1

This add-on drops a shell-compatible module at:

```text
/apps/extreme-exos
```

and a reusable shared vendor/parser helper at:

```text
shared/extreme_exos.py
```

## Install

From the extracted add-on folder:

```bash
python install_extreme_exos_addon.py /path/to/SingleDigitsEngineeringPlatform
```

On Windows:

```bat
python install_extreme_exos_addon.py "C:\Path\To\SingleDigitsEngineeringPlatform"
```

Then restart the shell. Because the shell is manifest-driven, the new module should appear automatically from:

```text
apps/extreme_exos/module.json
```

## Extreme EXOS command rules

Do after login:

```text
disable clipaging
```

Do not send generic paging commands such as `pag`, `terminal length 0`, or `no page` to Extreme EXOS.

Do not attempt nested SSH from the switch CLI. For LLDP recursion, the shell should open a new SSH session from the laptop/controller directly to the discovered neighbor management IP.

## Prompt handling

Extreme EXOS prompt examples:

```text
* VASHILMDFCoresw.1 #
* VASHILMDFCoresw.37 #
VASHILMDFCoresw.37 #
```

Recommended regex:

```python
r"(?m)^\s*\*?\s*[A-Za-z0-9_.-]+(?:\.\d+)?\s*[#>]\s*$"
```

## Wire into shared/vendors.py

```python
from shared.extreme_exos import VENDOR_KEY as EXTREME_EXOS, detect as detect_extreme_exos

# In detection order, after initial command output such as show version/show system:
if detect_extreme_exos(output):
    return EXTREME_EXOS
```

Detection markers include:

```text
ExtremeXOS
Extreme Networks
Switch Engine
```

## Wire into shared/commands.py

```python
from shared.extreme_exos import COMMANDS as EXTREME_EXOS_COMMANDS

COMMAND_MAP["extreme_exos"] = EXTREME_EXOS_COMMANDS
```

Core commands:

```text
show system
show version
show ports no-refresh
show ports rxerrors
show ports txerrors no-refresh port-number
show lldp neighbors
show lldp neighbors detailed
show lldp neighbors detailed | include Name|Address
show fdb <mac>
show fdb
show fdb vlan <vlan>
```

## Wire into shared/parsers.py

```python
from shared.extreme_exos import (
    parse_fdb as parse_extreme_fdb,
    parse_lldp_neighbors_detailed as parse_extreme_lldp_detail,
    parse_lldp_neighbors_summary as parse_extreme_lldp_summary,
    parse_ports_no_refresh as parse_extreme_ports,
    parse_rxerrors as parse_extreme_rxerrors,
    parse_txerrors as parse_extreme_txerrors,
    parse_show_system as parse_extreme_show_system,
)
```

## MAC Trace integration

For Extreme EXOS:

```text
1. SSH from shell host to starting switch
2. disable clipaging
3. show fdb <mac>
4. show ports no-refresh
5. show lldp neighbors detailed
6. If learned port has an LLDP switch neighbor with management IP, open a new SSH session from the shell host to that IP
7. Do not send ssh <neighbor_ip> from the Extreme CLI
```

## Port Map / Topology integration

Use:

```text
show ports no-refresh
show lldp neighbors detailed
```

Do not assume one LLDP neighbor per port. Extreme can show multiple neighbors on the same local port, especially when a router/gateway advertises multiple logical interfaces.

## Switch Health integration

Use:

```text
show system
show ports no-refresh
show ports rxerrors
show ports txerrors no-refresh port-number
```

Findings guidance:

- Critical: SysHealth not normal, current state not OPERATIONAL, fan failed, temperature abnormal.
- Warning: port disabled by link-flap detection, half duplex, active ports with TX lost/parity/errors/late collisions.
- Info: low/non-increasing CRC counters, service odometer age, PSU-2 empty when expected on fixed models.

## Evidence Pack integration

Include raw outputs and parsed JSON for:

```text
identity/environment
port inventory
RX/TX errors
LLDP
FDB/MAC lookup
```
