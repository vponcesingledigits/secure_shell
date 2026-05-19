# Prompt to apply this add-on to the main shell chat

Add Extreme EXOS / Switch Engine support to the Single Digits Engineering Platform shell as a first-class shared vendor.

Use the attached Extreme EXOS RC0.1 add-on files.

Requirements:

- Copy `shared/extreme_exos.py` into the shell `shared/` folder.
- Copy `apps/extreme_exos/` into the shell `apps/` folder.
- The module manifest should expose `/apps/extreme-exos` and appear under Support Diagnostics.
- Wire Extreme EXOS into `shared/vendors.py` vendor detection.
- Wire Extreme EXOS commands into `shared/commands.py`.
- Wire Extreme EXOS parser functions into `shared/parsers.py`.
- Make Extreme EXOS available to MAC Trace, Switch Health, Port Map, Topology, Compliance, and Evidence Pack.

Important behavior:

- Extreme has a login banner.
- Extreme prompt may look like `* VASHILMDFCoresw.1 #` or `VASHILMDFCoresw.37 #`.
- Use `disable clipaging` after login.
- Do not send `pag`, `terminal length 0`, or `no page` to Extreme.
- Do not attempt switch-to-switch nested SSH from the Extreme CLI.
- For LLDP recursion, use the shell host to open a new SSH session directly to the discovered neighbor management IP.

Commands:

- Identity/environment: `show system`, `show version`
- Ports: `show ports no-refresh`
- RX errors: `show ports rxerrors`
- TX errors: `show ports txerrors no-refresh port-number`
- LLDP: `show lldp neighbors`, `show lldp neighbors detailed`
- Quick LLDP name/IP: `show lldp neighbors detailed | include Name|Address`
- MAC lookup: `show fdb <mac>`
- MAC table: `show fdb`
- VLAN-scoped MAC table: `show fdb vlan <vlan>`

Parser notes:

- `show ports no-refresh` speed and duplex are optional because ready/down/disabled ports omit them.
- `show fdb` returns VLAN name with VLAN tag in parentheses, such as `Guest-Generic(1000)`.
- `show lldp neighbors detailed` can contain multiple neighbors on one local port.
- Filtered LLDP output with `include Name|Address` is useful for quick discovery but does not preserve local port context, so full LLDP detail is required for topology and MAC Trace.
