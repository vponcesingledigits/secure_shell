# Traffic Investigation Core Add-on

This add-on converts the old Cisco-only Traffic Investigator idea into a shared shell-wide investigation engine.

## What is included

```text
shared/investigation.py
shared/traffic_command_profiles.py
apps/traffic_analyzer/
apps/mac_trace_integration_notes/
docs/IMPLEMENTATION_NOTES.md
```

## What this is meant to replace

Do not import the old Cisco Traffic Investigator directly. It had useful ideas, but it was standalone and Cisco-only:

- standalone FastAPI app object
- standalone CSS/templates
- Netmiko-only SSH
- hardcoded command list
- hardcoded app port
- no shared parser/command model

The useful harvested ideas are:

- interface counter/rate parsing
- MAC table lookup
- ARP correlation
- LLDP/CDP neighbor discovery
- recursive path following
- port role guessing
- top talker / abnormal port investigation pattern

## Required shell wiring

`shared.investigation.trace_mac_path()` expects a command runner:

```python
def runner(target_ip: str, commands: Sequence[str], vendor: str | None = None) -> dict[str, str]:
    return shared.ssh.run_commands(target_ip, commands, vendor=vendor, ...)
```

The included `apps/traffic_analyzer/routes.py` intentionally has `_shared_runner_placeholder()` so it does not duplicate SSH logic.

Wire that placeholder into the existing shared SSH/session manager.

## Shared command hierarchy

The command profiles now normalize around:

- `mac_trace_quick`
- `traffic_quick`
- `traffic_deep`
- `targeted_port_followup`

Supported vendor keys:

- `cisco_ios`
- `ruckus_icx`
- `aruba_cx`
- `aruba_procurve`
- `extreme_exos`
- `tplink`

## App behavior

### MAC Trace

Fast workflow:

- find MAC or IP
- build path
- classify port role
- show speed/duplex/errors quick health
- recommend Traffic Analyzer for deep investigation

### Traffic Analyzer

Deeper workflow:

- same path finding logic
- deeper command profile
- larger counter/error/STP/log/trunk review
- same output schema plus deeper findings

## Evidence Pack and History

Both apps should save the `TracePath.to_dict()` payload.

Recommended JSON layout:

```text
history/mac_trace/<session_id>.json
history/traffic_analyzer/<session_id>.json
```

Common keys:

- `target`
- `resolved_mac`
- `resolved_ip`
- `resolved_vlan`
- `final_switch_ip`
- `final_switch_hostname`
- `final_port`
- `final_role`
- `hops`
- `findings`
- `visited_switches`
- `raw_outputs`

## Parser maturity note

The parsers in `shared/investigation.py` are intentionally broad first-pass parsers. They are designed to centralize logic now and improve with real switch output samples. As we collect outputs from Ruckus, Aruba CX, ProCurve, Extreme, TP-Link, and Cisco, improve the parser functions here instead of adding per-app parsing.
