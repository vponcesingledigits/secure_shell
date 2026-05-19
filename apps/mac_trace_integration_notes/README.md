# MAC Trace integration notes

MAC Trace should stop owning its own MAC/IP location logic. Replace local trace functions with calls to `shared.investigation.trace_mac_path()`.

Recommended default call:

```python
from shared.investigation import parse_target, trace_mac_path, analyze_path_health, render_path_summary

path = trace_mac_path(
    seed_targets=targets,
    runner=shared_ssh_runner,
    target=parse_target(mac=form_mac, ip=form_ip, vlan=form_vlan),
    mode="mac_trace_quick",
    max_hops=8,
)
findings = analyze_path_health(path, mode="mac_trace_quick")
```

MAC Trace should display the fast subset:

- path summary
- final switch / final port
- final role classification
- speed / duplex
- native VLAN / learned VLAN
- MAC count on final port
- quick red flags from `finding_summary`
- recommendation to run Traffic Analyzer when deeper evidence is needed

Important rule:

MAC Trace and Traffic Analyzer must not parse MAC tables independently. Both should consume the common `TracePath` schema.
