# Switch Health shell module

Mount path: `/apps/switch-health`

This is the shell-compatible Switch Health module with selectable command sets. It uses shared SSH/vendor libraries when present and falls back to its internal Paramiko runner when the shell shared modules are not loaded yet.

## Command sets

The UI exposes all currently available command sets:

- System / Version
- Resource Utilization
- Environmental
- Port / Link Health
- PoE / Power
- Logs / Events
- LLDP Neighbors
- STP / Loop Signals
- VLANs
- MAC Table
- Inventory / Chassis
- Optics / Transceivers
- ARP / IP Neighbors

Vendor command catalogs are included for:

- Ruckus ICX
- Aruba CXOS
- HP/Aruba ProCurve
- Cisco IOS
- Extreme EXOS / Switch Engine
- TP-Link media panel switches
- Generic fallback devices

A machine-readable command catalog is exposed at:

`/apps/switch-health/api/command-sets`

## Install

Copy `apps/switch_health` into the shell root. The current manifest-driven shell should discover `module.json` automatically.

If your shell build does not auto-mount app static folders, add:

```python
from fastapi.staticfiles import StaticFiles
app.mount('/apps/switch-health/static', StaticFiles(directory='apps/switch_health/static'), name='switch_health_static')
```

If your shell build does not auto-import manifest routers, add:

```python
from apps.switch_health.router import router as switch_health_router
app.include_router(switch_health_router)
```

## Notes

- Default SSH port is 22.
- Default concurrency is 10 and max concurrency is 25.
- Show tech is optional because it can be slow and produce very large output.
- Cable diagnostics are currently implemented for Ruckus ICX using the two-step TDR workflow.
- Passwords are redacted from JSON exports.
