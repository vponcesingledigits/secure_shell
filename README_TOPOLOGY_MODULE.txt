Single Digits Engineering Platform - Topology Builder Alpha 0.4
================================================================

Mount path:
/apps/topology

Purpose:
Basic switch-only LLDP topology discovery. This is intentionally not a health checker.
It lists infrastructure switch names and management IP addresses, then renders a simple hierarchy.
APs, endpoints, phones, firewalls, gateways, and edge devices are ignored on this pass.

What changed in Alpha 0.4:
- Restored the standard Single Digits light theme used by MAC Trace and the other shell apps.
- Added the standard real-time debug output panel.
- Scan now starts through /apps/topology/scan/start and polls /apps/topology/scan/status/{job_id}.
- Kept a non-JavaScript fallback POST at /apps/topology/scan.
- Improved layout: hero card, scan card, debug card, summary cards, switch list, topology hierarchy.
- No dark theme on this module; dark theme should be added later as a global shell setting.

Files:
apps/topology/__init__.py
apps/topology/app.py
apps/topology/routes.py
apps/topology/models.py
apps/topology/parser.py
apps/topology/scanner.py
apps/topology/module.json
apps/topology/templates/topology.html
apps/topology/static/topology.css

Import:
Copy apps/topology into your shell's apps directory.
The shell manifest scanner should find apps/topology/module.json.

Dependencies:
- fastapi
- jinja2
- python-multipart
- paramiko, unless your shared/ssh.py adapter handles command execution
- reportlab for PDF export

Notes:
- This uses a best-effort shared.ssh.run_commands adapter first, then falls back to Paramiko.
- This should eventually be wired directly into the shared shell SSH/session/debug framework so every app uses the exact same live log component.


Alpha 0.5 updates:
- Added normalized NCM/AI import export at /apps/topology/export/ncm-json and /apps/topology/export/ai-json.
- NCM export schema: single_digits.ncm.topology.v1.
- Export includes normalized devices, switch-to-switch LLDP links, local port, neighbor-side port, management IPs, hierarchy, and normalization notes.
- Updated Ruckus LLDP collection preference to: show lldp neigh det | i Local|name|address|Desc.
- Parser now prefers Port description as neighbor-side port before Port ID to avoid capturing neighbor MAC address as a port.
