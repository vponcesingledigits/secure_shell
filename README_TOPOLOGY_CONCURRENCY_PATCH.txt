Single Digits Engineering Platform - Topology Builder Concurrency Patch Alpha 0.6
================================================================================

Patch purpose:
Adds Switch Health-style concurrency to Topology Builder.

What changed:
- Adds Concurrency input to the Topology Builder UI.
- Default concurrency is 10.
- Hard cap is 25 active SSH sessions.
- Recursive LLDP switch discovery now uses a shared worker pool.
- Live debug output reports queued targets, worker concurrency, discovered downstream switches, and scan completion.
- Fallback /apps/topology/scan route also honors concurrency.

Files included:
apps/topology/app.py
apps/topology/scanner.py
apps/topology/templates/topology.html
apps/topology/static/topology.css
apps/topology/module.json

Install:
1. Stop the shell.
2. Copy the included apps/topology files over your existing apps/topology module.
3. Start the shell on the normal shell port.
4. Open /apps/topology.

Notes:
- This patch does not add link health, speed, duplex, or MAC lookup.
- APs/endpoints remain ignored for this pass.
- The topology output remains switch name, management IP, and LLDP switch-to-switch links.
