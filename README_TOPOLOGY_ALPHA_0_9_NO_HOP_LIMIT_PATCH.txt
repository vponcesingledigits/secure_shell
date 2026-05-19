Single Digits Engineering Platform - Topology Builder Alpha 0.9 Patch

Purpose
- Removes the unintended Max Hops behavior from Topology Builder.
- Topology discovery now continues until the LLDP-discovered switch queue is exhausted.
- Concurrency remains shell-standard: default 10, maximum 25.

Changes
- Removed Max Hops field from the UI.
- Removed max_hops as a scan limiter.
- Scan log now shows "N scanned" instead of "N/max_hops".
- Newly discovered LLDP switch neighbors are queued unless already visited or already queued.
- Existing route compatibility is preserved; older form submissions with max_hops are accepted but ignored.

Install
1. Copy the apps/topology folder over your existing apps/topology folder.
2. Restart the shell.
3. Open /apps/topology.

Behavior
- Enter starting switch IPs, hostnames, or subnets.
- The scanner logs into each candidate switch.
- LLDP switch neighbors are discovered and queued.
- The scan ends when no new switch neighbors remain.
- APs/endpoints remain hidden from the main topology.
- Port-sheet export still includes all discovered switch ports and LLDP names.
