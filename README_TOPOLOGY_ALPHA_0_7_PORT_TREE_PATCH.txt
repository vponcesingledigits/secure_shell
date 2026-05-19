Single Digits Engineering Platform - Topology Builder Alpha 0.7 Port Tree Patch

Patch target:
- Existing /apps/topology module from Alpha 0.6.

What changed:
- Hierarchy nodes now show interswitch port relationships.
  Example: parent local port ⇄ neighbor remote port.
- Switch badges/cards were reduced in size for large sites.
- LLDP reciprocal management IP learning was improved.
  The SSH/reachability address is not always the switch management IP; the module now prefers LLDP-advertised management IP when learned from a neighbor record.
- Link deduplication no longer collapses all links between the same two switches.
  It preserves distinct local/remote port pairs so redundant/parallel switch links can be represented.
- NCM/AI JSON export continues to include devices, management IPs, source ports, and target ports.

Install:
1. Stop the shell.
2. Copy the included apps/topology files over the existing apps/topology directory.
3. Start the shell on port 8010.
4. Open /apps/topology.

Notes:
- APs and endpoints remain ignored for this pass.
- No link health/speed/duplex checks are added in this patch.
- Concurrency remains default 10, max 25.
