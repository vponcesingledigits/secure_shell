Single Digits Engineering Platform - Topology Builder Alpha 0.8 Port Sheet Patch

Patch target:
  apps/topology

What changed:
- Adds vendor-neutral port inventory collection commands during topology scan.
- Adds AP LLDP parsing for export only. APs remain hidden from the main topology window.
- Adds Excel-friendly Port Sheet TSV export:
    /apps/topology/export/port-sheet.tsv
- Adds normalized Port Sheet JSON export:
    /apps/topology/export/port-sheet.json
- Adds port_sheets into the normal topology JSON/NCM export payload.

Port Sheet rules enforced:
- Every discovered switch gets its own switch section.
- Ports are listed even when down or when there is no LLDP neighbor, as long as the switch interface table provided the port.
- LLDP Name is only the LLDP-derived neighbor System Name.
- No descriptions, IP addresses, status text, inferred labels, or generated names are placed in LLDP Name.
- Patch Panel columns are always intentionally blank.
- AP LLDP names are retained in the Port Sheet export but are not displayed in the topology hierarchy.

Scan command additions:
- show interfaces brief
- show interfaces brief wide
- show interface brief
- show interfaces status
- show ports no-refresh
- show name

Existing behavior retained:
- Light Single Digits theme.
- Real-time debug output.
- switch-only topology hierarchy.
- switch-to-switch links with local and neighbor port names.
- concurrency default 10, hard cap 25.
- NCM/AI topology JSON export.

Install:
Copy the apps/topology directory into the shell, replacing the existing topology module files.
