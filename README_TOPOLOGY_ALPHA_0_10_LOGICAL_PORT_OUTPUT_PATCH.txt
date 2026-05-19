Single Digits Topology Builder Alpha 0.7.50 Patch
================================================

Purpose
-------
Refines the Topology Builder output and export model based on field testing.

What changed
------------
1. Fixes switch names showing as "SSH"
   - Prompt parsing now handles prompts such as SSH@SwitchName#.
   - The switch name column should now use the detected hostname when available.

2. Reduces duplicate LLDP link rows
   - Duplicate LLDP records from multiple commands are grouped by local switch, local port, and remote switch.
   - If one record reports a MAC as the remote port and another reports a real port description, the real port is preferred.

3. Adds the requested logical port sheet format
   TSV export columns are now:
   - Switch Name
   - Local Port ID
   - Local Port Name
   - Patch Panel Port
   - Remote Hostname
   - Remote IP
   - Suggested Port Name

4. Patch Panel Port is always blank
   - This column is reserved for internal documentation use.

5. Remote Hostname is LLDP-only
   - No descriptions, IPs, status text, or inferred values are written into Remote Hostname.
   - Ports with no LLDP neighbor remain blank in the remote fields.

6. Local Port Name is parsed separately
   - Existing configured port names/descriptions are retained when available.
   - Ports named Empty/None/-- are exported blank.

7. Switch sections are collapsible in the UI
   - The port-sheet preview now renders one collapsible section per switch.
   - A hard visual line break separates each switch.

8. AP parser remains export-only
   - APs/endpoints remain hidden from the main topology map.
   - AP LLDP system names are still available in the port-sheet export.

Install
-------
Copy the included apps/topology files over the existing shell module files.
Restart the shell after replacing the files.

