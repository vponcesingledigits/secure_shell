# MAC Trace Development History


## MAC_TRACE_ALPHA_0_5_CLEAN_NOTES

MAC Trace Alpha 0.5 Clean Vendor MAC Formats

Cleaned behavior:
- ProCurve / ArubaOS-Switch uses only dash MAC format:
  show mac-address | includ 123456-123456
  show mac-address 123456-123456

- Ruckus / Cisco / TP-Link keep dotted format:
  1234.1234.1234

- Aruba CX keeps colon lookup with dotted include fallback.

- Removed failed patch scripts from the bundle root.
- Removed show running-config | include hostname entries where found.
- Replaced parse_port_from_mac_line and parse_mac_hits to handle:
  48d6d5-3a5728     B15     1000
  and ProCurve single-MAC table output:
  Port VLAN
  B15  1000


## MAC_TRACE_ALPHA_0_6_10_PROCURVE_SHOW_SYSTEM_NOTES

MAC Trace Alpha 0.6.10 ProCurve ShowSystem

Adds show system as a vendor-detection fallback.

ProCurve / ArubaOS-Switch markers:
- Status and Counters - General System Information
- Software revision
- ROM Version
- Allow V2 Modules
- MAC Age Time
- IP Mgmt packet counters

Example:
  show system
  Status and Counters - General System Information
  Software revision : KB.16.11.0026
  ROM Version       : KB.16.01.0006

This should classify as:
  hp_aruba_procurve

Why:
Nested SSH sessions can occasionally make show version parsing inconclusive.
show system is short, stable, and provides enough information to infer ProCurve.


## MAC_TRACE_ALPHA_0_6_11_PROCURVE_RUN_HEADER_NOTES

MAC Trace Alpha 0.6.11 ProCurve RunHeader

Adds another lightweight ProCurve / ArubaOS-Switch detection fallback:

  show run | include ;

Example:
  ; J9850A Configuration Editor; Created on release #KB.16.11.0026

Parsed:
  model              = J9850A
  software_revision  = KB.16.11.0026
  vendor             = hp_aruba_procurve

Why:
- The semicolon config header is short and stable.
- It works on HP/Aruba ProCurve / ArubaOS-Switch platforms.
- It helps when nested SSH banners make show version parsing inconclusive.


## MAC_TRACE_ALPHA_0_6_12_SELF_UPDATING_MODEL_DB_NOTES

MAC Trace Alpha 0.6.12 Self-Updating Model DB

Adds:
  shared/hp_models.py

Initial internal mappings:
  J9728A -> Aruba/HP 2920-48G
  J9729A -> Aruba/HP 2920-48G-PoE+
  J9850A -> Aruba/HP 5406R zl2 chassis

Self-updating behavior:
- Known J-models return mapped platform metadata immediately.
- Unknown JxxxxA models are still classified as hp_aruba_procurve.
- Unknown J-models are saved to:
    %LOCALAPPDATA%/SingleDigitsEngineeringPlatform/ModelCache/hp_models_user.json

Saved unknown entry includes:
- model
- first_seen
- last_seen
- seen_count
- source
- raw evidence
- known_model=false

This lets the internal database grow safely from field observations without
requiring internet lookups during call-center traces.


## MAC_TRACE_ALPHA_0_6_13_RUCKUS_LLDP_FAST_FILTER_NOTES

MAC Trace Alpha 0.6.13 Ruckus LLDP FastFilter

Adds Ruckus ICX fast LLDP identity command:

  show lldp neighbor detail port eth <port> | include name|add|desc

Example:
  + System name: HS015296SW01-MDataCent
  + Port description: "10GigabitEthernet2/1/2"
  + System description: "Ruckus Wireless, Inc. Stacking System ICX7550-24..."
  + Management address (IPv4): 192.168.250.242

Parser updates:
- Derives local_port from the command key because filtered output may omit it.
- Parses System name as neighbor_name.
- Parses System description as neighbor_description.
- Parses Port description as neighbor_port_description.
- Parses Management address (IPv4) as neighbor_ip.

This reduces Ruckus LLDP trace-time output while still keeping the fields needed
to determine AP vs switch and next-hop IP.


## MAC_TRACE_ALPHA_0_6_2_NAMING_NOTES

MAC Trace Alpha 0.6.2 Naming Classification

Fix:
PHXBDSW01-14-IDF14 was being classified as gateway because LLDP capabilities
included "router". Normal switches can advertise router capability, so that is
not enough to call the neighbor a gateway.

New classification priority:
1. Single Digits naming convention:
   <propertycode><devicecode>-<floor>-<idf_location>

   Example:
   PHXBDSW01-14-IDF14
     PHXBD = property code
     SW    = switch
     01    = first switch on this floor/area
     14    = floor 14
     IDF14 = IDF name

2. AP-specific name/description.
3. Switch-specific name/description/bridge capability.
4. Gateway/firewall-specific name/description.

Important:
- SW in hostname is switch.
- IDF/MDF in hostname is switch location context.
- "bridge, router" LLDP capability does not make a switch a gateway.
- Gateway requires stronger evidence such as GW/FW/RTR naming or firewall/Nomadix/WatchGuard description.


## MAC_TRACE_ALPHA_0_6_3_LLDP_FAST_IDENTITY_NOTES

MAC Trace Alpha 0.6.3 LLDP Fast Identity

New ProCurve fast-path LLDP identity command:

  sh lldp inf rem <port> | i Name|Addre

Example output:
  SysName      : PHXBD-AP017-17-Rm1730
  Remote Management Address
     Address : 192.168.162.123

Why:
- This replaces separate Address and Name fallback commands.
- The parser now derives local_port from the command itself because this filtered
  output does not contain "Local Port".
- This reduces ProCurve LLDP identity lookup from up to 3 commands to 1 command.

ProCurve learned-port command set now starts with:
  sh lldp inf rem <port> | i Name|Addre
  show interfaces brief | include <port>
  show interfaces <port>
  show log -r | i <port>


## MAC_TRACE_ALPHA_0_6_4_LLDP_RICH_IDENTITY_NOTES

MAC Trace Alpha 0.6.4 LLDP Rich Identity

New ProCurve fast-path LLDP identity command:

  sh lldp inf rem <port> | i SysName|Desc|Add

Example AP output:
  SysName      : PHXBD-AP006-16-Rm1608
  System Descr : Ruckus H510 Multimedia Hotzone Wireless AP/SW Version: 10...
  PortDescr    : eth0
  Remote Management Address
     Address : 192.168.162.54

Example switch output:
  SysName      : PHXBDSW01-1-MDF
  System Descr : HP J9850A Switch 5406Rzl2, revision KB.16.11.0026, ROM KB...
  PortDescr    : B15
  Remote Management Address
     Address : 10.0.3.131

Why:
- One command gives name, classification, remote port, and management IP.
- Avoids separate Address and Name fallback commands.
- Avoids full LLDP detail output when not needed for trace decisions.


## MAC_TRACE_ALPHA_0_6_5_LLDP_COMPATIBLE_FILTERS_NOTES

MAC Trace Alpha 0.6.5 LLDP Compatible Filters

Reason:
Some ProCurve / ArubaOS-Switch versions do not support multiple grep/include
patterns in one command. This can fail:

  sh lldp inf rem <port> | i SysName|Desc|Add

with:

  Invalid input: grep usage error

New ProCurve-compatible LLDP identity sequence:

  sh lldp inf rem <port> | i SysName
  sh lldp inf rem <port> | i Desc
  sh lldp inf rem <port> | i Add

This still avoids the full LLDP detail dump while remaining compatible with
older ProCurve filtering behavior.

Parser behavior:
- Derives local_port from the command itself.
- Merges SysName, System Descr, PortDescr, and Address from the three outputs
  into a single neighbor object.


## MAC_TRACE_ALPHA_0_6_6_PROCURVE_PORT_MODE_NOTES

MAC Trace Alpha 0.6.6 ProCurve Port Mode

Fix:
ProCurve 'show interfaces brief | include <port>' output was being parsed
incorrectly. The tool could treat port number 10 as '10m', producing:

  speed_duplex: 10m unknown

for this real output:

  Port Type      Enabled Status Mode
  10   100/1000T Yes     Up     100FDx

Correct parsed value:
  speed = 100m
  duplex = full

Parser now reads the Mode column:
  10FDx    -> 10m full
  10HDx    -> 10m half
  100FDx   -> 100m full
  100HDx   -> 100m half
  1000FDx  -> 1gbit full
  1000HDx  -> 1gbit half


## MAC_TRACE_ALPHA_0_6_8_PROCURVE_CUSTOM_SPEED_NOTES

MAC Trace Alpha 0.6.8 ProCurve Custom Speed

Adds this ProCurve command to the learned-port command set:

  sh int custom <port> speed | i 1

Example:
  PHXBDSW01-1-MDF# sh int custom b15 speed | i 1
    1000FDx

Parser preference:
1. Parse 'show interfaces custom <port> speed' output first.
2. Fall back to 'show interfaces brief | include <port>' Mode column.

Expected:
  1000FDx -> 1gbit full
  100FDx  -> 100m full
  10FDx   -> 10m full

This works with chassis-style ProCurve ports like B15.


## MAC_TRACE_ALPHA_0_6_9_PROCURVE_LLDP_INTERFACE_NOTES

MAC Trace Alpha 0.6.9 ProCurve LLDP Interface

Fix:
For ProCurve / ArubaOS-Switch, when a port is specified, do not use 'detail':

  show lldp info remote-device <port>

already returns detailed information for that port.

Also:
- Unknown fallback no longer immediately fans out into CX/Cisco LLDP detail variants.
- Single Digits switch hostnames like PHXBDSW03-17-IDF17 infer hp_aruba_procurve
  when show version is inconclusive after nested SSH.
- Compatible ProCurve filtered identity commands remain:
    sh lldp inf rem <port> | i SysName
    sh lldp inf rem <port> | i Desc
    sh lldp inf rem <port> | i Add

Manual ProCurve multi-port syntax:
  show lldp info remote-device 10,11,14


## MAC_TRACE_ALPHA_0_6_IMPORTFIX_NOTES

MAC Trace Alpha 0.6.1 SSH Import Fix

Fix:
Python imports shared.ssh from shared/ssh/__init__.py when a shared/ssh/ package
exists. Alpha 0.6 had the new prompt helper functions in shared/ssh.py, but not
in shared/ssh/__init__.py.

This build places the shared helper functions in both:
- shared/ssh.py
- shared/ssh/__init__.py

Functions included:
- clean_terminal_text()
- extract_network_prompt()
- has_network_prompt()
- drain_shell()
- settle_shell_prompt()

This resolves:
ImportError: cannot import name 'clean_terminal_text' from 'shared.ssh'


## MAC_TRACE_ALPHA_0_6_NOTES

MAC Trace Alpha 0.6 Clean Bundle

Purpose:
- Lightweight call-center MAC trace workflow.
- Locate a client MAC, follow LLDP switch-to-switch recursively, stop at AP/direct port.
- Use only the commands needed for the learned port on each hop.

Normalized MAC lookup policy:
- ProCurve / ArubaOS-Switch:
    show mac-address | includ 123456-123456
    show mac-address 123456-123456
- Ruckus / Cisco / TP-Link:
    1234.1234.1234
- Aruba CX:
    colon format primary, dotted include fallback

Normalized ProCurve path workflow:
- no page
- show mac-address | includ <dash-mac>
- show mac-address <dash-mac>
- show lldp info remote-device <port>
- sh lldp inf rem <port> | i Address
- sh lldp inf rem <port> | inc Name
- show interfaces brief | include <port>
- show interfaces <port>
- show log -r | i <port>
- If LLDP neighbor is AP only:
    show power-over-ethernet br <port>

Shared SSH helper:
- shared/ssh.py now exposes:
    clean_terminal_text()
    extract_network_prompt()
    has_network_prompt()
    drain_shell()
    settle_shell_prompt()
- MAC Trace uses these for every switch-to-switch SSH session.
- After nested SSH login, it sends blank Enter three times and settles on a clean prompt before running next-hop commands.
- HPE/ProCurve banners and "Press any key to continue" are expected and handled.

Cleanup:
- routes.py is a safe shim to router.py.
- Stale patch scripts removed.
- Port detail collection does not re-run vendor detection.
