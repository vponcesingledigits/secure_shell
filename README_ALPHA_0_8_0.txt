Single Digits Engineering Platform — Alpha.0.8.0 Clean Rebuild Kit
=================================================================

Purpose
-------
This kit creates a clean Alpha.0.8.0 folder from your last fully working shell folder, then safely layers in the Off-Service module without overwriting shared command registries.

Use this when an add-on changed shared files or route manifests and some launcher links now return 404.

Recommended command
-------------------
Run this against the last fully working shell folder, not the broken repair output:

    python tools\rebuild_alpha_0_8_0.py "C:\Path\To\LastWorkingShell"

Optional: if you want to use one folder as the baseline and copy missing apps from another folder:

    python tools\rebuild_alpha_0_8_0.py "C:\Path\To\CurrentShell" --known-good "C:\Path\To\LastWorkingShell"

Output
------
The tool creates a new sibling folder named:

    Single_Digits_Engineering_Platform_Alpha.0.8.0

It also writes:

    ALPHA_0_8_0_REBUILD_REPORT.txt

What it changes
---------------
- Renames internal version markers to Alpha.0.8.0 where safe.
- Preserves existing working app code.
- Normalizes module.json for known shell apps.
- Adds route compatibility only for missing links, so good apps are not disturbed.
- Installs Off-Service as apps/off_service and shared/offservice_commands.py.
- Does not replace shared/commands.py.
- Adds .env.offservice.example for sensitive values.

Known app routes normalized
---------------------------
- /apps/mac-trace
- /apps/switch-health
- /apps/port-map
- /apps/monitoring
- /apps/smartzone-ap-investigator
- /apps/forescout
- /apps/evidence
- /apps/topology
- /apps/switchport-normalizer
- /apps/switch-configurator
- /apps/off-service
- /apps/nomadix-config
- /apps/mikrotik-router

Important
---------
If the source folder does not contain the real app code for a module, this kit cannot recreate the full functionality of that module from logs alone. It will make the link resolve to a diagnostic page and clearly mark the missing module in the rebuild report. For full functionality, run the rebuild from the last fully working shell folder or pass it as --known-good.
