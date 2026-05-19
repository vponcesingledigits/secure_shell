# Alpha 0.7.2 UI Normalization

This build adds a shell-wide module normalization stylesheet:

- `/static/css/sd-module-unified.css`

Every standalone module template now loads:

1. `/static/css/sd-platform.css`
2. the module's own CSS when needed
3. `/static/css/sd-module-unified.css` as the final override

This keeps modules modular while forcing a single cohesive light-mode Single Digits shell look across:

- Nomadix Configuration Builder
- Evidence Pack
- MAC Trace
- Port Map
- Switch Health
- Topology
- SmartZone AP Investigator
- ForeScout
- MikroTik Router Builder

The module normalization layer standardizes:

- headers/topbars
- cards/panels
- forms/inputs/buttons
- tables
- status badges
- live status panels
- shell spacing/radius/shadow values
- light-mode color palette

Command set sharing remains centralized through `shared/commands.py` and app-level wrappers should continue to call shared helpers instead of maintaining separate duplicate command lists.
