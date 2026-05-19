# Security Baseline Alpha 0.7.6

Implemented from audit immediate actions:

- Removed hardcoded SSH fallback credentials from shared SSH engine.
- Pinned ReportLab to `>=4.4.9,<5`.
- Added centralized client-safe exception handling/redaction.
- Added strict MAC address validation for shared MAC trace command generation.
- Added Evidence Pack path traversal protection; exports are limited to History session IDs under the configured history root.
- Strengthened redaction for passwords, secrets, SNMP communities, tokens, API keys, TACACS/RADIUS values, and case-insensitive secret values.

Explicitly not changed per operational requirements:

- Host key policy / AutoAddPolicy behavior.
- Local HTTP/TLS behavior.
- Legacy SSH KEX support for older switch fleets.
