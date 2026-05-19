Single Digits Engineering Platform - MAC Trace fixed baseline

Fixes in this bundle:
- MAC Trace package now exports the known-good async job router (apps.mac_trace.router).
- Restores /apps/mac-trace/trace/start and /trace/status/{job_id}, matching the existing UI JavaScript.
- Keeps the working real-time Command / Progress Output interface.
- Keeps password redaction behavior.
- Keeps targeted learned-port command behavior: MAC lookup first, then LLDP/health only for the learned port.
- Adds shared MAC Trace command catalog functions to shared/commands.py so future apps can reuse the same vendor-aware command sets.

Start with start.bat and open http://127.0.0.1:8010/apps/mac-trace
