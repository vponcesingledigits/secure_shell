# Single Digits Shell Add-on: Shared Traffic Investigation Core

This bundle adds a shared investigation engine so MAC Trace and Traffic Analyzer use the same MAC/IP location method.

Main file:

```text
shared/investigation.py
```

New module scaffold:

```text
apps/traffic_analyzer/
```

Integration note:

```text
apps/mac_trace_integration_notes/README.md
```

Copy the contents into the shell root, then wire `apps/traffic_analyzer/routes.py` to the real `shared/ssh.py` command runner.
