# Single Digits Engineering Platform — Alpha 0.7.5

Clean shell bundle with Monitoring Tool integrated as a Support Diagnostics module.

## Added in Alpha 0.7.5

- New `apps/monitoring` shell module mounted at `/apps/monitoring`.
- Down Device Troubleshooter imported from the prior Monitoring Tool Alpha 0.7.5 standalone build.
- Reusable monitoring/down-device evidence logic added to `shared/monitoring.py`.
- Monitoring command helpers added to `shared/commands.py`.
- Ruckus interface brief parsing improved in `shared/parsers`.
- Saved monitoring run JSON under `%LOCALAPPDATA%/SingleDigitsEngineeringPlatform/Monitoring/runs`.
- Internal version naming updated to Alpha 0.7.5.

## Start

Run `start.bat` on Windows or `start.sh` on Linux/macOS, then open `http://127.0.0.1:8010`.

## Alpha 0.7.5 integrated command normalization rebuild

This rebuilt package includes Switch Configurator as `/apps/switch-configurator`, adds shell-wide `/site-context`, and normalizes reusable command selection through `shared/commands.py`. See `COMMAND_NORMALIZATION_ALPHA_0_7_5.md` for details.
