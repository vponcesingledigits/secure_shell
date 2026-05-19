# Off-Service Alpha.0.8.0 HTML Fix

This patch repairs the `apps/off_service` module when the route exists but the module is missing its HTML/template file.

## Install

From the extracted patch folder:

```powershell
python tools\install_off_service_html_fix.py "C:\Path\To\Single_Digits_Engineering_Platform_Alpha.0.8.0"
```

Restart the shell and open:

```text
http://127.0.0.1:8010/apps/off-service
```

## Files installed

```text
apps/off_service/__init__.py
apps/off_service/module.json
apps/off_service/routes.py
apps/off_service/templates/off_service.html
apps/off_service/static/off_service.css
apps/off_service/static/off_service.js
shared/offservice_commands.py
shared/redaction.py
.env.offservice.example
```

## Notes

- Sensitive values are read from `.env` / `.env.offservice` and are not hardcoded in the HTML.
- The route supports both `/apps/off-service` and `/apps/off-service/`.
- The route uses the template when present and has a fallback so the page will not hard-fail if the template is misplaced.
