# Alpha 0.7.5 Windows 11 Dependency Compatibility Fix

This build fixes a Windows 11 startup failure caused by internet installs pulling the latest FastAPI/Starlette stack.

Observed error:
`TypeError: unhashable type: 'dict'`

Root cause:
Starlette 1.0 changed the Jinja2 `TemplateResponse` argument order. Existing shell modules used the older FastAPI-compatible form.

Fixes:
- pinned FastAPI/Starlette/Uvicorn to the known-compatible shell baseline
- added `app/template_compat.py` so old and new TemplateResponse call styles both work
- updated `start.bat` to use upgrade/downgrade strategy so existing `.venv` environments are corrected automatically
- disabled colored console output where respected by dependencies

If this is run over an existing broken `.venv`, `start.bat` should correct the dependencies automatically.
If it does not, delete `.venv` and run `start.bat` again.
