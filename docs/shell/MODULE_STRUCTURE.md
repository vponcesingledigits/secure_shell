# Manifest-Driven Module Structure

Every shell module should follow:

```text
apps/<module_name>/
├── __init__.py
├── routes.py
├── module.json
├── templates/
└── static/   optional
```

The shell scans `apps/*/module.json`, imports each enabled manifest router path, and expects `router = APIRouter(...)`.

The launcher metadata is exposed at:

```text
GET /api/modules
```
