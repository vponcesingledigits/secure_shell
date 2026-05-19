from __future__ import annotations
try:
    from apps.history.store import HistoryStore, history_root
except Exception:
    HistoryStore = None
    def history_root():
        from pathlib import Path
        p = Path('data/history'); p.mkdir(parents=True, exist_ok=True); return p
