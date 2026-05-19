#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
APP_PORT="${APP_PORT:-8010}"
APP_HOST="${APP_HOST:-127.0.0.1}"
if [ ! -x ".venv/bin/python" ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
echo "Starting Single Digits Engineering Platform on http://${APP_HOST}:${APP_PORT}"
python -m uvicorn app.main:app --host "$APP_HOST" --port "$APP_PORT" --reload
