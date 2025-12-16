#!/usr/bin/env bash
set -xe

echo "=== RUNNING migrations ==="
python data/int_db.py

echo "=== INGESTING vectors ==="
python langchain_ingest.py

if [ "${PY_DEBUG:-false}" = "true" ]; then
    echo "=== STARTING debugpy+uvicorn (waiting for debugger) ==="
    exec python -Xfrozen_modules=off -u -m debugpy \
    --listen 0.0.0.0:5678 \
    --wait-for-client \
    --log-to-stderr \
    -m uvicorn main:app \
        --host 0.0.0.0 \
        --port 8000 \
        --reload
else
    echo "=== STARTING uvicorn (no debugger) ==="
    exec uvicorn main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --reload
fi
