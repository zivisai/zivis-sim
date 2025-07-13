#!/usr/bin/env bash
set -xe

echo "=== RUNNING migrations ==="
python data/int_db.py

echo "=== INGESTING vectors ==="
python langchain_ingest.py

echo "=== STARTING debugpy+uvicorn ==="
exec python -Xfrozen_modules=off -u -m debugpy \
    --listen 0.0.0.0:5678 \
    --wait-for-client \
    --log-to-stderr \
    -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
