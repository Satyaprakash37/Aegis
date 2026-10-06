#!/bin/sh
set -e

echo "[AEGIS] Running database migrations..."
alembic upgrade head

echo "[AEGIS] Database migration completed. Starting server..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
