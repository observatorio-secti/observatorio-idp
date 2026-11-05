#!/bin/sh
set -e

echo "Executando migrações do banco de dados (Alembic)..."
alembic upgrade head

echo "Iniciando Observatório IdP..."
if [ $# -gt 0 ]; then
    exec "$@"
elif [ -n "$ROOT_PATH" ]; then
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --root-path "$ROOT_PATH"
else
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000
fi
