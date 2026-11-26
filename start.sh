#!/bin/sh
# 海育幼兒園圖書管理系統啟動腳本（macOS／Linux）
set -eu

BASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON=${PYTHON:-python3}
HOST=${LIBRARY_HOST:-0.0.0.0}
PORT=${LIBRARY_PORT:-8000}

cd "$BASE_DIR"
exec "$PYTHON" server.py --host "$HOST" --port "$PORT" "$@"
