#!/bin/sh
# 海育幼兒園圖書管理系統安裝／初始化腳本（macOS／Linux）
set -eu

BASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON=${PYTHON:-python3}

command -v "$PYTHON" >/dev/null 2>&1 || {
    echo "找不到 Python 3，請先安裝 Python 3.8 以上。" >&2
    exit 1
}

"$PYTHON" - <<'PY'
import sys
if sys.version_info < (3, 8):
    raise SystemExit("需要 Python 3.8 以上。")
PY

mkdir -p "$BASE_DIR/data/backups"
chmod +x "$BASE_DIR/start.sh" "$BASE_DIR/update.sh" 2>/dev/null || true

# 啟動一次資料庫初始化，既有資料不會被覆蓋。
(cd "$BASE_DIR" && "$PYTHON" -c 'import server; server.init_db()')

echo "安裝／初始化完成。"
echo "啟動方式：$BASE_DIR/start.sh"
echo "網址：http://localhost:8000/index.html"
