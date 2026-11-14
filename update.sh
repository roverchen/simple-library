#!/bin/bash
# Simple Library 自動更新腳本
# 用途：從 GitHub 拉取最新程式碼並重啟伺服器
set -e
cd "$(dirname "$0")"
echo "[1/3] git pull origin main..."
git pull origin main
echo "[2/3] 重啟伺服器..."
PID=$(lsof -iTCP:8080 -sTCP:LISTEN -n -P 2>/dev/null | awk 'NR>1{print $2}' | head -1)
if [ -n "$PID" ]; then
  kill "$PID" 2>/dev/null || true
  for i in $(seq 1 20); do
    lsof -iTCP:8080 -sTCP:LISTEN >/dev/null 2>&1 || break
    sleep 0.5
  done
fi
nohup python3 server.py --host 0.0.0.0 --port 8080 >> data/server.log 2>&1 &
sleep 2
echo "[3/3] 完成，伺服器已重啟。"
lsof -iTCP:8080 -sTCP:LISTEN -n -P | tail -1