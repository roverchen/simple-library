@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel% equ 0 (
    py -3 server.py --host 0.0.0.0 --port 8000 %*
) else (
    python server.py --host 0.0.0.0 --port 8000 %*
)

if errorlevel 1 (
    echo 系統已停止或啟動失敗。
    pause
)
