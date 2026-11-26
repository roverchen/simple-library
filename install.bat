@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel% equ 0 (
    set "PYTHON=py -3"
) else (
    where python >nul 2>nul
    if errorlevel 1 (
        echo 找不到 Python 3，請先安裝 Python 3.8 以上，並勾選 Add Python to PATH。
        pause
        exit /b 1
    )
    set "PYTHON=python"
)

if not exist "data\backups" mkdir "data\backups"

echo 正在初始化資料庫（既有資料不會被覆蓋）...
%PYTHON% -c "import server; server.init_db()"
if errorlevel 1 (
    echo 初始化失敗，請確認 Python 版本與檔案完整性。
    pause
    exit /b 1
)

echo 安裝／初始化完成。
echo 請雙擊 start.bat 啟動系統。
pause
