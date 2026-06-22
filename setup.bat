@echo off
cd /d "%~dp0"

if not exist ".venv" (
    echo Virtual muhit yaratilmoqda...
    python -m venv .venv
)

echo Kutubxonalar o'rnatilmoqda...
.venv\Scripts\pip install --upgrade pip
.venv\Scripts\pip install -r requirements.txt

echo.
echo Tayyor! Keyingi qadamlar:
echo   1. .venv\Scripts\activate
echo   2. python cli.py serve
