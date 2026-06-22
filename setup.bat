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
echo Tayyor! Ishlatish:
echo   .venv\Scripts\activate
echo   python cli.py scan my.mingeo.uz
