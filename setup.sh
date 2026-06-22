#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
    echo "Virtual muhit yaratilmoqda..."
    python3 -m venv .venv
fi

echo "Kutubxonalar o'rnatilmoqda..."
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo ""
echo "Tayyor! Ishlatish:"
echo "  source .venv/bin/activate"
echo "  python cli.py serve                          # brauzerda ochiladi"
echo "  python cli.py serve --domain my.mingeo.uz    # avtomatik skanerlash"
echo "  python cli.py scan my.mingeo.uz --open       # HTML brauzerda"
