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
echo "Tayyor! Keyingi qadamlar:"
echo "  1. source .venv/bin/activate"
echo "  2. python cli.py serve"
