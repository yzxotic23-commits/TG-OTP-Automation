#!/bin/bash
# Setup project di Mac tanpa Homebrew — pakai Python bawaan macOS.
set -e
cd "$(dirname "$0")"

PY="/usr/bin/python3"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "ERROR: Python tidak ditemukan. Install Xcode Command Line Tools:"
  echo "  xcode-select --install"
  exit 1
fi

echo "Python: $($PY --version)"
echo "Membuat virtual environment (.venv)..."
"$PY" -m venv .venv

echo "Install dependencies..."
.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo ""
echo "Selesai. Jalankan bot:"
echo "  cd \"$(pwd)\""
echo "  source .venv/bin/activate"
echo "  python telegram_otp_allinone.py listen"
