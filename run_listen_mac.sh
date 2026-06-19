#!/bin/bash
cd "$(dirname "$0")"
if [ ! -f .venv/bin/activate ]; then
  echo "ERROR: .venv belum ada. Jalankan dulu: bash setup_mac.sh"
  exit 1
fi
source .venv/bin/activate
find .venv -name '._*' -type f -delete 2>/dev/null
ulimit -n 10240 2>/dev/null || ulimit -n 4096 2>/dev/null || true
python telegram_otp_allinone.py listen
