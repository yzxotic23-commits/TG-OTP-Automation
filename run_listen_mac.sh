#!/bin/bash
cd "$(dirname "$0")"
if [ ! -f .venv/bin/activate ]; then
  echo "ERROR: .venv belum ada. Jalankan dulu: bash setup_mac.sh"
  exit 1
fi
source .venv/bin/activate
python telegram_otp_allinone.py listen
