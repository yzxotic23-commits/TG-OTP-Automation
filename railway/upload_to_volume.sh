#!/bin/bash
# Upload session + secrets dari Mac ke Railway volume (sekali setup).
# Butuh: railway CLI (npm i -g @railway/cli) + sudah railway login + link project.
#
#   cd "/Users/geri/Telegram-BOT-OTP"
#   bash railway/upload_to_volume.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v railway >/dev/null 2>&1; then
  echo "Install Railway CLI (pilih salah satu):"
  echo "  brew install railway          # Mac — recommended"
  echo "  bash <(curl -fsSL railway.com/install.sh) -y"
  echo "Lalu: railway login && railway link"
  exit 1
fi

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

mkdir -p "$STAGING/telegram_session"
cp -a telegram_session/. "$STAGING/telegram_session/" 2>/dev/null || true
cp -a accounts.json shooteraccounts.json "$STAGING/" 2>/dev/null || true
cp -a state.json "$STAGING/" 2>/dev/null || true
cp -a tg-otp-automation-*.json "$STAGING/" 2>/dev/null || true

echo "Upload ke /data di Railway volume..."
echo "(Proses ini bisa beberapa menit — banyak file .session)"
echo ""

# Pack + extract di container via railway run
tar -C "$STAGING" -czf - . | railway run bash -c 'mkdir -p /data && tar -xzf - -C /data'

echo ""
echo "Selesai. Redeploy service atau restart container di Railway dashboard."
echo "Env vars (.env) tetap set manual di Railway → Variables (jangan commit)."
