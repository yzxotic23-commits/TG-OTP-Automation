#!/bin/bash
# Upload session + secrets ke Railway volume.
# Archive di-extract otomatis saat container start (entrypoint.sh).
#
#   cd "/Users/geri/Telegram-BOT-OTP"
#   bash railway/upload_to_volume.sh
#   # lalu Redeploy di Railway dashboard
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v railway >/dev/null 2>&1; then
  echo "Install: brew install railway"
  exit 1
fi

VOLUME="$(railway volume list 2>/dev/null | awk '/^Volume: /{print $2; exit}')"
if [[ -z "$VOLUME" ]]; then
  echo "ERROR: Volume tidak ditemukan."
  exit 1
fi

STAGING="$(mktemp -d)"
ARCHIVE="$STAGING/otp-data.tgz"
trap 'rm -rf "$STAGING"' EXIT

mkdir -p "$STAGING/telegram_session/shooter"

echo "Menyiapkan archive..."
find telegram_session -name '*.session' -type f ! -name '._*' | while IFS= read -r f; do
  rel="${f#telegram_session/}"
  mkdir -p "$STAGING/telegram_session/$(dirname "$rel")"
  cp -a "$f" "$STAGING/telegram_session/$rel"
done

cp -a accounts.json shooteraccounts.json "$STAGING/" 2>/dev/null || true
cp -a state.json "$STAGING/" 2>/dev/null || true
shopt -s nullglob
for f in tg-otp-automation-*.json google-credentials.json; do
  cp -a "$f" "$STAGING/" 2>/dev/null || true
done
shopt -u nullglob

tar -czf "$ARCHIVE" -C "$STAGING" .
session_count="$(find "$STAGING/telegram_session" -name '*.session' -type f | wc -l | tr -d ' ')"
archive_mb="$(du -sm "$ARCHIVE" | awk '{print $1}')"

echo ""
echo "Volume  : $VOLUME"
echo "Sessions: $session_count (.session saja — ~${archive_mb} MB normal)"
echo ""
echo "Upload otp-data.tgz ..."
railway volume files --volume "$VOLUME" upload "$ARCHIVE" /otp-data.tgz --overwrite

echo ""
echo "Selesai upload."
echo ""
echo "Langkah berikutnya:"
echo "  1. Push entrypoint terbaru ke Git (kalau belum) + Redeploy Railway"
echo "  2. Container akan extract otp-data.tgz otomatis → Sessions on volume: $session_count"
echo "  3. Matikan production Mac"
echo ""
