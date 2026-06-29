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
ARCHIVE="$(mktemp -t otp-data-XXXXXX).tgz"
cleanup() { rm -rf "$STAGING" "$ARCHIVE"; }
trap cleanup EXIT

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
echo "Sessions: $session_count (~${archive_mb} MB compressed — normal)"
echo ""
echo "Upload otp-data.tgz (retry otomatis kalau timeout)..."
echo ""

upload_ok=0
for attempt in 1 2 3 4 5; do
  if railway volume files --volume "$VOLUME" upload "$ARCHIVE" /otp-data.tgz --overwrite; then
    upload_ok=1
    break
  fi
  if [[ "$attempt" -lt 5 ]]; then
    wait=$((attempt * 15))
    echo ""
    echo "Upload gagal (attempt $attempt/5). Coba lagi dalam ${wait}s..."
    echo "  Tip: cek WiFi / VPN off / Railway dashboard service Running"
    sleep "$wait"
  fi
done

if [[ "$upload_ok" -ne 1 ]]; then
  echo ""
  echo "ERROR: Upload gagal setelah 5x (SFTP timeout)."
  echo "  Coba lagi: bash railway/upload_to_volume.sh"
  echo "  Atau upload manual: railway volume files --volume $VOLUME upload \"$ARCHIVE\" /otp-data.tgz --overwrite"
  exit 1
fi

echo ""
echo "Selesai upload."
echo ""
echo "Langkah berikutnya:"
echo "  1. Redeploy service di Railway (pull commit terbaru)"
echo "  2. Log harus: Extract otp-data.tgz + Sessions on volume: $session_count"
echo "  3. Matikan production Mac"
echo ""
