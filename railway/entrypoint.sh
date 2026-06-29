#!/bin/bash
# Railway: 1 container, 5 proses (bot + listen + 3x live sync)
set -euo pipefail

APP=/app
DATA="${RAILWAY_DATA_DIR:-/data}"
PY="$APP/.venv/bin/python"

mkdir -p "$DATA/telegram_session/shooter"

link_dir() {
  local name="$1"
  mkdir -p "$DATA/$name"
  rm -rf "$APP/$name"
  ln -sf "$DATA/$name" "$APP/$name"
}

link_file() {
  local name="$1"
  if [[ -f "$DATA/$name" ]]; then
    rm -f "$APP/$name"
    ln -sf "$DATA/$name" "$APP/$name"
  elif [[ -f "$APP/$name" ]] && [[ ! -L "$APP/$name" ]]; then
    cp -a "$APP/$name" "$DATA/$name"
    rm -f "$APP/$name"
    ln -sf "$DATA/$name" "$APP/$name"
  fi
}

link_dir telegram_session
link_file accounts.json
link_file shooteraccounts.json
link_file state.json

# Google service account JSON (upload ke volume /data)
shopt -s nullglob
for src in "$DATA"/tg-otp-automation-*.json "$DATA"/google-credentials.json; do
  base="$(basename "$src")"
  ln -sf "$src" "$APP/$base"
done
shopt -u nullglob

ulimit -n 65536 2>/dev/null || ulimit -n 10240 2>/dev/null || true

echo "========================================"
echo "  Telegram OTP — Railway (5 processes)"
echo "  Data volume: $DATA"
sessions="$(find "$DATA/telegram_session" -name '*.session' -type f 2>/dev/null | wc -l | tr -d ' ')"
echo "  Sessions on volume: $sessions"
echo "========================================"

if [[ "$sessions" -eq 0 ]]; then
  echo ""
  echo "  [!] Belum ada .session di volume."
  echo "      Upload telegram_session/ ke /data via Railway shell / CLI."
  echo ""
fi

exec supervisord -n -c /railway/supervisord.conf
