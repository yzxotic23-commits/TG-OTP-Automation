#!/bin/bash
# ============================================================
# START_PRODUCTION_MAC.SH — buka 5 window Terminal.app sekaligus
# BOT + LISTEN + LIVE-PULL + LIVE-LOGIN + LIVE-STATUS
#
# Jalankan:
#   cd "/path/to/Telegram BOT OTP"
#   bash start_production_mac.sh
# ============================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

PY="$ROOT/.venv/bin/python"
SCRIPT="$ROOT/telegram_otp_allinone.py"
SELF="$ROOT/start_production_mac.sh"

escape_sq() {
  printf "%s" "$1" | sed "s/'/'\"'\"'/g"
}

run_service() {
  local title="$1"
  shift
  clear
  printf '\033]0;%s\007' "$title"
  echo "$title"
  echo "========================================"
  echo ""
  cd "$ROOT"
  find .venv -name '._*' -type f -delete 2>/dev/null
  # LISTEN buka ratusan session SQLite — macOS default ~256 fd tidak cukup
  ulimit -n 10240 2>/dev/null || ulimit -n 4096 2>/dev/null || true
  "$PY" "$SCRIPT" "$@" || {
    local code=$?
    echo ""
    echo "[$title] service berhenti (exit $code)."
    read -r -p "Tekan Enter untuk tutup window... " _
    exit "$code"
  }
}

stop_old_processes() {
  local count=0
  local pid cmd
  for pid in $(pgrep -f "telegram_otp_allinone.py" 2>/dev/null || true); do
    cmd=$(ps -p "$pid" -o command= 2>/dev/null || true)
    [[ -n "$cmd" && "$cmd" == *"$ROOT"* ]] || continue
    [[ "$cmd" =~ telegram_otp_allinone\.py[[:space:]]+(bot|listen|sync[[:space:]]+live|sync[[:space:]]+live-login|sync[[:space:]]+live-status) ]] || continue
    kill "$pid" 2>/dev/null && count=$((count + 1)) || true
  done
  rm -f "$ROOT/.bot_polling.lock"
  echo "$count"
}

open_otp_window() {
  local title="$1"
  shift
  local args=("$@")
  local cmd="bash '$(escape_sq "$SELF")' run-service '$(escape_sq "$title")'"
  local a
  for a in "${args[@]}"; do
    cmd+=" '$(escape_sq "$a")'"
  done

  local title_esc="${title//\"/\\\"}"
  local cmd_esc="${cmd//\"/\\\"}"

  osascript <<APPLESCRIPT
tell application "Terminal"
  activate
  set w to do script "${cmd_esc}"
  try
    set custom title of w to "${title_esc}"
  end try
end tell
APPLESCRIPT
}

# Dipanggil otomatis dari setiap window Terminal (bukan untuk user)
if [[ "${1:-}" == "run-service" ]]; then
  shift
  [[ $# -ge 1 ]] || { echo "Usage: $0 run-service TITLE [python args...]"; exit 2; }
  run_service "$@"
  exit 0
fi

echo ""
echo "========================================"
echo "  Telegram OTP - Start Production (Mac)"
echo "========================================"
echo ""

if [[ ! -f "$ROOT/.env" ]]; then
  echo "ERROR: .env tidak ditemukan. Isi dulu .env (copy dari .env.example)."
  exit 1
fi

for f in accounts.json shooteraccounts.json; do
  if [[ ! -f "$ROOT/$f" ]]; then
    echo "ERROR: $f tidak ditemukan."
    exit 1
  fi
done

if [[ ! -x "$PY" ]]; then
  echo "ERROR: .venv belum ada / belum Mac-ready."
  echo "Jalankan dulu: bash setup_mac.sh"
  exit 1
fi

echo "[1/3] Menghentikan proses OTP lama..."
stopped="$(stop_old_processes)"
if [[ "$stopped" -gt 0 ]]; then
  echo "       Dihentikan: $stopped proses."
  sleep 2
else
  echo "       Tidak ada proses OTP yang berjalan."
fi

echo ""
echo "[2/3] Mengecek session..."
session_count="$(find "$ROOT/telegram_session" -name "*.session" ! -name "._*" -type f 2>/dev/null | wc -l | tr -d ' ')"
echo "       $session_count file .session ditemukan."
if [[ "$session_count" -eq 0 ]]; then
  echo "       [!] Belum ada session. Login dulu sebelum production."
  read -r -p "       Lanjut start production tanpa session? (y/N): " ans
  [[ "$ans" =~ ^[yY]$ ]] || exit 0
fi

echo ""
echo "[3/3] Membuka 5 window Terminal..."
open_otp_window "OTP - BOT" bot
sleep 2
open_otp_window "OTP - LISTEN" listen
sleep 2
open_otp_window "OTP - LIVE-PULL" sync live
sleep 2
open_otp_window "OTP - LIVE-LOGIN" sync live-login
sleep 2
open_otp_window "OTP - LIVE-STATUS" sync live-status

echo ""
echo "========================================"
echo "  Production running (5 Terminal windows)"
echo "========================================"
echo ""
echo "  1 = BOT          (/login, /main, /other, /ping)"
echo "  2 = LISTEN       (OTP + status ke Sheet)"
echo "  3 = LIVE-PULL    (Sheet -> JSON, auto register)"
echo "  4 = LIVE-LOGIN   (kolom OTP Sheet -> .session)"
echo "  5 = LIVE-STATUS  (queue + health-check 12h -> Sheet)"
echo ""
echo "  Tutup window Terminal = stop service itu saja."
echo "  Jangan jalankan script ini lagi kalau 5 window masih terbuka."
echo "  Jangan start bot dari Cursor terminal (hindari 409 Conflict)."
echo ""
