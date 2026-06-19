#!/bin/bash
# Restart ONE (or more) production services — window lain tidak disentuh.
#
# Usage:
#   bash restart_service_mac.sh live-pull
#   bash restart_service_mac.sh live-login
#   bash restart_service_mac.sh live-status
#   bash restart_service_mac.sh sync-logs          # 3 sync window sekaligus
#   bash restart_service_mac.sh bot
#   bash restart_service_mac.sh listen
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
START="$ROOT/start_production_mac.sh"

escape_sq() {
  printf "%s" "$1" | sed "s/'/'\"'\"'/g"
}

usage() {
  echo "Usage: bash restart_service_mac.sh SERVICE [SERVICE ...]"
  echo ""
  echo "  bot | listen | live-pull | live-login | live-status | sync-logs"
  exit 2
}

service_title() {
  case "$1" in
    bot)         echo "OTP - BOT" ;;
    listen)      echo "OTP - LISTEN" ;;
    live-pull)   echo "OTP - LIVE-PULL" ;;
    live-login)  echo "OTP - LIVE-LOGIN" ;;
    live-status) echo "OTP - LIVE-STATUS" ;;
    *)           return 1 ;;
  esac
}

service_pattern() {
  case "$1" in
    bot)         echo 'telegram_otp_allinone\.py bot$' ;;
    listen)      echo 'telegram_otp_allinone\.py listen$' ;;
    live-pull)   echo 'telegram_otp_allinone\.py sync live$' ;;
    live-login)  echo 'telegram_otp_allinone\.py sync live-login$' ;;
    live-status) echo 'telegram_otp_allinone\.py sync live-status$' ;;
    *)           return 1 ;;
  esac
}

stop_service() {
  local key="$1"
  local pattern count=0 pid cmd
  pattern="$(service_pattern "$key")" || return 1
  for pid in $(pgrep -f "telegram_otp_allinone.py" 2>/dev/null || true); do
    cmd=$(ps -p "$pid" -o command= 2>/dev/null || true)
    [[ -n "$cmd" && "$cmd" == *"$ROOT"* ]] || continue
    [[ "$cmd" =~ $pattern ]] || continue
    kill "$pid" 2>/dev/null && count=$((count + 1)) || true
  done
  if [[ "$key" == "bot" && "$count" -gt 0 ]]; then
    rm -f "$ROOT/.bot_polling.lock"
  fi
  echo "$count"
}

open_service() {
  local key="$1"
  local title cmd title_esc cmd_esc
  title="$(service_title "$key")" || return 1

  case "$key" in
    bot)         cmd="bash '$(escape_sq "$START")' run-service '$(escape_sq "$title")' bot" ;;
    listen)      cmd="bash '$(escape_sq "$START")' run-service '$(escape_sq "$title")' listen" ;;
    live-pull)   cmd="bash '$(escape_sq "$START")' run-service '$(escape_sq "$title")' sync live" ;;
    live-login)  cmd="bash '$(escape_sq "$START")' run-service '$(escape_sq "$title")' sync live-login" ;;
    live-status) cmd="bash '$(escape_sq "$START")' run-service '$(escape_sq "$title")' sync live-status" ;;
    *)           return 1 ;;
  esac

  title_esc="${title//\"/\\\"}"
  cmd_esc="${cmd//\"/\\\"}"

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

expand_one() {
  local s="$1"
  if [[ "$s" == "sync-logs" ]]; then
    printf '%s\n' live-pull live-login live-status
  else
    printf '%s\n' "$s"
  fi
}

[[ $# -ge 1 ]] || usage

if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  echo "ERROR: .venv belum ada. Jalankan: bash setup_mac.sh"
  exit 1
fi

SERVICES=()
while [[ $# -gt 0 ]]; do
  while IFS= read -r line; do
    SERVICES+=("$line")
  done < <(expand_one "$1")
  shift
done

echo ""
echo -n "Restart service(s):"
for svc in "${SERVICES[@]}"; do
  if ! service_title "$svc" >/dev/null; then
    echo "ERROR: service tidak dikenal: $svc"
    usage
  fi
  echo -n " $svc"
done
echo ""
echo ""

for svc in "${SERVICES[@]}"; do
  stopped="$(stop_service "$svc")"
  if [[ "$stopped" -gt 0 ]]; then
    echo "  [$svc] dihentikan: $stopped proses."
  else
    echo "  [$svc] tidak ada proses lama (start fresh)."
  fi
done

sleep 2

for svc in "${SERVICES[@]}"; do
  echo "  [$svc] membuka window baru..."
  open_service "$svc"
  sleep 1
done

echo ""
echo "Selesai. Window lama yang sudah mati bisa ditutup manual (Cmd+W)."
echo ""
