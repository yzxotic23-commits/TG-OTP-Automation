# Telegram BOT OTP

Telegram bot that forwards login OTP codes to configured chats. Production runs as **5 separate PowerShell windows**.

---

## Quick Start (Windows)

```powershell
cd "E:\Telegram BOT OTP"
powershell -ExecutionPolicy Bypass -File .\setup.ps1
powershell -ExecutionPolicy Bypass -File .\start_production.ps1
```

Copy manually (do **not** use Git): `.env`, `accounts.json`, `shooteraccounts.json`, `tg-otp-automation-*.json`, `telegram_session\**\*.session`

---

## Google Sheet columns (tab `Telegram Acc`)

| Column | Who writes | Values |
|--------|------------|--------|
| **Status** | **Staff** sets `Pending` to trigger login. **Script** writes `Ready`, `Banned`, `Frozen`, `Expired`, `Disconnected` | Script **never** writes `Pending` or `Pending Login` |
| **Session Friday** | **Script only** | `Active`, `Pending Login`, `Banned`, `Frozen`, `Expired`, `Disconnected` |
| **OTP** | Staff during login | 5-digit SMS code |
| **2FA** | Staff | Cloud password if account has 2FA |

**Staff rule:** Only set **Status = Pending** manually. Session Friday is the main reference for bot session state.

---

## Production windows

| # | Service | Role |
|---|---------|------|
| 1 | BOT | `/login`, `/main`, `/other`, `/ping` |
| 2 | LISTEN | OTP forward + detect Banned/Frozen/Expired → queue (no status spam on reconnect) |
| 3 | LIVE-PULL | Pending + **new phone** → JSON only |
| 4 | LIVE-LOGIN | SMS once → wait OTP in Sheet |
| 5 | LIVE-STATUS | Push queue → Sheet + scheduled health-check (**12h**, 2 shifts/day) |

Restart **one** service only:

```powershell
powershell -ExecutionPolicy Bypass -File .\restart_service.ps1 listen
powershell -ExecutionPolicy Bypass -File .\restart_service.ps1 live-status
```

Full reset (all 5 windows — stops duplicates):

```powershell
powershell -ExecutionPolicy Bypass -File .\start_production.ps1
```

**No restart needed** when editing `accounts.json` or Sheet rows (LISTEN hot-reload ~45s).

---

## Account status detection

| Status | When detected | System Status alert |
|--------|---------------|---------------------|
| **Banned** | LISTEN on connect | Yes |
| **Expired** (dead session) | LISTEN on connect fail | Yes (cooldown 24h; not from LISTEN reconnect spam) |
| **Frozen** (`restricted=True`) | LISTEN on connect | Purge JSON; alert on change via health-check |
| **Frozen** (UI / SpamBot only) | Health-check (@SpamBot + Saved Messages probe) | Yes (cooldown 24h) |
| **Disconnected** | LISTEN reconnect fail | Queued to Sheet; no LISTEN alert spam |

**LIVE-STATUS** startup banner shows **next scheduled health-check** time (local server clock).  
Manual health-check anytime:

```powershell
.\.venv\Scripts\python.exe telegram_otp_allinone.py sync health --pool all
```

Check schedule from `state.json`:

```powershell
python -c "import time,json; from datetime import datetime,timezone,timedelta; st=json.load(open('state.json')); ts=st.get('last_health_check_ts',0); iv=43200; print('Last:',(datetime.fromtimestamp(ts,tz=timezone.utc)+timedelta(hours=7)).strftime('%d/%m/%Y %H:%M')); print('Next:',(datetime.fromtimestamp(ts+iv,tz=timezone.utc)+timedelta(hours=7)).strftime('%d/%m/%Y %H:%M'))"
```

---

## New account login

1. Add row in Google Sheet (Device ID, Group, Acc Name, Phone, …)
2. Staff set **Status = Pending**
3. LIVE-PULL registers phone if new → JSON
4. LIVE-LOGIN sends SMS → fill **OTP** column
5. Script writes **Status = Ready**, **Session Friday = Active**

---

## Replace banned account (same row)

1. Old account → **Status = Banned**, **Session Friday = Banned** (auto purge JSON + session)
2. Clear row → fill new details (new phone OK)
3. Staff set **Status = Pending** → login flow as new account

---

## Reconcile JSON vs Sheet

Find accounts in JSON missing from Sheet (common gap):

```powershell
.\.venv\Scripts\python.exe telegram_otp_allinone.py sync reconcile
```

Add missing rows to Sheet before expecting status sync to work.

---

## Staff rules (Telegram group)

| Rule | Detail |
|------|--------|
| **Topics** | **Main (GCS):** MYR / SGD / USC topic. **Other (Shooter):** `/other` in same topic — MYR/SGD by owner name (e.g. `KAREN`), **USC by brand** (e.g. `OK188KH`). **WPLUS:** `/main WPLUS` in USC topic only. **Not** #feedback or System Status. |
| **OTP** | Send `/login` in the correct topic **before** OTP is forwarded. |
| **Lists** | `/main` and `/other` hide accounts with Pending or Pending Login (no session ready). |
| **Alerts** | Manual Login Detected tags: @geri_work @Sinyee_29 @Zaabryan (separate from bot admin role). |
| **Owner rename** | Sheet sync renames session files; expired/missing sessions still need Pending + login. |

See **WEEKLY_OPS_CHECKLIST.txt** for ops routine and **COMMANDS.txt** for full reference.

---

## Bot commands

| Command | Function |
|---------|----------|
| `/main [BRAND]` | List GCS accounts (Pending / Pending Login hidden) |
| `/other [USER\|BRAND]` | List shooter accounts — MYR/SGD: owner name; USC: brand code (Pending / Pending Login hidden) |
| `/login ACCOUNT_ID` | Request OTP — must be in correct forum topic first |
| `/ping` | Bot alive check |

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `409 Conflict` | Only one BOT instance; use `start_production.ps1` once |
| `getaddrinfo failed` / Google timeout | DNS/network blip — set DNS `8.8.8.8` + `8.8.4.4`, then `ipconfig /flushdns` and restart services |
| Duplicate services | `Get-CimInstance Win32_Process -Filter "Name='python.exe'"` — should be **1** per service |
| OTP not delivered | LISTEN running + staff used `/login` first |
| Status not syncing | Run `sync reconcile` — phone may be missing from Sheet |
| `database is locked` | Stop LISTEN briefly, retry login |
| Health-check seems late | Interval is **48h from last run**, not calendar days — check banner in LIVE-STATUS |

---

## Key env vars (see `.env.example`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `TELEGRAM_SYNC_HEALTH_INTERVAL_SEC` | `43200` | Health-check every 12 hours |
| `TELEGRAM_SYNC_STATUS_INTERVAL_SEC` | `300` | Delta push queue → Sheet |
| `TELEGRAM_SHEET_READ_CACHE_SEC` | `120` | Cache Sheet reads (LISTEN pending check) |
| `TELEGRAM_NOTIFY_EXPIRED_COOLDOWN_SEC` | `86400` | Expired alert max once per day |
| `TELEGRAM_NOTIFY_FROZEN_COOLDOWN_SEC` | `86400` | Frozen alert max once per day |
| `TELEGRAM_PURGE_FROZEN_ACCOUNTS` | `1` | Remove frozen from bot list + JSON |
| `TELEGRAM_MANUAL_LOGIN_CC` | `geri_work,sinyee,zaabryan` | Who gets tagged on Manual Login Detected |

---

## Git safety

Do not commit: `.env`, `telegram_session/`, credentials JSON, `*.lock`, `state.json`, `sheet_status_queue.jsonl`, `deliverables*.txt`, `JIRA_TASKS_7_DAYS.txt`

Optional env vars: see `.env.example`
