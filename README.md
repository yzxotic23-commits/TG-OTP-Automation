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
| 1 | BOT | `/login`, `/accounts`, `/ping` |
| 2 | LISTEN | OTP forward + detect Banned/Frozen → queue |
| 3 | LIVE-PULL | Pending + **new phone** → JSON only |
| 4 | LIVE-LOGIN | SMS once → wait OTP in Sheet |
| 5 | LIVE-STATUS | Push queue → Sheet + health-check (2 days) |

Restart **one** service only:

```powershell
powershell -ExecutionPolicy Bypass -File .\restart_service.ps1 listen
```

Full reset (all 5 windows):

```powershell
powershell -ExecutionPolicy Bypass -File .\start_production.ps1
```

**No restart needed** when editing `accounts.json` or Sheet rows (LISTEN hot-reload ~45s).

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

## Bot commands

| Command | Function |
|---------|----------|
| `/accounts [BRAND]` | List GCS accounts |
| `/login ACCOUNT_ID` | Request OTP (staff must send in topic first if `TELEGRAM_REQUIRE_LOGIN_REQUEST=1`) |
| `/ping` | Bot alive check |

See **COMMANDS.txt** for full reference.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `409 Conflict` | Only one BOT instance; use `start_production.ps1` once |
| LISTEN Unicode error | Fixed: UTF-8 stdout on Windows (restart LISTEN) |
| OTP not delivered | LISTEN running + staff used `/login` |
| Status not syncing | Run `sync reconcile` — phone may be missing from Sheet |
| `database is locked` | Stop LISTEN briefly, retry login |

---

## Git safety

Do not commit: `.env`, `telegram_session/`, credentials JSON, `*.lock`, `state.json`, `sheet_status_queue.jsonl`

Optional env vars: see `.env.example`
