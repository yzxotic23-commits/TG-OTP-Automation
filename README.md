# Telegram BOT OTP

Telegram bot that forwards Telegram login OTP codes to configured chats.

---

## Quick Start (New PC)

### 1. Setup (once)

```powershell
cd "E:\Telegram BOT OTP"
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

### 2. Copy sensitive files manually (do not use Git)

```
.env
accounts.json
shooteraccounts.json
tg-otp-automation-*.json
telegram_session\**\*.session
```

> Do **not** sync `telegram_session/` across Mac/Windows via Git.

### 3. New account login (production flow)

1. Add a row in Google Sheet (Phone, Group, User, …).
2. **LIVE-PULL** syncs Sheet → JSON.
3. Set **column I (Status) = `Pending`** to trigger login.
4. When SMS arrives, fill **OTP column** (header `OTP`). Put **2FA** in its column if the account uses 2FA.
5. After success: **J & K = Active**, **I = Feeding**.

Emergency terminal login (optional):

```powershell
.\.venv\Scripts\python.exe telegram_otp_allinone.py login-all
.\.venv\Scripts\python.exe telegram_otp_allinone.py login-all-shooter
```

### 4. Run production (5 separate PowerShell windows)

```powershell
powershell -ExecutionPolicy Bypass -File .\start_production.ps1
```

This script will:
- Stop old OTP processes (bot/listen/live-*) if still running
- Open **5 external PowerShell windows**: BOT, LISTEN, LIVE-PULL, LIVE-LOGIN, LIVE-STATUS
- Handle new sessions via Sheet column **L (OTP)** — no typing in the terminal

---

## Google Sheet columns (tab `Telegram Acc`)

| Col | Header | Role |
|-----|--------|------|
| I | Status | Staff sets **Pending** to trigger LIVE-LOGIN |
| J | Account Status | Script writes **Active** (or Banned/Frozen) after login |
| K | Session Friday | Script writes **Active** after login |
| L | 2FA | Cloud / 2FA password (if the Telegram account has 2FA enabled) |
| M | OTP | Staff fills SMS code during login |

---

## Bot commands (Telegram)

| Command | Function |
|---------|----------|
| `/start` | Register / link staff |
| `/ping` | Check bot is alive |
| `/accounts` | List GCS brands |
| `/login STMY_LINA` | Request OTP for an account |

---

## PowerShell scripts

| Script | Function |
|--------|----------|
| `setup.ps1` | First-time setup + venv helpers |
| `start_production.ps1` | Stop old processes + start all 5 live services |

## Manual sync (any PowerShell window)

```powershell
.\.venv\Scripts\python.exe telegram_otp_allinone.py sync
.\.venv\Scripts\python.exe telegram_otp_allinone.py sync health
```

Do not use `sync loop`.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `409 Conflict` | Do not start the bot twice; close old BOT window; run `start_production.ps1` once |
| `AuthKeyDuplicatedError` | Session used on 2 machines; re-login; run `listen` on one PC only |
| OTP not delivered | Ensure LISTEN window is running and staff used `/login` |
| `database is locked` | Stop LISTEN, then retry login |

---

## Git safety

Do not commit: `.env`, `telegram_session/`, `tg-otp-automation-*.json`, `*.lock`, `state.json`.

Optional variables: see `.env.example`.
