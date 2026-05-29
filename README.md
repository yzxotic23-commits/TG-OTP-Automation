# Telegram BOT OTP

Bot Telegram untuk meneruskan kode login OTP ke chat yang ditentukan.

---

## Quick Start (PC Baru)

### 1. Setup (sekali saja)

```powershell
cd "E:\Telegram BOT OTP"
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

### 2. Salin file sensitif secara manual (jangan lewat Git)

```
.env
accounts.json
shooteraccounts.json
tg-otp-automation-*.json
telegram_session\**\*.session
```

> `telegram_session/` **tidak** boleh di-sync antar Mac/Windows lewat Git.

### 3. Login akun (jika belum ada `.session`)

```powershell
.\.venv\Scripts\python.exe telegram_otp_allinone.py login-all
.\.venv\Scripts\python.exe telegram_otp_allinone.py login-all-shooter
```

### 4. Jalankan production (3 jendela PowerShell terpisah)

```powershell
powershell -ExecutionPolicy Bypass -File .\start_production.ps1
```

Script ini akan:
- Stop proses OTP lama (bot/listen/live-status) jika masih jalan
- Buka **3 jendela PowerShell eksternal** (bukan terminal Cursor)

---

## Perintah Bot di Telegram

| Perintah | Fungsi |
|----------|--------|
| `/start` | Mulai bot |
| `/ping` | Cek bot aktif |
| `/accounts` | Lihat semua brand |
| `/login STMY_LINA` | Request kode OTP |

---

## Script PowerShell

| Script | Fungsi |
|--------|--------|
| `setup.ps1` | Setup pertama kali + helper venv (bisa di-dot-source) |
| `start_production.ps1` | Stop proses lama + start BOT + LISTEN + LIVE-STATUS |

## Sync manual (jendela PowerShell biasa)

```powershell
.\.venv\Scripts\python.exe telegram_otp_allinone.py sync
.\.venv\Scripts\python.exe telegram_otp_allinone.py sync health
```

Jangan pakai `sync loop`.

---

## Troubleshooting

| Masalah | Solusi |
|---------|--------|
| `409 Conflict` | Jangan start bot 2x; tutup jendela BOT lama; jalankan `start_production.ps1` sekali |
| `AuthKeyDuplicatedError` | Session dipakai di 2 mesin; login ulang; `listen` hanya di 1 PC |
| OTP tidak muncul | Pastikan jendela LISTEN jalan & sudah `/login` |
| `database is locked` | Tutup LISTEN, lalu `login-all` |

---

## Keamanan Git

Jangan commit: `.env`, `telegram_session/`, `tg-otp-automation-*.json`, `*.lock`, `state.json`.

Variabel opsional: lihat `.env.example`.
