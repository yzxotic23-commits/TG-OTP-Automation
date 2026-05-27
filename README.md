# Telegram BOT OTP

Bot Telegram untuk meneruskan kode login OTP ke chat yang ditentukan.

---

## Quick Start (PC Baru)

### 1. Salin folder ini ke PC/laptop tujuan

### 2. Jalankan setup (sekali saja)

```powershell
powershell -ExecutionPolicy Bypass -File setup.ps1
```

Script ini otomatis:
- Download & install Python jika belum ada
- Buat virtual environment
- Install semua dependencies

### 3. Salin file dari PC utama (jika laptop baru)

```
.env                         → konfigurasi bot token
accounts.json                → daftar semua akun OTP
telegram_session\*.session   → session files Telethon
```

### 4. Login akun (jika belum ada file .session)

```powershell
.\.venv\Scripts\python.exe telegram_otp_allinone.py login-all
```

> Stop proses `listen` dulu sebelum menjalankan login-all.

### 5. Jalankan bot

```powershell
powershell -ExecutionPolicy Bypass -File run_local.ps1
```

Otomatis membuka 2 jendela: **bot** + **listener**.

---

## Perintah Bot di Telegram

| Perintah | Fungsi |
|----------|--------|
| `/start` | Mulai bot |
| `/ping` | Cek bot aktif |
| `/accounts` | Lihat semua brand |
| `/accounts STMY` | Detail akun per brand |
| `/login STMY_LINA` | Request kode OTP |

---

## File Penting

| File | Keterangan |
|------|------------|
| `.env` | Token bot + konfigurasi (wajib) |
| `accounts.json` | Daftar brand & akun OTP |
| `telegram_session/` | Session files Telethon |
| `state.json` | Antrian request OTP (otomatis, jangan edit) |

---

## .env (minimal)

```
TELEGRAM_BOT_TOKEN=token_dari_BotFather
TELEGRAM_ACCOUNT=geri_work
TELEGRAM_LOGIN_STATUS_CHAT_ID=your_chat_id
```

Variabel opsional lainnya lihat `.env.example`.

---

## Script PowerShell

| Script | Fungsi |
|--------|--------|
| `setup.ps1` | Setup pertama kali (Python, venv, dependencies) |
| `run_local.ps1` | Jalankan bot + listener (2 jendela) |
| `run_multi_local.ps1` | Setup + run (all-in-one) |

---

## Troubleshooting

| Masalah | Solusi |
|---------|--------|
| OTP tidak muncul | Pastikan `listen` jalan & sudah `/login` dulu |
| `409 Conflict` | Hanya 1 proses `bot` per token, tutup duplikat |
| `database is locked` | Stop `listen` dulu, lalu jalankan `login-all` |
| Bot tidak merespon | Cek `.env` → `TELEGRAM_BOT_TOKEN` benar |
