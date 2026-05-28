# Telegram BOT OTP

Bot Telegram untuk meneruskan kode login OTP ke chat yang ditentukan.

---

## Quick Start (PC Baru)

### 1. Salin folder proyek ke PC/laptop tujuan

### 2. Jalankan setup (sekali saja)

```powershell
powershell -ExecutionPolicy Bypass -File setup.ps1
```

### 3. Salin file sensitif secara manual (jangan lewat Git)

```
.env                              → token bot + konfigurasi
accounts.json                     → daftar akun GCS
shooteraccounts.json              → daftar akun shooter
tg-otp-automation-*.json          → kredensial Google Sheet
telegram_session\*.session        → session Telethon (buat di mesin ini)
```

> **Penting:** `telegram_session/` **tidak** boleh di-commit atau di-sync antar Mac/Windows lewat Git. Satu session hanya untuk **satu mesin** yang menjalankan `listen`.

### 4. Login akun (jika belum ada file `.session`)

```powershell
.\.venv\Scripts\python.exe telegram_otp_allinone.py login-all
.\.venv\Scripts\python.exe telegram_otp_allinone.py login-all-shooter
```

Stop proses `listen` dulu sebelum `login-all`.

### 5. Jalankan bot (production)

```powershell
powershell -ExecutionPolicy Bypass -File run_local.ps1
```

Atau 3 layanan sekaligus (bot + listen + live-status):

```powershell
powershell -ExecutionPolicy Bypass -File run_local_3.ps1
```

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
| `.env` | Token bot + konfigurasi (lokal, tidak di Git) |
| `accounts.json` | Daftar brand & akun OTP GCS |
| `shooteraccounts.json` | Daftar akun shooter |
| `telegram_session/` | Session Telethon (lokal per mesin) |
| `state.json` | Antrian request OTP (otomatis) |
| `sheet_status_queue.jsonl` | Antrian push status ke Sheet |

---

## Script PowerShell

| Script | Fungsi |
|--------|--------|
| `setup.ps1` | Setup pertama kali (Python, venv, dependencies) |
| `run_local.ps1` | Bot + listener (2 jendela) |
| `run_local_3.ps1` | Bot + listener + live-status (3 jendela) |
| `run_sync.ps1` | Sync manual ke Google Sheet |

---

## Troubleshooting

| Masalah | Solusi |
|---------|--------|
| OTP tidak muncul | Pastikan `listen` jalan & sudah `/login` |
| `409 Conflict` | Hanya 1 proses `bot` per token; revoke token lama di BotFather |
| `AuthKeyDuplicatedError` | Session dipakai di 2 mesin/IP; hapus `.session`, login ulang, `listen` di 1 mesin saja |
| `database is locked` | Stop `listen`, lalu `login-all` |
| Bot tidak merespon | Cek `TELEGRAM_BOT_TOKEN` di `.env` |

---

## Keamanan Git

Jangan commit: `.env`, `telegram_session/`, `tg-otp-automation-*.json`, file `*.lock`, `state.json`, antrian `sheet_status_queue.jsonl`.

Variabel opsional lainnya: lihat `.env.example`.
