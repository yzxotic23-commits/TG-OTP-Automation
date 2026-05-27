# ============================================================
# SETUP.PS1 — Full auto-setup untuk laptop/server baru
# Jalankan sekali: klik kanan > Run with PowerShell
# atau: powershell -ExecutionPolicy Bypass -File setup.ps1
# ============================================================
$ErrorActionPreference = "Stop"
$root = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
Set-Location $root

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Telegram OTP Bot - Auto Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# --- 1. Cek Python ---
Write-Host "[1/5] Mengecek Python..." -ForegroundColor Yellow
$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python\s+3\.(\d+)") {
            $minor = [int]$Matches[1]
            if ($minor -ge 10) {
                $pythonCmd = $cmd
                Write-Host "       OK: $ver ($cmd)" -ForegroundColor Green
                break
            }
        }
    } catch {}
}

if (-not $pythonCmd) {
    Write-Host "       Python 3.10+ tidak ditemukan. Mendownload installer..." -ForegroundColor Red
    $pyUrl = "https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe"
    $pyInstaller = Join-Path $env:TEMP "python-3.12.7-amd64.exe"

    Write-Host "       Downloading Python 3.12.7..." -ForegroundColor Yellow
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $pyUrl -OutFile $pyInstaller -UseBasicParsing

    Write-Host "       Installing Python (silent, add to PATH)..." -ForegroundColor Yellow
    Start-Process -FilePath $pyInstaller -ArgumentList "/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_pip=1" -Wait

    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "User") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "Machine")

    $pythonCmd = "python"
    try {
        $ver = & $pythonCmd --version 2>&1
        Write-Host "       Installed: $ver" -ForegroundColor Green
    } catch {
        Write-Error "Python installasi gagal. Install manual dari https://python.org lalu jalankan ulang setup.ps1"
        exit 1
    }
}

# --- 2. Buat / perbaiki Virtual Environment ---
Write-Host ""
Write-Host "[2/5] Membuat virtual environment..." -ForegroundColor Yellow
. (Join-Path $root "_venv_helpers.ps1")
try {
    $venvInfo = Ensure-ProjectVenv -ProjectRoot $root
    $venvPy = $venvInfo.Python
    if ($venvInfo.Created) {
        Write-Host "       .venv dibuat / diperbaiki." -ForegroundColor Green
    } else {
        Write-Host "       .venv sudah ada dan sehat." -ForegroundColor Green
    }
} catch {
    Write-Error $_.Exception.Message
    exit 1
}

# --- 3. Install dependencies ---
Write-Host ""
Write-Host "[3/5] Menginstall dependencies..." -ForegroundColor Yellow
$reqFile = Join-Path $root "requirements.txt"
if (-not (Test-Path $reqFile)) {
    Write-Error "requirements.txt tidak ditemukan di $root"
    exit 1
}
Install-ProjectRequirements -ProjectRoot $root
Write-Host "       Dependencies terinstall." -ForegroundColor Green

# --- 4. Cek file konfigurasi ---
Write-Host ""
Write-Host "[4/5] Mengecek file konfigurasi..." -ForegroundColor Yellow

$envFile = Join-Path $root ".env"
if (Test-Path $envFile) {
    Write-Host "       .env OK" -ForegroundColor Green
} else {
    $envExample = Join-Path $root ".env.example"
    if (Test-Path $envExample) {
        Copy-Item $envExample $envFile
        Write-Host "       .env dibuat dari .env.example" -ForegroundColor Yellow
        Write-Host "       PENTING: Edit .env dan isi TELEGRAM_BOT_TOKEN!" -ForegroundColor Red
    } else {
        Write-Host "       .env tidak ada. Buat manual dengan isi:" -ForegroundColor Red
        Write-Host "         TELEGRAM_BOT_TOKEN=token_dari_BotFather" -ForegroundColor White
        Write-Host "         TELEGRAM_ACCOUNT=geri_work" -ForegroundColor White
    }
}

$accFile = Join-Path $root "accounts.json"
if (Test-Path $accFile) {
    Write-Host "       accounts.json OK" -ForegroundColor Green
} else {
    Write-Host "       accounts.json tidak ditemukan!" -ForegroundColor Red
    Write-Host "       Salin dari PC utama ke folder ini." -ForegroundColor Red
}

$sessionDir = Join-Path $root "telegram_session"
if (Test-Path $sessionDir) {
    $count = (Get-ChildItem $sessionDir -Filter "*.session" -File).Count
    Write-Host "       telegram_session/ OK ($count session files)" -ForegroundColor Green
} else {
    New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null
    Write-Host "       telegram_session/ dibuat (kosong, perlu login-all)" -ForegroundColor Yellow
}

# --- 5. Instruksi selanjutnya ---
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Setup selesai!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "File yang harus disalin dari PC utama (jika laptop baru):" -ForegroundColor White
Write-Host "  - .env (production: topic System Status, preview OFF)" -ForegroundColor White
Write-Host "  - accounts.json + shooteraccounts.json" -ForegroundColor White
Write-Host "  - tg-otp-automation-*.json (Google Sheets)" -ForegroundColor White
Write-Host "  - telegram_session\**\*.session (semua session GCS + shooter)" -ForegroundColor White
Write-Host ""
Write-Host "Production .env (notifikasi ke topic, bukan DM):" -ForegroundColor Yellow
Write-Host "  TELEGRAM_LOGIN_STATUS_CHAT_ID=-1003994531684" -ForegroundColor White
Write-Host "  TELEGRAM_LOGIN_STATUS_THREAD_ID=1322" -ForegroundColor White
Write-Host "  TELEGRAM_SYNC_INSTANT_PUSH=1" -ForegroundColor White
Write-Host "  # TELEGRAM_STATUS_PREVIEW_*  (dikomentari)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Langkah selanjutnya:" -ForegroundColor Yellow
Write-Host "  1. Jika BELUM ada file .session:" -ForegroundColor White
Write-Host "     .\.venv\Scripts\python.exe telegram_otp_allinone.py login-all" -ForegroundColor White
Write-Host "     .\.venv\Scripts\python.exe telegram_otp_allinone.py login-all-shooter" -ForegroundColor White
Write-Host ""
Write-Host "  2. Jalankan bot + listener (production):" -ForegroundColor White
Write-Host "     .\run_local.ps1" -ForegroundColor White
Write-Host ""
Write-Host "  3. Sync Sheet (hanya saat perlu, sekali jalan):" -ForegroundColor White
Write-Host "     .\run_sync.ps1" -ForegroundColor White
Write-Host "     .\run_sync.ps1 health   (audit manual)" -ForegroundColor White
Write-Host ""
Write-Host "  JANGAN: sync loop (overwrite / limit API)" -ForegroundColor Red
Write-Host ""

Read-Host "Tekan Enter untuk keluar"
