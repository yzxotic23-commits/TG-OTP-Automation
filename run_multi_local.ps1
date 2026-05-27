# ============================================================
# RUN_MULTI_LOCAL.PS1 — Setup + Run (all-in-one)
# Untuk laptop baru: auto venv, install, lalu jalankan
# ============================================================
$ErrorActionPreference = "Stop"
$root = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
Set-Location $root

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Telegram OTP Bot - Setup & Run" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# --- 1. Cek Python ---
Write-Host "[1/4] Mengecek Python..." -ForegroundColor Yellow
$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python\s+3\.(\d+)") {
            $minor = [int]$Matches[1]
            if ($minor -ge 10) {
                $pythonCmd = $cmd
                Write-Host "       $ver" -ForegroundColor Green
                break
            }
        }
    } catch {}
}

if (-not $pythonCmd) {
    Write-Host "       Python 3.10+ tidak ditemukan!" -ForegroundColor Red
    Write-Host "       Jalankan setup.ps1 untuk auto-download, atau install manual dari https://python.org" -ForegroundColor Yellow
    exit 1
}

# --- 2. Buat / perbaiki venv + install ---
Write-Host "[2/4] Virtual environment & dependencies..." -ForegroundColor Yellow
. (Join-Path $root "_venv_helpers.ps1")
try {
    $venvInfo = Ensure-ProjectVenv -ProjectRoot $root
    $venvPy = $venvInfo.Python
    Install-ProjectRequirements -ProjectRoot $root
    Write-Host "       Dependencies OK." -ForegroundColor Green
} catch {
    Write-Host "       $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# --- 3. Cek konfigurasi ---
Write-Host "[3/4] Cek konfigurasi..." -ForegroundColor Yellow
$ok = $true

if (-not (Test-Path (Join-Path $root ".env"))) {
    Write-Host "       .env TIDAK ADA - salin dari PC utama!" -ForegroundColor Red
    $ok = $false
} else {
    Write-Host "       .env OK" -ForegroundColor Green
}

if (-not (Test-Path (Join-Path $root "accounts.json"))) {
    Write-Host "       accounts.json TIDAK ADA - salin dari PC utama!" -ForegroundColor Red
    $ok = $false
} else {
    Write-Host "       accounts.json OK" -ForegroundColor Green
}

if (-not (Test-Path (Join-Path $root "shooteraccounts.json"))) {
    Write-Host "       shooteraccounts.json TIDAK ADA - salin dari PC utama!" -ForegroundColor Red
    $ok = $false
} else {
    Write-Host "       shooteraccounts.json OK" -ForegroundColor Green
}

$envPath = Join-Path $root ".env"
if (Test-Path $envPath) {
    $ec = Get-Content $envPath -Raw
    if ($ec -match 'TELEGRAM_LOGIN_STATUS_CHAT_ID\s*=\s*-?\d+' -and $ec -match 'TELEGRAM_LOGIN_STATUS_THREAD_ID\s*=\s*\d+') {
        Write-Host "       System Status topic .env OK" -ForegroundColor Green
    } else {
        Write-Host "       [!] Set TELEGRAM_LOGIN_STATUS_CHAT_ID + THREAD_ID di .env" -ForegroundColor Yellow
    }
    if ($ec -match 'TELEGRAM_STATUS_PREVIEW_ONLY\s*=\s*1') {
        Write-Host "       [!] PREVIEW_ONLY=1 (DM only) - set 0 untuk production topic" -ForegroundColor Yellow
    }
}

$sessionDir = Join-Path $root "telegram_session"
if (-not (Test-Path $sessionDir)) {
    New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null
}
$sessionCount = (Get-ChildItem $sessionDir -Filter "*.session" -File -ErrorAction SilentlyContinue).Count
if ($sessionCount -eq 0) {
    Write-Host "       telegram_session/ KOSONG" -ForegroundColor Red
    Write-Host "       Salin *.session dari PC utama, atau jalankan login-all:" -ForegroundColor Yellow
    Write-Host "       .\.venv\Scripts\python.exe telegram_otp_allinone.py login-all" -ForegroundColor White
    $ok = $false
} else {
    Write-Host "       telegram_session/ OK ($sessionCount files)" -ForegroundColor Green
}

if (-not $ok) {
    Write-Host ""
    Write-Host "Setup selesai tapi ada file yang kurang. Lengkapi dulu lalu jalankan run_local.ps1" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Tekan Enter untuk keluar"
    exit 0
}

# --- 4. Jalankan ---
Write-Host "[4/4] Memulai bot + listener..." -ForegroundColor Yellow
Write-Host ""
& (Join-Path $root "run_local.ps1")
