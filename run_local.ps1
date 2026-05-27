# ============================================================
# RUN_LOCAL.PS1 — Production: bot + listener (2 jendela)
# Notifikasi → forum topic System Status | Sheet = event only
# ============================================================
$ErrorActionPreference = "Stop"
$root = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
Set-Location $root

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Telegram OTP Bot - Run Local" -ForegroundColor Cyan
Write-Host "  (Production)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# --- Cek .env ---
$envPath = Join-Path $root ".env"
if (-not (Test-Path $envPath)) {
    Write-Error "File .env tidak ada. Jalankan setup.ps1 dulu, atau salin dari PC utama."
    exit 1
}

# --- Cek file wajib ---
$required = @(
    @{ Path = "accounts.json"; Label = "accounts.json" },
    @{ Path = "shooteraccounts.json"; Label = "shooteraccounts.json" }
)
foreach ($f in $required) {
    $p = Join-Path $root $f.Path
    if (-not (Test-Path $p)) {
        Write-Error "$($f.Label) tidak ada. Salin dari PC utama."
        exit 1
    }
}

# --- Google Sheets credentials (opsional tapi disarankan) ---
$hasGoogleCreds = $false
$envContent = Get-Content $envPath -Raw -ErrorAction SilentlyContinue
if ($envContent -match 'GOOGLE_SHEETS_CREDENTIALS\s*=\s*(\S+)') {
    $credName = $Matches[1].Trim()
    $credPath = Join-Path $root $credName
    if (Test-Path $credPath) { $hasGoogleCreds = $true }
}
if (-not $hasGoogleCreds) {
    $jsonCreds = Get-ChildItem $root -Filter "tg-otp-automation-*.json" -File -ErrorAction SilentlyContinue
    if ($jsonCreds) { $hasGoogleCreds = $true }
}
if (-not $hasGoogleCreds) {
    Write-Host "[!] Google Sheets credentials tidak ditemukan." -ForegroundColor Yellow
    Write-Host "    Sheet sync / instant push tidak akan jalan." -ForegroundColor Yellow
}

# --- Info notifikasi dari .env ---
if ($envContent -match 'TELEGRAM_LOGIN_STATUS_CHAT_ID\s*=\s*(-?\d+)') {
    Write-Host "Notifikasi sistem → topic chat_id $($Matches[1])" -ForegroundColor Green
}
if ($envContent -match 'TELEGRAM_LOGIN_STATUS_THREAD_ID\s*=\s*(\d+)') {
    Write-Host "  thread_id $($Matches[1]) (System Status)" -ForegroundColor Green
}
if ($envContent -match 'TELEGRAM_STATUS_PREVIEW_ONLY\s*=\s*1') {
    Write-Host "[!] PREVIEW_ONLY=1 → notifikasi hanya ke DM, belum ke topic." -ForegroundColor Yellow
    Write-Host "    Production: comment TELEGRAM_STATUS_PREVIEW_* di .env" -ForegroundColor Yellow
}

# --- Auto-repair venv + dependencies (path Python dari PC lain = rebuild) ---
$helpers = Join-Path $root "_venv_helpers.ps1"
if (-not (Test-Path -LiteralPath $helpers)) {
    Write-Error "_venv_helpers.ps1 tidak ada. Jalankan setup.ps1 atau salin ulang folder proyek."
    exit 1
}
. $helpers
try {
    $venvInfo = Ensure-ProjectVenv -ProjectRoot $root
    $venvPy = $venvInfo.Python
    $needInstall = $venvInfo.Created
    if (-not $needInstall) {
        $importOk = $true
        try {
            $null = & $venvPy -c "import telegram, telethon, filelock; from dotenv import load_dotenv" 2>&1
            if ($LASTEXITCODE -ne 0) { $importOk = $false }
        } catch { $importOk = $false }
        if (-not $importOk) { $needInstall = $true }
    }
    if ($needInstall) {
        Write-Host "[!] Menginstall dependencies..." -ForegroundColor Yellow
        Install-ProjectRequirements -ProjectRoot $root
        Write-Host "    Dependencies OK." -ForegroundColor Green
    }
} catch {
    Write-Error $_.Exception.Message
    Write-Host "Coba: powershell -ExecutionPolicy Bypass -File .\setup.ps1" -ForegroundColor Yellow
    exit 1
}

# --- Cek session files ---
$sessionDir = Join-Path $root "telegram_session"
if (-not (Test-Path $sessionDir)) {
    New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null
}
$sessionCount = (Get-ChildItem $sessionDir -Filter "*.session" -Recurse -File -ErrorAction SilentlyContinue).Count
if ($sessionCount -eq 0) {
    Write-Host ""
    Write-Host "[!] Tidak ada file .session di telegram_session\" -ForegroundColor Red
    Write-Host "    Opsi 1: Salin *.session dari PC utama" -ForegroundColor Yellow
    Write-Host "    Opsi 2: Login:" -ForegroundColor Yellow
    Write-Host "    .\.venv\Scripts\python.exe telegram_otp_allinone.py login-all" -ForegroundColor White
    Write-Host "    .\.venv\Scripts\python.exe telegram_otp_allinone.py login-all-shooter" -ForegroundColor White
    Write-Host ""
    Read-Host "Tekan Enter setelah file session tersedia, atau Ctrl+C untuk batal"
}

# --- Jalankan bot + listen (2 jendela) ---
Write-Host ""
Write-Host "Memulai bot + listener..." -ForegroundColor Green

$py = $venvPy
$script = Join-Path $root "telegram_otp_allinone.py"

$argBot = @(
    "-NoExit"
    "-NoLogo"
    "-Command"
    "Set-Location -LiteralPath '$root'; Write-Host 'BOT (production)' -ForegroundColor Green; & '$py' '$script' bot"
)
$argListen = @(
    "-NoExit"
    "-NoLogo"
    "-Command"
    "Set-Location -LiteralPath '$root'; Write-Host 'LISTENER (Sheet+topic on events)' -ForegroundColor Green; & '$py' '$script' listen"
)

Start-Process powershell -WorkingDirectory $root -ArgumentList $argBot
Start-Sleep -Seconds 2
Start-Process powershell -WorkingDirectory $root -ArgumentList $argListen

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  2 jendela terbuka:" -ForegroundColor Green
Write-Host "    1 = BOT     (/login, /accounts, /shooter)" -ForegroundColor White
Write-Host "    2 = LISTEN  (OTP + status Banned/Frozen/...)" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Google Sheet:" -ForegroundColor Yellow
Write-Host "  - listen TIDAK overwrite semua baris" -ForegroundColor White
Write-Host "  - Hanya update Account Status / Session Friday saat masalah terdeteksi" -ForegroundColor White
Write-Host ""
Write-Host "Sync (manual, jendela terpisah):" -ForegroundColor Yellow
Write-Host "  .\.venv\Scripts\python.exe telegram_otp_allinone.py sync" -ForegroundColor White
Write-Host "  JANGAN pakai: sync loop" -ForegroundColor Red
Write-Host ""
Write-Host "Uji: /ping ke bot. Tutup jendela untuk stop." -ForegroundColor Yellow
Write-Host ""
