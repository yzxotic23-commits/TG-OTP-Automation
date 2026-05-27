# ============================================================
# RUN_SYNC.PS1 — Sync Sheet sekali (import + login baru)
# Tidak jalan loop — aman untuk production
# ============================================================
$ErrorActionPreference = "Stop"
$root = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
Set-Location $root

$venvPy = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    Write-Error ".venv tidak ada. Jalankan setup.ps1 atau run_local.ps1 dulu."
    exit 1
}

$script = Join-Path $root "telegram_otp_allinone.py"
$step = $args[0]

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Telegram OTP - Sync (once)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($step) {
    Write-Host "Menjalankan: sync $step" -ForegroundColor Yellow
    & $venvPy $script sync $step
} else {
    Write-Host "Menjalankan: sync (import Sheet -> login baru -> import ulang)" -ForegroundColor Yellow
    & $venvPy $script sync
}

Write-Host ""
Write-Host "Selesai. Untuk audit semua akun: .\run_sync.ps1 health" -ForegroundColor Yellow
Write-Host "JANGAN jalankan: sync loop" -ForegroundColor Red
Write-Host ""
