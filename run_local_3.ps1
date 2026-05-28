# ============================================================
# RUN_LOCAL_3.PS1 — BOT + LISTEN + LIVE-STATUS (3 jendela)
# ============================================================
$ErrorActionPreference = "Stop"
$root = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
Set-Location $root

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Telegram OTP Bot - Run 3 Services" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1) Jalankan flow standar (akan buka BOT + LISTEN)
& (Join-Path $root "run_local.ps1")

# 2) Siapkan venv untuk service ke-3
$helpers = Join-Path $root "_venv_helpers.ps1"
if (-not (Test-Path -LiteralPath $helpers)) {
    Write-Host "[!] _venv_helpers.ps1 tidak ditemukan. skip live-status." -ForegroundColor Yellow
    exit 0
}
. $helpers

try {
    $venvInfo = Ensure-ProjectVenv -ProjectRoot $root
    $py = $venvInfo.Python
} catch {
    Write-Host "[!] Gagal siapkan venv untuk live-status: $($_.Exception.Message)" -ForegroundColor Yellow
    exit 0
}

$script = Join-Path $root "telegram_otp_allinone.py"
$argLive = @(
    "-NoExit"
    "-NoLogo"
    "-Command"
    "Set-Location -LiteralPath '$root'; Write-Host 'LIVE-STATUS (delta sync)' -ForegroundColor Green; & '$py' '$script' sync live-status"
)

Start-Sleep -Seconds 2
Start-Process powershell -WorkingDirectory $root -ArgumentList $argLive

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  3 jendela terbuka:" -ForegroundColor Green
Write-Host "    1 = BOT" -ForegroundColor White
Write-Host "    2 = LISTEN" -ForegroundColor White
Write-Host "    3 = LIVE-STATUS (delta)" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
