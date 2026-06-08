# ============================================================
# START_PRODUCTION.PS1 - Stop old processes, open 5 PowerShell windows
# BOT + LISTEN + LIVE-PULL + LIVE-LOGIN + LIVE-STATUS (not Cursor terminal)
# Run: powershell -ExecutionPolicy Bypass -File .\start_production.ps1
# ============================================================
$ErrorActionPreference = "Stop"
$root = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
Set-Location $root

. (Join-Path $root "setup.ps1")

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Telegram OTP - Start Production" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# --- Required files ---
if (-not (Test-Path (Join-Path $root ".env"))) {
    Write-Error ".env not found. Run setup.ps1 first."
    exit 1
}
foreach ($f in @("accounts.json", "shooteraccounts.json")) {
    if (-not (Test-Path (Join-Path $root $f))) {
        Write-Error "$f not found. Copy from your main PC."
        exit 1
    }
}

# --- Stop old OTP processes (bot/listen/live pull/live-status in this folder only) ---
Write-Host "[1/4] Stopping old OTP processes..." -ForegroundColor Yellow
$stopped = Stop-OtpProductionProcesses -ProjectRoot $root
if ($stopped -gt 0) {
    Write-Host "       Stopped: $stopped root process(es)." -ForegroundColor Green
    Start-Sleep -Seconds 2
} else {
    Write-Host "       No OTP processes were running." -ForegroundColor Green
}

# --- Venv ---
Write-Host ""
Write-Host "[2/4] Checking virtual environment..." -ForegroundColor Yellow
try {
    $venvInfo = Ensure-ProjectVenv -ProjectRoot $root
    $py = $venvInfo.Python
    if ($venvInfo.Created) {
        Install-ProjectRequirements -ProjectRoot $root
    } else {
        $importOk = $true
        try {
            $null = & $py -c 'import telegram, telethon, filelock; from dotenv import load_dotenv' 2>&1
            if ($LASTEXITCODE -ne 0) { $importOk = $false }
        } catch { $importOk = $false }
        if (-not $importOk) {
            Write-Host "       Installing dependencies..." -ForegroundColor Yellow
            Install-ProjectRequirements -ProjectRoot $root
        }
    }
    Write-Host "       venv OK" -ForegroundColor Green
} catch {
    Write-Error $_.Exception.Message
    Write-Host "Try: powershell -ExecutionPolicy Bypass -File .\setup.ps1" -ForegroundColor Yellow
    exit 1
}

# --- Session ---
Write-Host ""
Write-Host "[3/4] Checking session files..." -ForegroundColor Yellow
$sessionDir = Join-Path $root "telegram_session"
if (-not (Test-Path $sessionDir)) {
    New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null
}
$sessionCount = (Get-ChildItem $sessionDir -Filter "*.session" -Recurse -File -ErrorAction SilentlyContinue).Count
Write-Host "       $sessionCount .session file(s) found." -ForegroundColor $(if ($sessionCount -gt 0) { "Green" } else { "Yellow" })
if ($sessionCount -eq 0) {
    Write-Host "       [!] No sessions yet. Run login before production." -ForegroundColor Red
    Write-Host "       .\.venv\Scripts\python.exe telegram_otp_allinone.py login-all" -ForegroundColor White
    $ans = Read-Host "       Continue starting production without sessions? (y/N)"
    if ($ans -notmatch '^[yY]') { exit 0 }
}

# --- Open 4 external PowerShell windows ---
Write-Host ""
Write-Host "[4/4] Opening 5 PowerShell windows (BOT, LISTEN, LIVE-PULL, LIVE-LOGIN, LIVE-STATUS)..." -ForegroundColor Yellow

$script = Join-Path $root "telegram_otp_allinone.py"

function Start-OtpServiceWindow {
    param(
        [string]$WindowTitle,
        [string[]]$PythonArgs
    )
    $pyQ = $py.Replace("'", "''")
    $scriptQ = $script.Replace("'", "''")
    $argStr = ($PythonArgs | ForEach-Object { "'$_'" }) -join ', '
    $cmd = @"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
`$OutputEncoding = [System.Text.Encoding]::UTF8
Set-Location -LiteralPath '$($root.Replace("'", "''"))'
`$Host.UI.RawUI.WindowTitle = '$WindowTitle'
Write-Host '$WindowTitle' -ForegroundColor Green
& '$pyQ' '$scriptQ' $argStr
"@
    Start-Process powershell.exe -WorkingDirectory $root -ArgumentList @(
        "-NoExit",
        "-NoLogo",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        $cmd
    ) | Out-Null
}

Start-OtpServiceWindow -WindowTitle "OTP - BOT" -PythonArgs @("bot")
Start-Sleep -Seconds 2
Start-OtpServiceWindow -WindowTitle "OTP - LISTEN" -PythonArgs @("listen")
Start-Sleep -Seconds 2
Start-OtpServiceWindow -WindowTitle "OTP - LIVE-PULL" -PythonArgs @("sync", "live")
Start-Sleep -Seconds 2
Start-OtpServiceWindow -WindowTitle "OTP - LIVE-LOGIN" -PythonArgs @("sync", "live-login")
Start-Sleep -Seconds 2
Start-OtpServiceWindow -WindowTitle "OTP - LIVE-STATUS" -PythonArgs @("sync", "live-status")

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Production running (5 separate windows)" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  1 = BOT          (/login, /main, /other, /ping)" -ForegroundColor White
Write-Host "  2 = LISTEN       (OTP + status to Sheet)" -ForegroundColor White
Write-Host "  3 = LIVE-PULL    (Sheet -> JSON, auto register)" -ForegroundColor White
Write-Host "  4 = LIVE-LOGIN   (Sheet OTP column -> .session)" -ForegroundColor White
Write-Host "  5 = LIVE-STATUS  (queue + health-check every 12h -> Sheet)" -ForegroundColor White
Write-Host ""
Write-Host "  Close a PowerShell window to stop that service." -ForegroundColor Yellow
Write-Host "  Do NOT run this script again while all 5 windows are open." -ForegroundColor Red
Write-Host "  Do NOT start the bot from Cursor terminal (avoids 409 Conflict)." -ForegroundColor Red
Write-Host ""
