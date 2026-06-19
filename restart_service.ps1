# Restart ONE production service (without touching the other 4 windows).
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\restart_service.ps1 listen
#   powershell -ExecutionPolicy Bypass -File .\restart_service.ps1 bot
#   powershell -ExecutionPolicy Bypass -File .\restart_service.ps1 live-pull
#   powershell -ExecutionPolicy Bypass -File .\restart_service.ps1 live-login
#   powershell -ExecutionPolicy Bypass -File .\restart_service.ps1 live-status
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("bot", "listen", "live-pull", "live-login", "live-status")]
    [string]$Service
)

$ErrorActionPreference = "Stop"
$root = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
Set-Location $root

. (Join-Path $root "setup.ps1")

$serviceMap = @{
    "bot"         = @{ Title = "OTP - BOT";         Args = @("bot") }
    "listen"      = @{ Title = "OTP - LISTEN";      Args = @("listen") }
    "live-pull"   = @{ Title = "OTP - LIVE-PULL";   Args = @("sync", "live") }
    "live-login"  = @{ Title = "OTP - LIVE-LOGIN";  Args = @("sync", "live-login") }
    "live-status" = @{ Title = "OTP - LIVE-STATUS"; Args = @("sync", "live-status") }
}

$cmdTail = switch ($Service) {
    "bot"         { "bot$" }
    "listen"      { "listen$" }
    "live-pull"   { "sync live$" }
    "live-login"  { "sync live-login$" }
    "live-status" { "sync live-status$" }
}

$rootEsc = [regex]::Escape($root)
$pattern = "$rootEsc.*telegram_otp_allinone\.py $cmdTail"

Write-Host ""
Write-Host "Restart service: $Service" -ForegroundColor Cyan

$procs = Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match $pattern }

$pids = @($procs | ForEach-Object { $_.ProcessId } | Sort-Object -Unique)
foreach ($procId in $pids) {
    Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
}

if ($Service -eq "bot") {
    Remove-Item -LiteralPath (Join-Path $root ".bot_polling.lock") -Force -ErrorAction SilentlyContinue
}

if ($pids.Count -gt 0) {
    Write-Host "  Stopped PID: $($pids -join ', ')" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
} else {
    Write-Host "  No running process for $Service (starting fresh)." -ForegroundColor Green
}

$venvInfo = Ensure-ProjectVenv -ProjectRoot $root
$py = $venvInfo.Python
$script = Join-Path $root "telegram_otp_allinone.py"
$info = $serviceMap[$Service]

$pyQ = $py.Replace("'", "''")
$scriptQ = $script.Replace("'", "''")
$argStr = ($info.Args | ForEach-Object { "'$_'" }) -join ', '
$title = $info.Title

$cmd = @"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
`$OutputEncoding = [System.Text.Encoding]::UTF8
Set-Location -LiteralPath '$($root.Replace("'", "''"))'
`$Host.UI.RawUI.WindowTitle = '$title'
Write-Host '$title' -ForegroundColor Green
& '$pyQ' '$scriptQ' $argStr
"@

Start-Process powershell.exe -WorkingDirectory $root -ArgumentList @(
    "-NoExit",
    "-NoLogo",
    "-ExecutionPolicy", "Bypass",
    "-Command",
    $cmd
) | Out-Null

Write-Host "  Opened new window: $title" -ForegroundColor Green
Write-Host ""
