# ============================================================
# SETUP.PS1 — Full auto-setup + shared venv helpers
# Run: powershell -ExecutionPolicy Bypass -File setup.ps1
# Can be dot-sourced from start_production.ps1 (loads functions only)
# ============================================================

$script:PythonMinMinor = 10

function Get-SystemPythonExe {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($tag in @("3.12", "3.11", "3.10", "3.14", "3.13")) {
            try {
                $exe = (& py "-$tag" -c "import sys; print(sys.executable)" 2>$null | Out-String).Trim()
                if ($exe -and (Test-Path -LiteralPath $exe)) {
                    $ver = & $exe --version 2>&1 | Out-String
                    if ($ver -match "Python\s+3\.(\d+)") {
                        $minor = [int]$Matches[1]
                        if ($minor -ge $script:PythonMinMinor) { return $exe }
                    }
                }
            } catch {}
        }
    }
    foreach ($cmd in @("python", "python3")) {
        $found = Get-Command $cmd -ErrorAction SilentlyContinue
        if (-not $found) { continue }
        if ($found.Source -match "WindowsApps") { continue }
        $ver = & $found.Source --version 2>&1 | Out-String
        if ($ver -match "Python\s+3\.(\d+)") {
            $minor = [int]$Matches[1]
            if ($minor -ge $script:PythonMinMinor) { return $found.Source }
        }
    }
    return $null
}

function Test-ProjectVenvBroken {
    param(
        [string]$ProjectRoot,
        [string]$VenvPython = $(Join-Path $ProjectRoot ".venv\Scripts\python.exe")
    )
    if (-not (Test-Path -LiteralPath $VenvPython)) { return $true }
    try {
        $null = & $VenvPython --version 2>&1
        if ($LASTEXITCODE -ne 0) { return $true }
    } catch {
        return $true
    }
    $cfgPath = Join-Path $ProjectRoot ".venv\pyvenv.cfg"
    if (-not (Test-Path -LiteralPath $cfgPath)) { return $false }
    foreach ($line in Get-Content -LiteralPath $cfgPath) {
        if ($line -match '^\s*home\s*=\s*(.+)$') {
            $pyHome = $Matches[1].Trim()
            if (-not (Test-Path -LiteralPath (Join-Path $pyHome "python.exe"))) { return $true }
        }
        if ($line -match '^\s*executable\s*=\s*(.+)$') {
            $exe = $Matches[1].Trim()
            if ($exe -and -not (Test-Path -LiteralPath $exe)) { return $true }
        }
    }
    return $false
}

function Ensure-ProjectVenv {
    param(
        [string]$ProjectRoot,
        [switch]$ForceRecreate
    )
    $venvPy = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    $broken = Test-ProjectVenvBroken -ProjectRoot $ProjectRoot -VenvPython $venvPy
    if ($ForceRecreate -or $broken) {
        if ($broken -and (Test-Path -LiteralPath (Join-Path $ProjectRoot ".venv"))) {
            Write-Host "[!] .venv broken / from another PC — recreating..." -ForegroundColor Yellow
            Remove-Item -LiteralPath (Join-Path $ProjectRoot ".venv") -Recurse -Force -ErrorAction SilentlyContinue
        }
        $pythonExe = Get-SystemPythonExe
        if (-not $pythonExe) {
            throw "Python 3.$($script:PythonMinMinor)+ not found. Run setup.ps1 first."
        }
        & $pythonExe -m venv (Join-Path $ProjectRoot ".venv")
        if (-not (Test-Path -LiteralPath $venvPy)) {
            throw "Failed to create .venv with $pythonExe"
        }
        Write-Host "    .venv OK ($pythonExe)" -ForegroundColor Green
        return @{ Python = $venvPy; Created = $true }
    }
    return @{ Python = $venvPy; Created = $false }
}

function Install-ProjectRequirements {
    param([string]$ProjectRoot)
    $venvPy = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    $req = Join-Path $ProjectRoot "requirements.txt"
    if (-not (Test-Path -LiteralPath $req)) { throw "requirements.txt not found." }
    & $venvPy -m pip install -U pip wheel -q 2>&1 | Out-Null
    & $venvPy -m pip install -r $req -q
    $check = "import telegram, telethon, filelock; from dotenv import load_dotenv"
    & $venvPy -c $check 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Module verification failed after pip install."
    }
}

function Stop-OtpProductionProcesses {
    param([string]$ProjectRoot)
    $pattern = [regex]::Escape($ProjectRoot) + '.*telegram_otp_allinone\.py (bot|listen|sync live-status)'
    $procs = Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match $pattern }
    $rootPids = @()
    foreach ($p in $procs) {
        $rootPids += $p.ProcessId
    }
    foreach ($procId in ($rootPids | Sort-Object -Unique)) {
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath (Join-Path $ProjectRoot ".bot_polling.lock") -Force -ErrorAction SilentlyContinue
    return ($rootPids | Sort-Object -Unique).Count
}

# --- Main setup (only when run directly, not dot-sourced) ---
if ($MyInvocation.InvocationName -ne '.' -and $PSCommandPath -eq $MyInvocation.MyCommand.Path) {
    $ErrorActionPreference = "Stop"
    $root = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
    Set-Location $root

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Telegram OTP Bot - Auto Setup" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "[1/5] Checking Python..." -ForegroundColor Yellow
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
        Write-Host "       Python 3.10+ not found. Downloading installer..." -ForegroundColor Red
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
            Write-Error "Python install failed. Install manually from https://python.org then re-run setup.ps1"
            exit 1
        }
    }

    Write-Host ""
    Write-Host "[2/5] Creating virtual environment..." -ForegroundColor Yellow
    try {
        $venvInfo = Ensure-ProjectVenv -ProjectRoot $root
        if ($venvInfo.Created) {
            Write-Host "       .venv created / repaired." -ForegroundColor Green
        } else {
            Write-Host "       .venv already exists and is healthy." -ForegroundColor Green
        }
    } catch {
        Write-Error $_.Exception.Message
        exit 1
    }

    Write-Host ""
    Write-Host "[3/5] Installing dependencies..." -ForegroundColor Yellow
    if (-not (Test-Path (Join-Path $root "requirements.txt"))) {
        Write-Error "requirements.txt not found in $root"
        exit 1
    }
    Install-ProjectRequirements -ProjectRoot $root
    Write-Host "       Dependencies installed." -ForegroundColor Green

    Write-Host ""
    Write-Host "[4/5] Checking config files..." -ForegroundColor Yellow
    $envFile = Join-Path $root ".env"
    if (Test-Path $envFile) {
        Write-Host "       .env OK" -ForegroundColor Green
    } else {
        $envExample = Join-Path $root ".env.example"
        if (Test-Path $envExample) {
            Copy-Item $envExample $envFile
            Write-Host "       .env created from .env.example" -ForegroundColor Yellow
            Write-Host "       IMPORTANT: Edit .env and set TELEGRAM_BOT_TOKEN!" -ForegroundColor Red
        } else {
            Write-Host "       .env missing. Create it manually." -ForegroundColor Red
        }
    }

    if (Test-Path (Join-Path $root "accounts.json")) {
        Write-Host "       accounts.json OK" -ForegroundColor Green
    } else {
        Write-Host "       accounts.json not found!" -ForegroundColor Red
    }

    $sessionDir = Join-Path $root "telegram_session"
    if (Test-Path $sessionDir) {
        $count = (Get-ChildItem $sessionDir -Filter "*.session" -Recurse -File -ErrorAction SilentlyContinue).Count
        Write-Host "       telegram_session/ OK ($count session files)" -ForegroundColor Green
    } else {
        New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null
        Write-Host "       telegram_session/ created (empty — run login-all)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Setup complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Login sessions (if not done yet):" -ForegroundColor White
    Write-Host "     .\.venv\Scripts\python.exe telegram_otp_allinone.py login-all" -ForegroundColor White
    Write-Host "     .\.venv\Scripts\python.exe telegram_otp_allinone.py login-all-shooter" -ForegroundColor White
    Write-Host ""
    Write-Host "  2. Start production (3 separate PowerShell windows):" -ForegroundColor White
    Write-Host "     powershell -ExecutionPolicy Bypass -File .\start_production.ps1" -ForegroundColor White
    Write-Host ""
    Write-Host "  Manual sync (this window, one-off):" -ForegroundColor White
    Write-Host "     .\.venv\Scripts\python.exe telegram_otp_allinone.py sync" -ForegroundColor White
    Write-Host "     .\.venv\Scripts\python.exe telegram_otp_allinone.py sync health" -ForegroundColor White
    Write-Host ""
    Write-Host "  Do NOT: sync loop | Do NOT start production twice" -ForegroundColor Red
    Write-Host ""

    Read-Host "Press Enter to exit"
}
