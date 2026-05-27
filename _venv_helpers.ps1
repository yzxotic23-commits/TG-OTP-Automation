# Shared: cek Python, deteksi .venv rusak (path PC lain), buat ulang jika perlu
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
            Write-Host "[!] .venv rusak / dari PC lain - membuat ulang..." -ForegroundColor Yellow
            Remove-Item -LiteralPath (Join-Path $ProjectRoot ".venv") -Recurse -Force -ErrorAction SilentlyContinue
        }
        $pythonExe = Get-SystemPythonExe
        if (-not $pythonExe) {
            throw "Python 3.$($script:PythonMinMinor)+ tidak ditemukan. Jalankan setup.ps1 dulu."
        }
        & $pythonExe -m venv (Join-Path $ProjectRoot ".venv")
        if (-not (Test-Path -LiteralPath $venvPy)) {
            throw "Gagal membuat .venv dengan $pythonExe"
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
    if (-not (Test-Path -LiteralPath $req)) { throw "requirements.txt tidak ditemukan." }
    & $venvPy -m pip install -U pip wheel -q 2>&1 | Out-Null
    & $venvPy -m pip install -r $req -q
    $check = "import telegram, telethon, filelock; from dotenv import load_dotenv"
    & $venvPy -c $check 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Verifikasi modul gagal setelah pip install."
    }
}
