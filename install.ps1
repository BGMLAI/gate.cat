$ErrorActionPreference = 'Stop'

# gate.cat user-local installer; never writes to the system Python.
$Package = if ($env:GATECAT_PACKAGE) { $env:GATECAT_PACKAGE } else { 'gate.cat' }
$InstallRoot = if ($env:GATECAT_HOME) { $env:GATECAT_HOME } else { Join-Path $HOME '.gate.cat' }
$Venv = Join-Path $InstallRoot 'venv'
$BinDir = if ($env:GATECAT_BIN_DIR) { $env:GATECAT_BIN_DIR } else { Join-Path $HOME '.local\bin' }

$Python = Get-Command py -ErrorAction SilentlyContinue
if (-not $Python) { $Python = Get-Command python -ErrorAction SilentlyContinue }
if (-not $Python) {
    throw 'gate.cat: Python 3.10+ is required.'
}

New-Item -ItemType Directory -Force -Path $InstallRoot, $BinDir | Out-Null

if (-not (Test-Path (Join-Path $Venv 'Scripts\python.exe'))) {
    if (Test-Path $Venv) { Remove-Item -Recurse -Force $Venv }
    & $Python.Source -m venv $Venv
}

$VenvPython = Join-Path $Venv 'Scripts\python.exe'
& $VenvPython -m pip install --disable-pip-version-check --upgrade $Package

$commands = @('gatecat-hook', 'gatecat', 'gatecat-cli', 'gatecat-shell', 'gatecat-proxy')
foreach ($command in $commands) {
    $source = Join-Path $Venv "Scripts\$command.exe"
    if (Test-Path $source) {
        Copy-Item -Force $source (Join-Path $BinDir "$command.exe")
    }
}

& $VenvPython -c 'import gatecat; print("gate.cat installed:", getattr(gatecat, "__version__", "ok"))'

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not (($userPath -split ';') -contains $BinDir)) {
    $newPath = if ($userPath) { "$BinDir;$userPath" } else { $BinDir }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Write-Host "Added $BinDir to the user PATH. Open a new terminal to use gatecat-hook."
}

Write-Host "Installed gate.cat into $Venv"
Write-Host "Hook: $(Join-Path $BinDir 'gatecat-hook.exe')"
