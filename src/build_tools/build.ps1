# Builds "dist\Oranovix Guardian.exe" (one file) and the installer
# "dist\Oranovix_Guardian_Setup_v1.1.0.exe".
#
#   powershell -ExecutionPolicy Bypass -File src\build_tools\build.ps1
#   powershell -ExecutionPolicy Bypass -File src\build_tools\build.ps1 -NoInstaller
#
# Needs the project venv (venv\) with the packages of src\requirements.txt
# and PyInstaller, and Inno Setup 6 for the installer.

param([switch]$NoInstaller)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Package = Join-Path $Root "src\oranovix_guardian"
Set-Location $Root
$Python = Join-Path $Root "venv\Scripts\python.exe"

# Read-only resources go into the bundle (sys._MEIPASS). Data the app writes
# lives in %LOCALAPPDATA%\Oranovix Guardian (core\app_paths.py), so
# rules\custom_rules.json is not bundled.
$PyInstallerArgs = @(
    "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--windowed",
    "--paths", (Join-Path $Root "src"),
    "--name", "Oranovix Guardian",
    "--icon", (Join-Path $Root "assets\icon.ico"),
    "--add-data", "$(Join-Path $Root 'assets');assets",
    "--add-data", "$(Join-Path $Package 'translations');translations",
    "--add-data", "$(Join-Path $Package 'rules\default_rules.json');rules",
    "--collect-all", "bandit",
    "--collect-all", "stevedore",
    "--copy-metadata", "bandit",
    "--hidden-import", "keyring.backends.Windows",
    "--hidden-import", "truststore",
    "--hidden-import", "regex",
    "--hidden-import", "PIL._tkinter_finder",
    "--collect-data", "certifi",
    "--collect-data", "customtkinter",
    "--collect-submodules", "arabic_reshaper",
    "--distpath", (Join-Path $Root "dist"),
    "--workpath", (Join-Path $Root "build\pyinstaller"),
    "--specpath", (Join-Path $Root "build\pyinstaller"),
    (Join-Path $Root "main.py")
)
& $Python @PyInstallerArgs
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE" }

if ($NoInstaller) { return }

$Iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Iscc) { throw "Inno Setup 6 (ISCC.exe) not found" }
& $Iscc (Join-Path $PSScriptRoot "installer.iss")
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed with exit code $LASTEXITCODE" }
