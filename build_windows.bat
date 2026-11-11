@echo off
REM ======================================================================
REM  Watchtower AV - ONE-CLICK INSTALLER BUILDER
REM  Double-click this file on any Windows 10/11 PC. It will:
REM    1. ask for admin rights
REM    2. install Python 3.12 and Inno Setup 6 automatically if missing (winget)
REM    3. build WatchtowerAV.exe + watchtower.exe with Python bundled inside
REM    4. produce  dist\WatchtowerAV-Setup-0.1.0.exe   <- give THIS to users
REM  End users need nothing else installed: the setup contains its own Python.
REM ======================================================================
setlocal EnableExtensions
set VER=0.1.0
cd /d "%~dp0"

REM ---- self-elevate -------------------------------------------------------
net session >nul 2>&1
if errorlevel 1 (
  echo Requesting administrator rights...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'"
  exit /b
)

where winget >nul 2>&1
if errorlevel 1 (
  echo winget not found. Install "App Installer" from the Microsoft Store, then re-run.
  goto :err
)
set WG=--silent --accept-package-agreements --accept-source-agreements --disable-interactivity

REM ---- 1. Python ----------------------------------------------------------
set "PY=%ProgramFiles%\Python312\python.exe"
if not exist "%PY%" (
  echo [1/4] Installing Python 3.12 ^(build machine only^)...
  winget install -e --id Python.Python.3.12 --scope machine %WG% --override "/quiet InstallAllUsers=1 Include_tcltk=1 Include_launcher=0 PrependPath=0"
)
if not exist "%PY%" (echo Python install failed. & goto :err)
echo [1/4] Python OK: %PY%

REM ---- 2. Inno Setup ------------------------------------------------------
set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" (
  echo [2/4] Installing Inno Setup 6...
  winget install -e --id JRSoftware.InnoSetup --scope machine %WG%
)
if not exist "%ISCC%" set "ISCC=%LocalAppData%\Programs\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" (echo Inno Setup install failed. & goto :err)
echo [2/4] Inno Setup OK

REM ---- 3. isolated build environment + executables ------------------------
echo [3/4] Building executables (takes 1-3 minutes)...
if not exist .buildenv (
  "%PY%" -m venv .buildenv
  if errorlevel 1 goto :err
)
set "VPY=%~dp0.buildenv\Scripts\python.exe"
"%VPY%" -m pip install --upgrade pip -q
"%VPY%" -m pip install -q -r requirements.txt pyinstaller pytest || goto :err
"%VPY%" -m pytest -q tests || (echo Tests failed - not building. & goto :err)

set COMMON=--noconfirm --onefile --clean --log-level WARN --add-data "rules;rules" --add-data "assets;assets" --icon assets\watchtower.ico --collect-submodules watchdog --version-file installer\version_info.txt
"%VPY%" -m PyInstaller %COMMON% --windowed --name WatchtowerAV launcher_gui.py || goto :err
"%VPY%" -m PyInstaller %COMMON% --console  --name watchtower   launcher_cli.py || goto :err
dist\watchtower.exe info || (echo Built CLI does not run. & goto :err)

REM ---- 4. installer -------------------------------------------------------
echo [4/4] Building installer...
"%ISCC%" /Q /DAppVersion=%VER% installer\WatchtowerAV.iss || goto :err

echo.
echo ==================================================================
echo  SUCCESS:  %~dp0dist\WatchtowerAV-Setup-%VER%.exe
echo  This single file installs Watchtower AV on any Windows 10/11 x64 PC.
echo ==================================================================
explorer "%~dp0dist"
pause
exit /b 0

:err
echo.
echo  Build failed - see messages above.
pause
exit /b 1
