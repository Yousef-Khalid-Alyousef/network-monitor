@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo [network-monitor] Starting launcher...

where py >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python launcher 'py' was not found. Install Python 3 first.
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo [network-monitor] Creating virtual environment...
  py -3 -m venv .venv
  if errorlevel 1 (
    echo [ERROR] Failed to create virtual environment.
    pause
    exit /b 1
  )
)

echo [network-monitor] Installing/updating dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 (
  echo [ERROR] Failed to upgrade pip.
  pause
  exit /b 1
)

".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
  echo [ERROR] Failed to install requirements.
  pause
  exit /b 1
)

if not exist "known_devices.json" (
  echo {}>known_devices.json
)

echo.
echo [network-monitor] Launching monitor...
echo [network-monitor] Tip: run this BAT as Administrator for full packet-capture/firewall access.
echo.
".venv\Scripts\python.exe" main.py

set "EXIT_CODE=%ERRORLEVEL%"
echo.
echo [network-monitor] Exited with code %EXIT_CODE%.
pause
exit /b %EXIT_CODE%
