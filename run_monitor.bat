@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo [network-monitor] Starting launcher...

:: 1. Check for Python
where py >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python launcher 'py' was not found. Install Python 3 first.
  pause
  exit /b 1
)

:: 2. Setup Virtual Environment
if not exist ".venv\Scripts\python.exe" (
  echo [network-monitor] Creating virtual environment...
  py -3 -m venv .venv
  if errorlevel 1 (
    echo [ERROR] Failed to create virtual environment.
    pause
    exit /b 1
  )
)

:: 3. Install Dependencies
echo [network-monitor] Installing/updating dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip >nul 2>&1
".venv\Scripts\python.exe" -m pip install -r requirements.txt >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Failed to install requirements.
  pause
  exit /b 1
)

:: 4. Ensure known_devices.json exists
if not exist "known_devices.json" (
  echo {}>known_devices.json
)

:: 5. Ensure .env exists, if not, copy example and open it
if not exist ".env" (
  echo [network-monitor] First time setup: creating .env configuration file...
  copy .env.example .env >nul
  echo [network-monitor] Opening .env in Notepad for you to add your email credentials...
  notepad .env
  echo [network-monitor] Please save and close notepad when you are done.
  pause
)

:: 6. Launch the monitor
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
