#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[network-monitor] Starting Raspberry Pi launcher..."

# 1. Check Python
if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 is not installed." >&2
  exit 1
fi

# 2. Setup venv
if [[ ! -d ".venv" ]]; then
  echo "[network-monitor] Creating virtual environment..."
  python3 -m venv .venv
fi

# 3. Install Dependencies
echo "[network-monitor] Installing/updating dependencies..."
".venv/bin/python" -m pip install --upgrade pip >/dev/null 2>&1
".venv/bin/python" -m pip install -r requirements.txt >/dev/null 2>&1

# 4. Ensure known_devices.json exists
if [[ ! -f "known_devices.json" ]]; then
  echo "{}" > known_devices.json
fi

# 5. Ensure .env exists
if [[ ! -f ".env" ]]; then
  echo "[network-monitor] First time setup: creating .env configuration file..."
  cp .env.example .env
  echo "=========================================================================="
  echo "  PLEASE EDIT '.env' TO ADD YOUR EMAIL CREDENTIALS BEFORE RUNNING AGAIN"
  echo "  You can edit it with: nano .env"
  echo "=========================================================================="
  exit 0
fi

# 6. Re-launch with sudo if needed
if [[ "${EUID}" -ne 0 ]]; then
  echo "[network-monitor] Re-launching with sudo for packet capture/firewall access..."
  exec sudo ".venv/bin/python" main.py
fi

exec ".venv/bin/python" main.py
