#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[network-monitor] Starting Raspberry Pi launcher..."

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 is not installed." >&2
  exit 1
fi

if [[ ! -d ".venv" ]]; then
  echo "[network-monitor] Creating virtual environment..."
  python3 -m venv .venv
fi

echo "[network-monitor] Installing/updating dependencies..."
".venv/bin/python" -m pip install --upgrade pip
".venv/bin/python" -m pip install -r requirements.txt

if [[ ! -f "known_devices.json" ]]; then
  echo "{}" > known_devices.json
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "[network-monitor] Re-launching with sudo for packet capture/firewall access..."
  exec sudo ".venv/bin/python" main.py
fi

exec ".venv/bin/python" main.py
