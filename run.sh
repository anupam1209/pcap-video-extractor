#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# run.sh  —  start PCAP Video Extractor
#
#   bash run.sh          →  local Python (tshark + GStreamer must be installed)
#   bash run.sh docker   →  Docker (all deps baked into the image)
# ─────────────────────────────────────────────────────────────────────────────
set -e
cd "$(dirname "$0")"

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"
MODE="${1:-local}"

if [ "$MODE" = "docker" ]; then
  echo "──────────────────────────────────────────────────"
  echo "  PCAP Video Extractor  [Docker]"
  echo "  http://localhost:${PORT}"
  echo "──────────────────────────────────────────────────"
  docker compose up --build
  exit 0
fi

# ── Local Python mode ─────────────────────────────────────────────────────────
PIP=$(command -v pip3 || command -v pip || echo "")
if [ -z "$PIP" ]; then
  echo "ERROR: pip not found. Install Python 3 pip first." >&2; exit 1
fi

# Optional virtualenv
[ -f venv/bin/activate ] && source venv/bin/activate

$PIP install -q -r requirements.txt

echo "──────────────────────────────────────────────────"
echo "  PCAP Video Extractor  [local]"
echo "  http://${HOST}:${PORT}"
echo "──────────────────────────────────────────────────"

python3 -m uvicorn main:app --host "$HOST" --port "$PORT" --reload
