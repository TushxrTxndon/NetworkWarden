#!/bin/bash
# ╔══════════════════════════════════════════════════════════╗
# ║   WiFi Guardian — System Runner                          ║
# ║   Run: sudo bash run.sh                                  ║
# ╚══════════════════════════════════════════════════════════╝

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/venv/bin/python"
VENV_ACTIVATE="$SCRIPT_DIR/venv/bin/activate"
MODEL="$SCRIPT_DIR/models/model.pkl"

# ── Check virtual environment ─────────────────────────────────────────────────
if [ ! -f "$VENV_ACTIVATE" ]; then
    echo "[ERROR] Virtual environment not found."
    echo "        Run: sudo bash setup.sh"
    exit 1
fi

if [ ! -f "$VENV_PYTHON" ]; then
    echo "[ERROR] Python not found inside venv. Re-run: sudo bash setup.sh"
    exit 1
fi

source "$VENV_ACTIVATE"

# ── Train model if it doesn't exist ──────────────────────────────────────────
if [ ! -f "$MODEL" ]; then
    echo "[INFO] No trained model found. Training now (using synthetic data)..."
    cd "$SCRIPT_DIR"
    # Use venv python explicitly — system python3 won't have scikit-learn/scapy
    "$VENV_PYTHON" scripts/train.py
fi

# ── Set optional Telegram environment variables ───────────────────────────────
# Uncomment and fill in these lines if you want Telegram alerts:
# export TELEGRAM_TOKEN="your_bot_token_here"
# export TELEGRAM_CHAT_ID="your_chat_id_here"

# ── Launch inference engine ───────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║       WiFi Guardian — Starting Monitoring            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

cd "$SCRIPT_DIR"
# Use venv python explicitly — NOT system python3 (system python lacks dependencies)
exec "$VENV_PYTHON" scripts/infer.py
