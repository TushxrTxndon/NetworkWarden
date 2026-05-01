#!/bin/bash
# ╔══════════════════════════════════════════════════════════╗
# ║   WiFi Guardian — One-Shot Setup Script (Kali Linux)     ║
# ║   Run: chmod +x setup.sh && sudo bash setup.sh           ║
# ╚══════════════════════════════════════════════════════════╝

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║         WiFi Guardian — Kali Linux Setup             ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── 1. Update package list ────────────────────────────────────────────────────
echo "[1/6] Updating packages..."
apt-get update -qq

# ── 2. Install system tools ───────────────────────────────────────────────────
# Most are pre-installed on Kali; || true prevents set -e from aborting on non-critical failures
echo "[2/6] Ensuring system tools are installed..."
apt-get install -y \
    arp-scan \
    nmap \
    tcpdump \
    hping3 \
    python3-pip \
    python3-venv \
    net-tools \
    2>/dev/null || {
    echo "[WARN] Some system tools may not have installed — continuing anyway."
    echo "       Required: arp-scan, python3-venv, python3-pip"
    echo "       Optional: nmap, tcpdump, hping3 (for attack simulation only)"
}

# ── 3. Create project directories ─────────────────────────────────────────────
echo "[3/6] Creating project directories..."
mkdir -p data/raw data/processed models logs

# ── 4. Create and activate Python virtual environment ─────────────────────────
echo "[4/6] Setting up Python virtual environment..."
python3 -m venv venv || {
    echo "[ERROR] Failed to create virtual environment."
    echo "        Install python3-venv: sudo apt-get install python3-venv"
    exit 1
}
source venv/bin/activate

# ── 5. Install Python dependencies ────────────────────────────────────────────
echo "[5/6] Installing Python dependencies..."
pip install --quiet --upgrade pip setuptools wheel
pip install --quiet -r requirements.txt || {
    echo "[ERROR] pip install failed. Check requirements.txt and your internet connection."
    exit 1
}

# Install as a proper package — eliminates sys.path hacks (B13 fix)
echo "      Installing NetworkWarden as editable package..."
pip install --quiet -e . || {
    echo "[WARN] pip install -e . failed. System will still work but imports use path fallback."
}

# ── 6. Verify tools ───────────────────────────────────────────────────────────
echo "[6/6] Verifying tools..."
echo -n "  arp-scan  : "; arp-scan  --version 2>&1 | head -1 || echo "NOT found (required)"
echo -n "  nmap      : "; nmap      --version        | head -1 || echo "NOT found (optional)"
echo -n "  hping3    : "; hping3    --version 2>&1   | head -1 || echo "NOT found (optional)"
echo -n "  tcpdump   : "; tcpdump   --version 2>&1   | head -1 || echo "NOT found (optional)"
echo -n "  Python    : "; python3   --version
echo -n "  scapy     : "; python3 -c "import scapy; print(scapy.__version__)" 2>/dev/null || echo "NOT found (ERROR — required)"
echo -n "  sklearn   : "; python3 -c "import sklearn; print(sklearn.__version__)" 2>/dev/null || echo "NOT found (ERROR — required)"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║              Setup Complete!                         ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Next steps:                                         ║"
echo "║  1. Edit config.py — set INTERFACE (e.g., wlan0)     ║"
echo "║  2. Add Telegram creds to .env (optional)            ║"
echo "║  3. source venv/bin/activate                         ║"
echo "║  4. python scripts/train.py                          ║"
echo "║  5. sudo bash run.sh                                 ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
