"""
WiFi Guardian — Central Configuration (v2 — Hardened)
Edit this file to customize your setup before running.

Changes in v2:
  - Replaced KDD Cup 99 with UNSW-NB15 (modern 2015 dataset)
  - Added temporal feature columns (sliding-window analysis)
  - Added alert rate-limiting, model versioning, CSV rotation
  - Added per-device baseline and cumulative anomaly settings
  - Added ARP spoof detection toggle
"""

import os
try:
    from dotenv import load_dotenv
    load_dotenv()  # loads variables from .env file into os.environ
except ImportError:
    pass


# ─── Network ─────────────────────────────────────────────────────────────────
INTERFACE = "wlan0"          # Your WiFi interface (check with: ip a)
SUBNET    = "192.168.1.0/24" # Your local subnet (change if needed)

# ─── Collection ──────────────────────────────────────────────────────────────
CAPTURE_WINDOW_SEC = 30      # seconds to sniff per cycle (longer = more accurate classification)
CYCLE_INTERVAL_SEC = 5       # seconds to sleep between cycles

# ─── Model ───────────────────────────────────────────────────────────────────
MODEL_PATH              = os.path.join(os.path.dirname(__file__), "models", "model.pkl")
ANOMALY_THRESHOLD       = 0.55   # Probability threshold — 0.55 balances sensitivity vs false positives
N_ESTIMATORS            = 50     # Random Forest trees (50 is lightweight for Pi)
RETRAIN_EVERY_N_CYCLES  = 100    # retrain every ~10 min (20 was too frequent — blocks detection on Pi)
USE_UNSW_DATASET        = True   # augment training with UNSW-NB15 real attack data
TEST_SPLIT_RATIO        = 0.2    # 80/20 train/test split for proper validation

# ─── Model Versioning ────────────────────────────────────────────────────────
MODEL_BACKUP_COUNT      = 3      # number of old model backups to keep

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR         = os.path.dirname(__file__)
RAW_DIR          = os.path.join(BASE_DIR, "data", "raw")
PROCESSED_DIR    = os.path.join(BASE_DIR, "data", "processed")
MASTER_DATA_PATH = os.path.join(BASE_DIR, "data", "master_training.csv")  # persistent training store
LOG_FILE         = os.path.join(BASE_DIR, "logs", "alerts.log")

# ─── Master CSV Rotation ─────────────────────────────────────────────────────
MAX_MASTER_ROWS  = 50000    # cap master_training.csv to prevent unbounded growth

# ─── Telegram Alerts (optional) ──────────────────────────────────────────────
# Set these as environment variables OR fill them in directly here
TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN",   "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# ─── Alert Rate Limiting ─────────────────────────────────────────────────────
ALERT_COOLDOWN_SEC = 60     # Telegram: max 1 message per IP per 60 seconds

# ─── Temporal / Sliding Window ───────────────────────────────────────────────
TEMPORAL_WINDOW_CYCLES       = 10   # how many past cycles to track per device
CUMULATIVE_ANOMALY_THRESHOLD = 5    # consecutive suspicious cycles before escalation (was 3)
SLOW_SCAN_PORT_THRESHOLD     = 15   # accumulated ports across cycles to flag slow scan

# ─── Per-Device Baseline ─────────────────────────────────────────────────────
BASELINE_MIN_SAMPLES    = 5      # minimum cycles before a per-device baseline is trusted
BASELINE_DEVIATION_MULT = 5.0    # z-score multiplier — 5.0 = 5 standard deviations (was 3.0)

# ─── ARP Spoof Detection ─────────────────────────────────────────────────────
ARP_SPOOF_DETECTION     = True   # enable ARP spoof detection (IP↔MAC binding tracking)

# ─── Label Safety ────────────────────────────────────────────────────────────
SAFE_NORMAL_THRESHOLD   = 0.1    # only label traffic as "normal" for training if prob < this


# ─── Feature Columns (must match train.py and features.py) ───────────────────
FEATURE_COLS = [
    # ── Base features (from raw packet capture) ──────────────────────────────
    "packets_per_sec",      # total traffic volume (packets)
    "bytes_per_sec",        # total traffic volume (bytes)
    "unique_ports",         # distinct ports contacted or received
    "conn_rate",            # TCP SYN rate (new connections/sec)
    "icmp_rate",            # ICMP packets/sec
    "rst_rate",             # TCP RST packets SENT/sec — spikes on port scan TARGET
    "rx_tx_ratio",          # bytes_in / bytes_out
    # ── Derived features (computed, network-speed-independent) ────────────────
    "bytes_per_packet",     # avg packet size — ICMP≈64B, SYN≈60B, UDP≈1400B
    "icmp_fraction",        # icmp_rate / packets_per_sec  → near 1.0 = ping flood
    "syn_fraction",         # conn_rate  / packets_per_sec → near 1.0 = SYN flood
    "port_scan_ratio",      # unique_ports / (conn_rate+0.01) → high = scan, low = flood
    # ── Temporal features (sliding window across cycles) ──────────────────────
    "delta_packets",        # change in packets_per_sec vs previous cycle
    "delta_ports",          # change in unique_ports vs previous cycle
    "burst_score",          # fraction of last N cycles that were suspicious (0.0–1.0)
    "port_accumulator",     # total unique ports seen across last N cycles
]
