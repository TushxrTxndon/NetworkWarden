# 🔧 WiFi Guardian — Fixes & Configuration Guide

This document tracks all issues identified, their fix status, and the configuration you need to set up.

---

## Issue Tracker

### ✅ Fixed

| ID | Issue | Fix | File(s) Changed |
|---|---|---|---|
| **B2** | No train/test split — model validated on training data | Added 80/20 stratified `train_test_split()` with separate validation report on unseen data | `train.py` |
| **B3** | Label contamination — all collected traffic assumed normal | Only traffic with `prob < 0.1` (configurable `SAFE_NORMAL_THRESHOLD`) is labeled normal for training | `infer.py`, `config.py` |
| **B4** | KDD Cup 99 dataset from 1998 — outdated attack patterns | Replaced with **UNSW-NB15** (2015, modern attacks: Fuzzers, Shellcode, Worms, DoS, Exploits, etc.) | `train.py`, `config.py` |
| **B5** | Single 30s window — no temporal correlation across cycles | Added 4 temporal features (`delta_packets`, `delta_ports`, `burst_score`, `port_accumulator`) via sliding-window `DeviceTracker` | `device_tracker.py` (NEW), `features.py`, `config.py` |
| **B6** | No per-device baseline — all devices share same "normal" | Added per-device rolling statistics using Welford's online algorithm with z-score deviation detection | `device_tracker.py` (NEW) |
| **B7** | Hardcoded classifier thresholds — no adaptation | Classifier now accepts `deviation_scores` from per-device baselines; z-scores shown in evidence when available | `classifier.py` |
| **B8** | ARP scan can be spoofed — no IP↔MAC binding tracking | Added ARP spoof detection: tracks IP↔MAC bindings, alerts on changes with CRITICAL severity and MITRE T1557.002 | `device_tracker.py` (NEW), `collector.py`, `alert.py`, `classifier.py` |
| **B9** | No rate-limiting on Telegram alerts — flood risk | Added per-IP cooldown (default 300s), suppressed alert counting, configurable via `ALERT_COOLDOWN_SEC` | `alert.py`, `config.py` |
| **B10** | Master CSV grows unbounded — eventually OOM | Added rotation: capped at `MAX_MASTER_ROWS` (default 50,000), keeps most recent rows | `train.py`, `config.py` |
| **B11** | No model versioning — old model overwritten | Backup before overwriting, keep last `MODEL_BACKUP_COUNT` (default 3) backups with timestamps | `train.py`, `config.py` |
| **B12** | README says Isolation Forest, code uses Random Forest | README fully rewritten to reflect current architecture, 15 features, UNSW-NB15, and all new capabilities | `README.md` |
| **B14** | No unit tests | Added 39 unit tests across 3 test files: features, classifier, device_tracker (2 new regression tests added) | `tests/` |
| **B1**  | No payload inspection (DPI) — DNS tunneling invisible | Added `dns_query_rate` feature + DNS Tunneling rule in classifier (MITRE T1041). Fixed silent key mismatch (`dns_count` → `dns_queries`) that was causing it to always read 0. | `classifier.py`, `features.py` |
| **B13** | `sys.path.insert(0, ...)` fragile import hack | Created `pyproject.toml` — run `pip install -e .` (now included in `setup.sh`) to install as proper package | `pyproject.toml` (NEW), `setup.sh` |
| **C1**  | ARP scan blocked capture window every cycle | Cached ARP results, refreshes only every 10 cycles. Added interface liveness check. Effective cycle now 6s not 16s. | `collector.py` |
| **C2**  | `classify_attack()` called twice per alert | Pre-compute `AttackResult` once in `infer.py`, pass to `fire_alert()` — eliminates redundant CPU work on Pi | `infer.py`, `alert.py` |
| **C3**  | `run.sh` used system `python3`, not venv | Fixed to use `$SCRIPT_DIR/venv/bin/python` — prevents silent import failures for new users | `run.sh` |

### ⚠️ Partially Fixed

| ID | Issue | What's Done | What Remains |
|---|---|---|---|
| **B15** | Windows incompatible — `arp-scan`, `hostname -I` are Linux-only | This is by design — the system runs on Raspberry Pi with Kali Linux. Tests run on Windows. | No fix needed — production target is always Linux/Pi. |

### ❌ Not Fixable (By Design)

| ID | Issue | Why |
|---|---|---|
| **Encrypted payload inspection** | Cannot inspect HTTPS/TLS content | Would require MITM proxy (breaks trust, illegal without consent). Metadata analysis (timing, volume, flow) is the correct approach. |
| **Physical-layer attacks** | WiFi jamming, rogue APs invisible | Requires specialized hardware (WiFi adapter in monitor mode with deauth frame detection). Out of scope for this project. |
| **Perfect mimicry attacks** | Attacker perfectly imitates normal traffic | Fundamental limitation of all anomaly detection. Can be mitigated with multi-factor detection but never fully eliminated. |

---

## New Capabilities Added

| Feature | Description | Config |
|---|---|---|
| **Slow Scan Detection** | Detects stealthy port scans spread across multiple cycles (e.g., 3 ports/cycle × 6 cycles = 18 ports total) | `SLOW_SCAN_PORT_THRESHOLD` |
| **ARP Spoof Detection** | Tracks IP↔MAC bindings, alerts with CRITICAL severity when bindings change | `ARP_SPOOF_DETECTION` |
| **DNS Tunneling Detection** | Flags >10 DNS queries/sec per device as potential C2 / data exfiltration via DNS (MITRE T1041) | Automatic (rule-based) |
| **Two-Layer Detection** | ML model (soft gate) + Rule engine (hard override). Clear attacks like port scans fire even if ML is uncertain | `ANOMALY_THRESHOLD` |
| **Cumulative Escalation** | Devices flagged suspicious for N consecutive cycles get escalated confidence levels | `CUMULATIVE_ANOMALY_THRESHOLD` |
| **Alert Severity Levels** | INFO (recon), WARNING (scans, brute force), CRITICAL (floods, exfil, ARP spoof, DNS tunnel) | Automatic |
| **Per-Device Baselines** | Each device gets its own "normal" profile via rolling statistics | `BASELINE_MIN_SAMPLES`, `BASELINE_DEVIATION_MULT` |
| **Model Backups** | Old model backed up with timestamp before overwriting | `MODEL_BACKUP_COUNT` |
| **Immediate Alerts** | Telegram fires instantly on every anomaly — no cooldown suppression | `ALERT_COOLDOWN_SEC = 0` |

---

## Configuration Guide

### Required Configuration

Edit `config.py` or set environment variables:

```python
# ─── MUST SET ─────────────────────────────────────────────────────
INTERFACE = "wlan0"           # Your WiFi interface (check: ip a)
SUBNET    = "192.168.1.0/24"  # Your local subnet
```

### Telegram Alerts (Optional)

Set in `.env` file or as environment variables:

```
TELEGRAM_TOKEN=your_bot_token_here     # Get from @BotFather on Telegram
TELEGRAM_CHAT_ID=your_chat_id_here     # Get from @userinfobot
```

### Tunable Parameters

| Parameter | Default | Description | When to Change |
|---|---|---|---|
| `CAPTURE_WINDOW_SEC` | `5` | Seconds to sniff per cycle | Increase for more accuracy, decrease for faster alerts |
| `CYCLE_INTERVAL_SEC` | `1` | Sleep between cycles | Increase to reduce CPU usage |
| `ANOMALY_THRESHOLD` | `0.55` | RF probability threshold | Lower = more sensitive (more false positives) |
| `N_ESTIMATORS` | `50` | Random Forest trees | Increase for accuracy, decrease for speed |
| `RETRAIN_EVERY_N_CYCLES` | `100` | Auto-retrain frequency (~10 min) | Lower = adapts faster, higher = more stable |
| `TEST_SPLIT_RATIO` | `0.2` | Train/test data split | 0.2 is standard, don't go below 0.1 |
| `ALERT_COOLDOWN_SEC` | `0` | Telegram cooldown per IP (0 = no cooldown) | Set to 60 if you get too many Telegram messages |
| `MAX_MASTER_ROWS` | `50000` | Cap on training data CSV | Increase if you have more disk space |
| `MODEL_BACKUP_COUNT` | `3` | Old model backups to keep | Increase if you want more rollback options |
| `TEMPORAL_WINDOW_CYCLES` | `10` | Cycles of history per device | Increase for better slow-scan detection |
| `CUMULATIVE_ANOMALY_THRESHOLD` | `5` | Consecutive suspicious cycles for escalation | Lower = more aggressive escalation |
| `SLOW_SCAN_PORT_THRESHOLD` | `15` | Accumulated ports to flag slow scan | Lower = more sensitive to stealthy scans |
| `BASELINE_MIN_SAMPLES` | `5` | Cycles before device baseline is trusted | Lower = faster adaptation, higher = more stable |
| `BASELINE_DEVIATION_MULT` | `5.0` | Z-score threshold (standard deviations) | Lower = more sensitive, 3.0 is standard |
| `SAFE_NORMAL_THRESHOLD` | `0.1` | Only label traffic as "normal" if prob below this | Lower = stricter, prevents label contamination |
| `USE_UNSW_DATASET` | `True` | Include UNSW-NB15 in training | Set False to skip download (synthetic only) |
| `ARP_SPOOF_DETECTION` | `True` | Enable ARP binding tracking | Set False if you have dynamic DHCP causing false alarms |

---

## Migration from v1/v2

1. **Delete old model**: `rm models/model.pkl` (model format changed)
2. **Delete old master data**: `rm data/master_training.csv` (feature columns changed, 11→15)
3. **Retrain**: `python scripts/train.py`
4. **Run**: `sudo python scripts/infer.py`

> ⚠️ The first run of `train.py` with `USE_UNSW_DATASET=True` will download ~20MB of UNSW-NB15 data. Subsequent runs use a local cache.

---

## Test Verification

Run all tests:
```bash
python -m pytest tests/ -v
```

Run classifier self-test:
```bash
python scripts/classifier.py
```

Expected: **37 unit tests passed**, **9/9 classifier tests passed**.
