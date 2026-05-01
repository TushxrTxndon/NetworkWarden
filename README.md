<div align="center">

# 🛡️ WiFi Guardian
### AI-Powered Network Intrusion Detection System

**Running on Raspberry Pi 4 | Kali Linux | Python + scikit-learn**

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python)
![Raspberry Pi](https://img.shields.io/badge/Raspberry%20Pi-4-red?style=for-the-badge&logo=raspberry-pi)
![Kali Linux](https://img.shields.io/badge/Kali%20Linux-ARM-blue?style=for-the-badge&logo=kali-linux)
![scikit-learn](https://img.shields.io/badge/scikit--learn-RandomForest-orange?style=for-the-badge&logo=scikit-learn)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

</div>

---

## 📌 What is WiFi Guardian?

**WiFi Guardian** is a real-time AI-powered network security system that runs entirely on a Raspberry Pi. It monitors every device on your local WiFi network, learns what normal traffic looks like **per device**, and automatically detects and classifies suspicious or malicious behavior — all without any cloud dependency.

> Built for **hackathons**, **live demonstrations**, and **home network security**.

---

## 🎯 Problem Statement

Modern home and office networks are filled with devices — phones, laptops, IoT gadgets — yet most people have **zero visibility** into what's happening on their network. Traditional firewalls use fixed rules and miss novel threats. Commercial solutions are expensive, cloud-dependent, and don't work offline.

**WiFi Guardian solves this by:**
- Running a supervised Random Forest classifier directly on a $35 Raspberry Pi
- Learning per-device baselines automatically (what's normal for YOUR devices)
- Detecting attacks across time windows (catches slow/stealthy scans)
- Detecting ARP spoofing (man-in-the-middle attacks)
- Flagging anomalies in real-time without any internet requirement
- Sending instant alerts to your phone via Telegram

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     WiFi Guardian Pipeline                      │
│                                                                 │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────────┐  │
│  │  COLLECTION │    │   FEATURE    │    │    ML MODEL       │  │
│  │             │    │  EXTRACTION  │    │  Random Forest    │  │
│  │  arp-scan   │───▶│              │───▶│  (supervised)     │  │
│  │  + scapy    │    │  15 numeric  │    │                   │  │
│  │             │    │  features    │    │  Trained on:      │  │
│  │  every 30s  │    │  per device  │    │  • UNSW-NB15      │  │
│  └─────────────┘    └──────────────┘    │  • Synthetic data │  │
│         │                               │  • Your network   │  │
│  ┌──────▼──────┐                        └────────┬──────────┘  │
│  │ ARP SPOOF   │                                 │              │
│  │ DETECTION   │                                 │              │
│  │ IP↔MAC      │──────────────┐                  │              │
│  │ tracking    │              │    ┌─────────────▼──────────┐  │
│  └─────────────┘              │    │   ATTACK CLASSIFIER    │  │
│                               │    │   Rule-based + temporal│  │
│  ┌─────────────┐              │    │   + per-device z-score │  │
│  │ DEVICE      │              │    └─────────────┬──────────┘  │
│  │ TRACKER     │──────────────┤                  │              │
│  │ • baselines │              │    ┌─────────────▼──────────┐  │
│  │ • temporal  │              └───▶│    ALERT SYSTEM        │  │
│  │ • history   │                   │  • Terminal (colored)  │  │
│  └─────────────┘                   │  • Telegram bot        │  │
│                                    │  • Persistent log      │  │
│                                    │  • Rate-limited per IP │  │
│                                    └────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔬 How It Works

### Stage 1 — Data Collection
Every 30 seconds, the system:
- Runs `arp-scan` to discover all live devices on the LAN
- Checks for **ARP spoofing** (IP↔MAC binding changes)
- Uses `scapy` to sniff raw packets for each device
- Captures traffic statistics: packets, bytes, ports, ICMP, TCP SYN/RST, DNS queries

### Stage 2 — Feature Engineering
Raw packet data is converted into **15 numerical features** per device:

| # | Feature | Formula | Attack Signal |
|---|---|---|---|
| 1 | `packets_per_sec` | total packets / window | DDoS / flood |
| 2 | `bytes_per_sec` | total bytes / window | Exfiltration / flood |
| 3 | `unique_ports` | distinct ports contacted or received | Port scanning |
| 4 | `conn_rate` | TCP SYN count / window | Brute force / SYN flood |
| 5 | `icmp_rate` | ICMP packets / window | Ping flood |
| 6 | `rst_rate` | TCP RST packets / window | Port scan target signal |
| 7 | `rx_tx_ratio` | bytes_in / bytes_out | Exfiltration (near 0) |
| 8 | `bytes_per_packet` | bytes / packets | Protocol discriminator |
| 9 | `icmp_fraction` | icmp / total packets | Ping flood fraction |
| 10 | `syn_fraction` | SYN / total packets | SYN flood fraction |
| 11 | `port_scan_ratio` | ports / conn_rate | Scan vs flood |
| 12 | `delta_packets` | change vs previous cycle | Sudden traffic spike |
| 13 | `delta_ports` | change vs previous cycle | Sudden port change |
| 14 | `burst_score` | % of recent suspicious cycles | Sustained attack |
| 15 | `port_accumulator` | total ports across N cycles | Slow scan detection |

### Stage 3 — Machine Learning (Random Forest)
**Why Random Forest?**
- **Supervised** — trained on real labeled attack data (UNSW-NB15)
- **Learns your baseline** — per-device rolling statistics
- **Lightweight** — 50 trees, trains in seconds, inference < 1ms on Pi 4
- **Interpretable** — feature importances explain why a detection occurred

### Stage 4 — Attack Classification
A rule-based classifier examines features and labels the attack type. It uses:
- **Per-device z-scores** (how far from THIS device's baseline)
- **Temporal features** (cross-cycle port accumulation, burst scoring)
- **Cumulative escalation** (sustained suspicious activity boosts confidence)

### Stage 5 — Alerting
Alerts fire through configured channels with **severity levels** and **rate limiting**:
- **Terminal** — color-coded by severity (red=CRITICAL, yellow=WARNING, cyan=INFO)
- **Telegram** — push notification with HTML-sanitized output
- **Log file** — persistent audit trail
- **Per-IP cooldown** — prevents alert floods (default: 5 min)

### Stage 6 — Incremental Learning
- Only **confidently normal** traffic (prob < 0.1) feeds back to training data
- Every 20 cycles, the model **automatically retrains** with all accumulated data
- Old model is **backed up** before overwriting (versioned with timestamps)
- Master training CSV is **rotated** at 50,000 rows to prevent unbounded growth

---

## 🚨 Attacks WiFi Guardian Can Detect & Classify

| # | Attack Type | How It's Detected | MITRE ATT&CK | Confidence |
|---|---|---|---|---|
| 🔍 | **Port Scan** | `unique_ports` spikes + `rst_rate` high | T1046 | High |
| 🌊 | **Ping Flood (ICMP DoS)** | `icmp_fraction` > 40% | T1499.002 | High |
| ⚡ | **SYN Flood (TCP DoS)** | `syn_fraction` high + `rst_rate` low | T1498.001 | High |
| 🌀 | **UDP Flood** | `bytes_per_packet` + `bytes_per_sec` spike | T1498.001 | High |
| 📤 | **Data Exfiltration** | High outbound + `rx_tx_ratio` near 0 | T1041 | Medium |
| 🔑 | **Brute Force** | Rapid connections to 1–2 ports | T1110 | Medium |
| 🐌 | **Slow / Stealthy Scan** | `port_accumulator` grows across cycles | T1046 | Medium |
| 🕵️ | **ARP Spoofing** | IP↔MAC binding changed | T1557.002 | Critical |
| 👁️ | **Reconnaissance** | Moderate port diversity | T1595 | Low |
| ❓ | **Unknown Anomaly** | Statistical outlier, no known signature | T1499 | Low |

> **Important:** WiFi Guardian *detects* anomalies. It does not block traffic.

### What It Cannot Detect
- Attacks hidden inside encrypted payloads (HTTPS content)
- Extremely slow, low-volume covert channels
- Physical-layer attacks (WiFi jamming, rogue access points)
- Attacks that perfectly mimic normal traffic patterns

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Hardware** | Raspberry Pi 4 (4GB RAM) | Edge compute platform |
| **OS** | Kali Linux (ARM64) | Pre-loaded network tools |
| **Language** | Python 3.11+ | Core implementation |
| **Device Discovery** | `arp-scan` | LAN device enumeration |
| **Packet Capture** | `scapy` | Raw traffic analysis |
| **Data Processing** | `pandas`, `numpy` | Feature engineering |
| **ML Framework** | `scikit-learn` (Random Forest) | Supervised classification |
| **Training Data** | UNSW-NB15 (2015) | Modern real attack dataset |
| **Model Storage** | `joblib` | Compressed .pkl with versioning |
| **Alert Delivery** | Telegram Bot API | Real-time phone alerts |
| **Testing** | `pytest` | 37 unit tests |

---

## 📁 Project Structure

```
wifi-guardian/
│
├── config.py                   # All settings — edit this first
├── requirements.txt            # Python dependencies
├── setup.sh                    # One-shot Kali Linux setup
├── run.sh                      # Start the full system
├── FIXES.md                    # Issue tracker & configuration guide
├── .env.example                # Telegram config template
├── README.md                   # This file
│
├── scripts/
│   ├── collector.py            # ARP scan + scapy traffic capture + DNS counting
│   ├── features.py             # Feature engineering (15 features)
│   ├── train.py                # Model training (UNSW-NB15 + synthetic + real)
│   ├── classifier.py           # Rule-based attack classifier (10 types)
│   ├── alert.py                # Alert system (rate-limited, severity-based)
│   ├── device_tracker.py       # Per-device baselines + temporal history + ARP spoof
│   └── infer.py                # Real-time inference loop (main entry point)
│
├── tests/
│   ├── test_features.py        # Feature extraction unit tests
│   ├── test_classifier.py      # Attack classification unit tests
│   └── test_device_tracker.py  # Device tracker unit tests
│
├── data/
│   ├── raw/                    # Raw snapshots from collector (gitignored)
│   ├── processed/              # Feature CSVs (gitignored)
│   ├── unsw_cache/             # Cached UNSW-NB15 dataset (gitignored)
│   └── master_training.csv     # Persistent training store (gitignored)
│
├── models/
│   └── model.pkl               # Trained Random Forest (gitignored)
│
└── logs/
    └── alerts.log              # Alert audit trail (gitignored)
```

---

## ⚡ Quick Start (Kali Linux on Raspberry Pi)

### 1. Clone the repository
```bash
git clone https://github.com/TushxrTxndon/NetworkWarden wifi-guardian
cd wifi-guardian
```

### 2. Run setup
```bash
chmod +x setup.sh run.sh
sudo bash setup.sh
```

### 3. Configure
```bash
nano config.py
```
```python
INTERFACE = "wlan0"            # check with: ip a
SUBNET    = "192.168.1.0/24"   # your network
```

### 4. Set up Telegram alerts (optional)
```bash
cp .env.example .env
nano .env
# Add your TELEGRAM_TOKEN and TELEGRAM_CHAT_ID
```

### 5. Train the model
```bash
source venv/bin/activate
python scripts/train.py
```

### 6. Start monitoring
```bash
sudo venv/bin/python scripts/infer.py
```

---

## 📊 Training Data Sources

| Source | Records | Type | Purpose |
|---|---|---|---|
| **UNSW-NB15** | ~7,000 sampled | Real network (2015) | Modern attack/normal diversity |
| **Synthetic** | 900 generated | Simulated | Controlled examples for 5 attack types |
| **Collected** | Grows over time | Live from your Pi | Learns YOUR network baseline |

The model automatically retrains every 20 cycles using all accumulated data.

---

## ⚙️ Configuration Reference

See [FIXES.md](FIXES.md) for the full configuration guide with all tunable parameters.

| Parameter | Default | Description |
|---|---|---|
| `INTERFACE` | `wlan0` | Network interface to monitor |
| `SUBNET` | `192.168.1.0/24` | Local subnet |
| `CAPTURE_WINDOW_SEC` | `30` | Seconds to capture per cycle |
| `ANOMALY_THRESHOLD` | `0.5` | RF probability cutoff |
| `ALERT_COOLDOWN_SEC` | `300` | Min seconds between alerts per IP |
| `USE_UNSW_DATASET` | `True` | Include UNSW-NB15 in training |
| `ARP_SPOOF_DETECTION` | `True` | Track IP↔MAC bindings |

---

## 🔒 Ethics & Legal

> ⚠️ Run WiFi Guardian **only on networks you own or are authorized to monitor**. Running `nmap` or `hping3` against third-party networks is illegal in most jurisdictions.

---

## 📄 License

MIT License — free to use, modify, and distribute with attribution.

---

## 👤 Author

**Tushar Tandon**
GitHub: [@TushxrTxndon](https://github.com/TushxrTxndon)

---

<div align="center">

*Built with ❤️ on Raspberry Pi 4 | Kali Linux | Python + scikit-learn*

**WiFi Guardian — Because your network deserves a guardian**

</div>
