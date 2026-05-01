#!/usr/bin/env python3
"""
WiFi Guardian — Alert System (v2 — Rate Limiting + Severity)

Changes in v2:
  - Per-IP alert cooldown (configurable, default 5 min) — B9 fix
  - Alert severity levels (INFO, WARNING, CRITICAL)
  - Telegram HTML sanitization to prevent parse errors
  - ARP spoof alert support (separate from anomaly alerts)

Import and call fire_alert() from infer.py — do not run directly.
"""

import os
import sys
import time
import html
import logging
import requests
from datetime import datetime
from collections import defaultdict

from scripts.classifier import (
    classify_attack, classify_arp_spoof,
    format_attack_result, AttackResult
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import (
    TELEGRAM_TOKEN, TELEGRAM_CHAT_ID,
    LOG_FILE, ALERT_COOLDOWN_SEC,
)

# ─── Logger setup ─────────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
log = logging.getLogger("ALERT")
log.setLevel(logging.INFO)

# File handler — persistent alert log
fh = logging.FileHandler(LOG_FILE)
fh.setFormatter(logging.Formatter("%(asctime)s [ALERT] %(message)s"))
log.addHandler(fh)

# (StreamHandler removed to prevent double-printing to terminal)


# ─── Rate Limiter (B9 fix) ───────────────────────────────────────────────────
# Two independent cooldowns:
#   1. _tg_last_alert   — per IP, gates Telegram (ALERT_COOLDOWN_SEC from config)
#   2. _term_last_alert — per IP+attack name, gates terminal/log (TERMINAL_DEDUP_SEC)

TERMINAL_DEDUP_SEC = 60   # suppress duplicate terminal alerts for same IP+attack type

_tg_last_alert:   dict = defaultdict(float)   # keyed by IP
_term_last_alert: dict = defaultdict(float)   # keyed by "IP|attack_name"
_suppressed_count: dict = defaultdict(int)    # keyed by IP


def _should_alert_telegram(ip: str) -> bool:
    """Telegram gate: per-IP cooldown via ALERT_COOLDOWN_SEC."""
    now = time.time()
    if now - _tg_last_alert[ip] < ALERT_COOLDOWN_SEC:
        _suppressed_count[ip] += 1
        return False
    _tg_last_alert[ip] = now
    return True


def _should_print_terminal(ip: str, attack_name: str = "") -> bool:
    """Terminal/log gate: suppress all alerts for same IP for TERMINAL_DEDUP_SEC seconds."""
    now = time.time()
    if now - _term_last_alert[ip] < TERMINAL_DEDUP_SEC:
        return False
    _term_last_alert[ip] = now
    return True


def _get_suppressed_info(ip: str) -> str:
    """Return suppression info string if alerts were suppressed."""
    count = _suppressed_count.get(ip, 0)
    if count > 0:
        _suppressed_count[ip] = 0
        return f"\n   ⏭ {count} alert(s) suppressed during cooldown period"
    return ""


# ─── Message Formatter ────────────────────────────────────────────────────────

def format_message(record: dict, score: float,
                    deviation_scores: dict = None,
                    is_escalated: bool = False) -> str:
    """Build a human-readable alert string including attack classification."""
    attack  = classify_attack(record, deviation_scores, is_escalated)
    atk_str = format_attack_result(attack, score)
    suppressed = _get_suppressed_info(record.get("ip", ""))

    escalation_line = ""
    if is_escalated:
        escalation_line = "   🔺 ESCALATED : Sustained suspicious activity across multiple cycles\n"

    return (
        f"🚨 ANOMALY DETECTED  [{attack.severity}]\n"
        f"{'─'*44}\n"
        f"Time        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"IP Address  : {record.get('ip',  'N/A')}\n"
        f"MAC Address : {record.get('mac', 'N/A')}\n"
        f"{'─'*44}\n"
        f"{escalation_line}"
        f"{atk_str}\n"
        f"{'─'*44}\n"
        f"Pkts/sec    : {record.get('packets_per_sec', 0):.2f}\n"
        f"Bytes/sec   : {record.get('bytes_per_sec',   0):.0f}\n"
        f"Unique Ports: {record.get('unique_ports',    0)}\n"
        f"Conn/sec    : {record.get('conn_rate',        0):.2f}\n"
        f"ICMP/sec    : {record.get('icmp_rate',        0):.2f}\n"
        f"RST/sec     : {record.get('rst_rate',         0):.2f}\n"
        f"RX/TX Ratio : {record.get('rx_tx_ratio',      0):.3f}\n"
        f"{'─'*44}"
        f"{suppressed}"
    )


def format_arp_spoof_message(spoof_info: dict) -> str:
    """Build alert message for ARP spoofing event."""
    attack = classify_arp_spoof(spoof_info)
    return (
        f"🕵️ ARP SPOOF DETECTED  [CRITICAL]\n"
        f"{'─'*44}\n"
        f"Time        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"IP Address  : {spoof_info.get('ip', 'N/A')}\n"
        f"Old MAC     : {spoof_info.get('old_mac', 'N/A')}\n"
        f"New MAC     : {spoof_info.get('new_mac', 'N/A')}\n"
        f"{'─'*44}\n"
        f"MITRE ATT&CK: {attack.mitre_code} — {attack.mitre_name}\n"
        f"Description : {attack.description}\n"
        f"{'─'*44}\n"
        f"⚠ This may indicate a Man-in-the-Middle (MITM) attack.\n"
        f"  The attacker is redirecting network traffic through their device.\n"
        f"{'─'*44}"
    )


# ─── Alert Channels ───────────────────────────────────────────────────────────

def alert_terminal(message: str, severity: str = "WARNING"):
    """Print a colored alert to the terminal."""
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

    color = {
        "INFO":     CYAN,
        "WARNING":  YELLOW,
        "CRITICAL": RED,
    }.get(severity, RED)

    border = "═" * 52
    print(f"\n{color}{BOLD}{border}{RESET}")
    print(f"{color}{message}{RESET}")
    print(f"{color}{BOLD}{border}{RESET}\n")


def alert_log(message: str):
    """Write alert to the persistent log file."""
    log.warning(message)


def alert_telegram(message: str):
    """
    Send alert via Telegram bot.
    Sanitizes HTML to prevent parse errors.
    Configure TELEGRAM_TOKEN and TELEGRAM_CHAT_ID in .env or config.py.
    """
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return  # not configured — silently skip

    # Sanitize: escape any HTML entities in the message, then wrap in <pre>
    sanitized = html.escape(message)

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    try:
        resp = requests.post(
            url,
            json={
                "chat_id":    TELEGRAM_CHAT_ID,
                "text":       f"<pre>{sanitized}</pre>",
                "parse_mode": "HTML",
            },
            timeout=10
        )
        if resp.status_code == 200:
            log.info("Telegram alert sent ✓")
        else:
            log.error(f"Telegram API error {resp.status_code}: {resp.text[:200]}")
    except requests.exceptions.ConnectionError:
        log.error("Telegram: no internet connection")
    except Exception as e:
        log.error(f"Telegram failed: {e}")


# ─── Public API ───────────────────────────────────────────────────────────────

def fire_alert(record: dict, score: float,
                deviation_scores: dict = None,
                is_escalated: bool = False):
    """
    Fire all configured alert channels for an anomaly.

    Called ONCE per incident (infer.py handles fire-once-per-incident logic).
    Every call to this function is a genuine new alert — no dedup needed here.

    Args:
        record:           feature dict from features.extract_features()
        score:            Random Forest prediction probability
        deviation_scores: optional z-scores from device baseline
        is_escalated:     True if sustained suspicious activity
    """
    ip = record.get("ip", "unknown")

    message  = format_message(record, score, deviation_scores, is_escalated)
    attack   = classify_attack(record, deviation_scores, is_escalated)
    severity = attack.severity

    alert_terminal(message, severity)
    alert_log(message)
    alert_telegram(message)


def fire_arp_spoof_alert(spoof_info: dict):
    """
    Fire alert for ARP spoofing — always fires (no rate limiting for spoofs).
    """
    message = format_arp_spoof_message(spoof_info)

    alert_terminal(message, severity="CRITICAL")
    alert_log(message)
    alert_telegram(message)
