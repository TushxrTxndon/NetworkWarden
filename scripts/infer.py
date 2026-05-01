#!/usr/bin/env python3
"""
WiFi Guardian — Real-Time Inference Engine (v3 — Hardened)

Changes in v3:
  - Integrated DeviceTracker for per-device baselines and temporal features
  - ARP spoof detection on every cycle
  - Cumulative anomaly scoring — escalation after N consecutive suspicious cycles
  - Slow scan detection via port accumulator across cycles
  - Label safety: only label as "normal" for training if model confidence < 0.1 (B3 fix)
  - Temporal features fed into model input (B5 fix)

Usage: sudo venv/bin/python scripts/infer.py
       sudo venv/bin/python scripts/infer.py --once
"""

import os
import sys
import time
import argparse
import logging
import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import (
    MODEL_PATH, ANOMALY_THRESHOLD,
    CYCLE_INTERVAL_SEC, FEATURE_COLS,
    RETRAIN_EVERY_N_CYCLES, USE_UNSW_DATASET,
    MASTER_DATA_PATH, RAW_DIR,
    SAFE_NORMAL_THRESHOLD,
)

from scripts.collector      import collect_snapshot, get_discovered_devices
from scripts.features       import get_feature_vector, extract_features
from scripts.alert          import fire_alert, fire_arp_spoof_alert
from scripts.device_tracker import DeviceTracker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [INFER] %(message)s"
)
log = logging.getLogger("INFER")

# Track IPs currently in an active incident — alert fires ONCE on normal→anomaly
# transition, then stays silent until the IP returns to normal.
_active_incidents: set = set()


# ─── Model Loading ────────────────────────────────────────────────────────────

def load_model():
    if not os.path.exists(MODEL_PATH):
        log.error(f"Model not found at: {MODEL_PATH}")
        log.error("Run: python scripts/train.py")
        sys.exit(1)
    model = joblib.load(MODEL_PATH)
    log.info(f"Model loaded from {MODEL_PATH}")
    return model


# ─── Persist New Data (with label safety — B3 fix) ───────────────────────────

def append_to_master(features_list: list):
    """
    Append newly collected feature rows to the persistent master training store.
    Only rows that the model is HIGHLY confident are normal (prob < SAFE_NORMAL_THRESHOLD)
    are labeled as normal — prevents label contamination (B3 fix).

    Args:
        features_list: list of (feature_dict, probability) tuples
    """
    os.makedirs(os.path.dirname(MASTER_DATA_PATH), exist_ok=True)

    rows = []
    for feat, prob in features_list:
        if prob > SAFE_NORMAL_THRESHOLD:
            # Model isn't confident this is normal — skip to prevent contamination
            continue
        row = {col: feat.get(col, 0.0) for col in FEATURE_COLS}
        row["label"] = 0  # confidently normal
        rows.append(row)

    if not rows:
        return

    new_df = pd.DataFrame(rows)

    if os.path.exists(MASTER_DATA_PATH):
        new_df.to_csv(MASTER_DATA_PATH, mode="a", header=False, index=False)
    else:
        new_df.to_csv(MASTER_DATA_PATH, index=False)

    log.info(f"Appended {len(rows)} confident-normal records to master training store")


# ─── Auto Retrain ─────────────────────────────────────────────────────────────

def retrain():
    """
    Trigger a full retrain using all accumulated data.
    Called automatically every RETRAIN_EVERY_N_CYCLES cycles.
    """
    log.info("=" * 54)
    log.info("AUTO-RETRAIN: incorporating all accumulated data...")
    log.info("=" * 54)

    try:
        from scripts.train import train_model
        model = train_model(use_unsw=USE_UNSW_DATASET)
        log.info("AUTO-RETRAIN complete. Model updated.")
        return model
    except Exception as e:
        log.error(f"AUTO-RETRAIN failed: {e}")
        return None


# ─── Single Inference Cycle ───────────────────────────────────────────────────

def run_cycle(model, tracker: DeviceTracker) -> list:
    """
    One full collect → extract → infer → alert cycle.
    Now integrated with DeviceTracker for temporal + baseline features.

    Returns list of (feat_dict, score, is_anomaly)
    """
    log.info("Collecting network snapshot...")

    # ── ARP Spoof Detection (B8 fix) ─────────────────────────────────────────
    devices = get_discovered_devices()
    arp_spoofs = tracker.check_arp_bindings(devices)
    for spoof in arp_spoofs:
        fire_arp_spoof_alert(spoof)

    # ── Collect raw packet data ──────────────────────────────────────────────
    raw_records = collect_snapshot()

    if not raw_records:
        log.warning("No devices found.")
        return []

    results      = []
    normal_buf   = []   # buffer for master store append: (feat, prob) tuples

    for raw in raw_records:
        ip = raw.get("ip", "")

        # Get temporal features from device history (B5 fix)
        # On first cycle, these will be all zeros (no history yet)
        temp_feats = tracker.get_temporal_features(ip, raw)

        # Extract features with temporal context
        feat = extract_features(raw, temporal=temp_feats)

        # Build feature vector for model
        X = np.array([[feat[col] for col in FEATURE_COLS]], dtype=np.float32)

        # Predict probability of attack (class 1)
        prob_attack = float(model.predict_proba(X)[0][1])

        # Strict threshold + dead-air filter
        # (Lowered from 1.0 to 0.1 because on 30s windows, 1.0 pps = 30 packets.
        # Slower scans/brute forces might only generate 10-20 packets.)
        is_anomaly = (prob_attack > ANOMALY_THRESHOLD) and (feat['packets_per_sec'] > 0.1)

        # ── Classifier confirmation ──────────────────────────────────────────
        # ALWAYS run the classifier to know what type of attack this is.
        from scripts.classifier import classify_attack as _classify
        attack_result = _classify(feat, tracker.get_deviation_scores(ip, feat),
                                   tracker.should_escalate(ip))

        # Specific, high-confidence attack types (not soft signals)
        hard_attack_types = {"Port Scan", "SYN Flood", "Ping Flood",
                             "UDP Flood", "Brute Force", "Data Exfiltration",
                             "DNS Tunneling", "Slow / Stealthy Port Scan",
                             "UDP / Bandwidth Flood", "Ping Flood (ICMP DoS)",
                             "SYN Flood (TCP DoS)", "DNS Tunneling / C2 via DNS",
                             "ARP Spoofing / Cache Poisoning"}

        # ── False positive suppression ───────────────────────────────────────
        # If ML says anomaly BUT classifier only sees "Unknown Anomaly" or
        # "Network Reconnaissance" with Low confidence → suppress.
        # This eliminates idle devices being flagged as anomalous.
        if is_anomaly:
            if (attack_result.name not in hard_attack_types
                    and attack_result.confidence == "Low"):
                is_anomaly = False
                log.info(f"  Suppressed false positive: {attack_result.name} "
                         f"({attack_result.confidence}) score={prob_attack:.4f}")

        # ── Rule-based override for clear attacks ────────────────────────────
        # If ML misses but the classifier sees an obvious attack pattern,
        # override. Only for high-confidence, specific attack types.
        rule_override = False
        if not is_anomaly and feat['packets_per_sec'] > 0.1:
            if (attack_result.name in hard_attack_types
                    and attack_result.confidence in ("High", "Critical")):
                rule_override = True
                log.info(f"  -> Rule override: {attack_result.name} ({attack_result.confidence})")

        # Check for slow scan (temporal, cross-cycle detection — B5 fix)
        is_slow_scan = tracker.is_slow_scan(ip) and feat['packets_per_sec'] > 0.1

        # Check for cumulative escalation
        is_escalated = tracker.should_escalate(ip)

        # Get per-device deviation scores (B6 fix)
        deviation_scores = tracker.get_deviation_scores(ip, feat)

        # Final anomaly decision: ML model OR rule override OR slow scan
        final_anomaly = is_anomaly or rule_override or is_slow_scan

        status = "⚠ ANOMALY" if final_anomaly else "  Normal "
        extra = ""
        if is_slow_scan and not is_anomaly:
            extra = " [SLOW SCAN]"
        if is_escalated:
            extra += " [ESCALATED]"

        log.info(
            f"{status}{extra} | {ip:>15} | prob={prob_attack:+.4f} | "
            f"pkt/s={feat['packets_per_sec']:>6.1f} | "
            f"ports={feat['unique_ports']:>4} | "
            f"icmp/s={feat['icmp_rate']:>5.1f} | "
            f"burst={feat.get('burst_score', 0):.2f}"
        )

        if final_anomaly:
            # Fire-once-per-incident: only alert on the TRANSITION from normal → anomaly.
            # If this IP is already in an active incident, stay silent.
            if ip not in _active_incidents:
                _active_incidents.add(ip)
                fire_alert(feat, prob_attack, deviation_scores, is_escalated)
        else:
            # IP returned to normal — clear incident so next anomaly will alert again
            _active_incidents.discard(ip)
            # Only append to training buffer if model is highly confident it's normal
            normal_buf.append((feat, prob_attack))

        # ── Update device tracker AFTER inference ────────────────────────────
        # Record this cycle (for temporal features in the NEXT cycle)
        tracker.record_cycle(ip, feat, final_anomaly)

        # Update baseline only for confirmed normal traffic
        if not final_anomaly and prob_attack < SAFE_NORMAL_THRESHOLD:
            tracker.update_baseline(ip, feat)

        results.append((feat, prob_attack, final_anomaly))

    # Persist confident-normal data to master store (B3 fix)
    if normal_buf:
        append_to_master(normal_buf)

    return results


# ─── Main Loop ────────────────────────────────────────────────────────────────

def main(once: bool = False):
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║     WiFi Guardian — AI Anomaly Detection v3         ║")
    print(f"║  Auto-retrain every {RETRAIN_EVERY_N_CYCLES} cycles | Press Ctrl+C to stop  ║")
    print("║  Features: temporal + per-device baseline + ARP     ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    model   = load_model()
    tracker = DeviceTracker()
    cycle   = 0

    while True:
        cycle += 1
        ts = time.strftime("%H:%M:%S")
        print(f"\n{'─'*56}")
        print(f"  Cycle #{cycle:<4}  {ts}  |  Devices tracked: {tracker.get_device_count()}  "
              f"Baselines: {tracker.get_baseline_count()}")
        print(f"{'─'*56}")

        try:
            results   = run_cycle(model, tracker)
            anomalies = [r for r in results if r[2]]
            print(f"  Devices : {len(results)} scanned   Anomalies: {len(anomalies)}")

            # ── Auto retrain every N cycles ───────────────────────────────
            if cycle % RETRAIN_EVERY_N_CYCLES == 0:
                new_model = retrain()
                if new_model is not None:
                    model = new_model
                    log.info("Live model swapped to newly trained version ✓")

        except PermissionError:
            log.error("Permission denied — run: sudo venv/bin/python scripts/infer.py")
            sys.exit(1)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            log.error(f"Cycle error: {e}")

        if once:
            break

        log.info(f"Sleeping {CYCLE_INTERVAL_SEC}s...\n")
        time.sleep(CYCLE_INTERVAL_SEC)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true",
                        help="Run single cycle and exit (for testing)")
    args = parser.parse_args()
    try:
        main(once=args.once)
    except KeyboardInterrupt:
        print("\n\n[WiFi Guardian] Stopped. Goodbye!")
        sys.exit(0)
