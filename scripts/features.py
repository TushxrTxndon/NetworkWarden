#!/usr/bin/env python3
"""
WiFi Guardian — Feature Extractor (v2 — Temporal Features)

Feature set (15 total):
  Base (7):
    packets_per_sec, bytes_per_sec, unique_ports, conn_rate,
    icmp_rate, rst_rate, rx_tx_ratio

  Derived (4):
    bytes_per_packet, icmp_fraction, syn_fraction, port_scan_ratio

  Temporal (4) — NEW:
    delta_packets, delta_ports, burst_score, port_accumulator

Changes in v2:
  - Added temporal feature injection (from DeviceTracker)
  - Temporal features default to 0 when no history exists (training time)
  - Backward compatible — works with or without DeviceTracker

Usage:
  from scripts.features import get_feature_vector, build_feature_dataframe
"""

import os
import sys
import glob
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import FEATURE_COLS, RAW_DIR, PROCESSED_DIR


def extract_features(record: dict, temporal: dict = None) -> dict:
    """
    Convert one raw collector record into a flat feature dict.
    Returns base features, derived ratio features, and temporal features.

    Args:
        record:   raw collector record dict
        temporal: optional dict from DeviceTracker.get_temporal_features()
                  If None, temporal features default to 0 (training mode).
    """
    w = max(float(record.get("window_sec", 15)), 1.0)

    pkts_in  = float(record.get("packets_in",    0))
    pkts_out = float(record.get("packets_out",   0))
    by_in    = float(record.get("bytes_in",      0))
    by_out   = float(record.get("bytes_out",     0))

    total_pkts  = pkts_in  + pkts_out
    total_bytes = by_in    + by_out
    safe_out    = max(by_out,       1.0)
    safe_pkts   = max(total_pkts,   0.001)  # avoid div-by-zero in fractions

    pkt_s   = round(total_pkts  / w, 4)
    byte_s  = round(total_bytes / w, 4)
    icmp_r  = round(float(record.get("icmp_count",    0)) / w, 4)
    conn_r  = round(float(record.get("conn_attempts", 0)) / w, 4)
    rst_r   = round(float(record.get("rst_count",     0)) / w, 4)
    ports   = int(record.get("unique_ports", 0))
    rx_tx   = round(by_in / safe_out, 4)

    safe_pkt_s  = max(pkt_s,  0.001)
    safe_conn_r = max(conn_r, 0.01)

    # Default temporal features (zero when no history — training or first cycle)
    temp = temporal or {}

    return {
        # ── metadata ──────────────────────────────────────────────────────────
        "ip":        record.get("ip",        ""),
        "mac":       record.get("mac",       ""),
        "timestamp": record.get("timestamp", ""),
        # ── base features ─────────────────────────────────────────────────────
        "packets_per_sec": pkt_s,
        "bytes_per_sec":   byte_s,
        "unique_ports":    ports,
        "conn_rate":       conn_r,
        "icmp_rate":       icmp_r,
        "rst_rate":        rst_r,
        "rx_tx_ratio":     rx_tx,
        # ── derived ratio features (attack-type discriminators) ───────────────
        "bytes_per_packet": round(byte_s / safe_pkt_s, 2),
        "icmp_fraction":    round(min(icmp_r / safe_pkt_s, 1.0), 4),
        "syn_fraction":     round(min(conn_r / safe_pkt_s, 1.0), 4),
        "port_scan_ratio":  round(ports / safe_conn_r, 2) if conn_r > 0 else 0.0,
        # ── temporal features (sliding window across cycles) ──────────────────
        "delta_packets":    round(float(temp.get("delta_packets",    0.0)), 4),
        "delta_ports":      round(float(temp.get("delta_ports",      0.0)), 4),
        "burst_score":      round(float(temp.get("burst_score",      0.0)), 4),
        "port_accumulator": int(temp.get("port_accumulator", 0)),
        # ── additional signal features (not in ML model, used by rule engine) ──
        "dns_query_rate":   round(float(record.get("dns_queries", 0)) / w, 4),
        "window_sec":       w,
    }


def get_feature_vector(record: dict, temporal: dict = None) -> np.ndarray:
    """
    Return a (1, n_features) numpy array for one record.
    Used during real-time inference.
    """
    f = extract_features(record, temporal)
    return np.array([[f[col] for col in FEATURE_COLS]], dtype=np.float32)


def build_feature_dataframe(records: list) -> pd.DataFrame:
    """Convert a list of raw records to a feature DataFrame."""
    return pd.DataFrame([extract_features(r) for r in records])


def process_all_raw_files() -> pd.DataFrame:
    """
    Batch-process every CSV in data/raw/ into a single
    data/processed/features.csv for model training.
    """
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    dfs = []

    files = glob.glob(os.path.join(RAW_DIR, "*.csv"))
    if not files:
        print(f"No raw CSV files found in {RAW_DIR}")
        return pd.DataFrame()

    for f in files:
        df      = pd.read_csv(f)
        records = df.to_dict(orient="records")
        feat_df = build_feature_dataframe(records)
        dfs.append(feat_df)

    combined  = pd.concat(dfs, ignore_index=True)
    out_path  = os.path.join(PROCESSED_DIR, "features.csv")
    combined.to_csv(out_path, index=False)
    print(f"[FEATURES] Processed {len(files)} file(s) → {len(combined)} rows → {out_path}")
    return combined


if __name__ == "__main__":
    process_all_raw_files()
