#!/usr/bin/env python3
"""
WiFi Guardian — Model Trainer (v3 — UNSW-NB15 + Hardened)

Data sources used (merged automatically):
  1. UNSW-NB15   — Modern (2015) real network attack dataset (replaces KDD-99)
  2. Synthetic   — Generated normal/attack patterns with temporal features
  3. Collected   — Your own Pi's captured traffic (grows over time)
  4. Master CSV  — Persistent union of all previous training runs

Changes in v3:
  - Replaced KDD Cup 99 (1998) with UNSW-NB15 (2015) — modern attacks
  - Proper 80/20 stratified train/test split (B2 fix)
  - Model versioning — backup before overwriting (B11 fix)
  - Master CSV rotation — cap at MAX_MASTER_ROWS (B10 fix)
  - Temporal features included in synthetic data (B5 fix)
  - Stricter label safety (B3 fix)

Usage:
  python scripts/train.py                  # auto-merge all sources
  python scripts/train.py --synthetic      # force synthetic only
  python scripts/train.py --no-unsw        # skip UNSW download
"""

import os
import sys
import glob
import shutil
import argparse
import numpy as np
import pandas as pd
import joblib
from datetime import datetime

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import (
    MODEL_PATH, FEATURE_COLS, ANOMALY_THRESHOLD, N_ESTIMATORS,
    PROCESSED_DIR, BASE_DIR, MASTER_DATA_PATH, USE_UNSW_DATASET,
    TEST_SPLIT_RATIO, MAX_MASTER_ROWS, MODEL_BACKUP_COUNT,
)

SYNTHETIC_PATH     = os.path.join(BASE_DIR, "data", "sample_dataset.csv")
PROCESSED_FEATURES = os.path.join(PROCESSED_DIR, "features.csv")
UNSW_CACHE_DIR     = os.path.join(BASE_DIR, "data", "unsw_cache")


# ─── Derived Feature Helper ──────────────────────────────────────────────────

def add_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute the 4 derived ratio features from the 7 base features.
    Call this on ANY DataFrame that has the base features.
    """
    safe_pkt  = df["packets_per_sec"].clip(lower=0.001)
    safe_conn = df["conn_rate"].clip(lower=0.01)

    df = df.copy()
    df["bytes_per_packet"] = (df["bytes_per_sec"]  / safe_pkt).clip(0, 2000).round(2)
    df["icmp_fraction"]    = (df["icmp_rate"]       / safe_pkt).clip(0, 1.0).round(4)
    df["syn_fraction"]     = (df["conn_rate"]       / safe_pkt).clip(0, 1.0).round(4)
    # Fix A: port_scan_ratio MUST be 0 when conn_rate is 0, just like in inference
    df["port_scan_ratio"]  = np.where(df["conn_rate"] > 0,
                                      (df["unique_ports"] / safe_conn).clip(0, 5000).round(2),
                                      0.0)
    return df


def add_zero_temporal_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add temporal features as zeros (no history during training)."""
    df = df.copy()
    df["delta_packets"]    = 0.0
    df["delta_ports"]      = 0.0
    df["burst_score"]      = 0.0
    df["port_accumulator"] = 0
    return df


# ─── Source 1: UNSW-NB15 (Modern Real Attack Dataset) ─────────────────────────

def load_unsw_dataset() -> pd.DataFrame:
    """
    Download and map UNSW-NB15 dataset to our feature space.

    UNSW-NB15 (2015, University of New South Wales) contains 9 modern
    attack categories: Fuzzers, Analysis, Backdoors, DoS, Exploits,
    Generic, Reconnaissance, Shellcode, Worms.

    We download the pre-processed CSV from the official research source
    and map the relevant columns to our 15-feature space.
    """
    print("[TRAIN] Loading UNSW-NB15 dataset...")

    os.makedirs(UNSW_CACHE_DIR, exist_ok=True)
    cache_file = os.path.join(UNSW_CACHE_DIR, "unsw_nb15_mapped.csv")

    # Use cached version if available
    if os.path.exists(cache_file):
        df = pd.read_csv(cache_file)
        normal_n = (df["label"] == 0).sum()
        attack_n = (df["label"] == 1).sum()
        print(f"[TRAIN] UNSW-NB15 loaded from cache: {normal_n} normal, {attack_n} attack")
        return df

    try:
        # UNSW-NB15 dataset (manually downloaded via Kaggle)
        urls = [
            os.path.join(UNSW_CACHE_DIR, "UNSW_NB15_training-set.csv"),
            os.path.join(UNSW_CACHE_DIR, "UNSW_NB15_testing-set.csv"),
        ]

        dfs = []
        for url in urls:
            print(f"[TRAIN] Downloading: {url.split('/')[-1]}...")
            try:
                chunk = pd.read_csv(url)
                dfs.append(chunk)
                print(f"[TRAIN]   -> {len(chunk)} records loaded")
            except Exception as e:
                print(f"[TRAIN]   -> Download failed: {e}")

        if not dfs:
            print("[TRAIN] All UNSW downloads failed. Falling back to synthetic.")
            return pd.DataFrame()

        raw = pd.concat(dfs, ignore_index=True)

        # ── UNSW-NB15 -> NetworkWarden Feature Mapping ────────────────────────
        # Key UNSW columns used:
        #   dur        -> flow duration (seconds)
        #   spkts      -> source-to-dest packet count
        #   dpkts      -> dest-to-source packet count
        #   sbytes     -> source bytes
        #   dbytes     -> dest bytes
        #   rate       -> packets per second (total)
        #   sport      -> source port number
        #   dsport     -> destination port number
        #   ct_dst_sport_ltm -> count of connections to same dst port (last 100)
        #   ct_src_dport_ltm -> count of connections from same src port
        #   proto      -> protocol (tcp, udp, icmp, etc.)
        #   state      -> connection state (FIN, RST, CON, etc.)
        #   attack_cat -> attack category or empty/Normal
        #   label      -> 0=normal, 1=attack

        dur       = raw.get("dur",    pd.Series(1.0, index=raw.index)).astype(float).clip(lower=0.01)
        sbytes    = raw.get("sbytes", pd.Series(0, index=raw.index)).astype(float)
        dbytes    = raw.get("dbytes", pd.Series(0, index=raw.index)).astype(float)
        spkts     = raw.get("spkts",  pd.Series(1, index=raw.index)).astype(float)
        dpkts     = raw.get("dpkts",  pd.Series(1, index=raw.index)).astype(float)
        rate      = raw.get("rate",   pd.Series(1, index=raw.index)).astype(float)
        proto     = raw.get("proto",  pd.Series("tcp", index=raw.index)).astype(str)
        state     = raw.get("state",  pd.Series("", index=raw.index)).astype(str)
        label_col = raw.get("label",  pd.Series(0, index=raw.index)).astype(int)

        # Proper packet and byte rates
        total_pkts  = (spkts + dpkts).clip(lower=1)
        total_bytes = (sbytes + dbytes).clip(lower=1)
        pkt_rate    = (total_pkts / dur).clip(0, 500)
        byte_rate   = (total_bytes / dur).clip(0, 1e6)

        # unique_ports: use ct_dst_sport_ltm as a PROXY for port diversity
        # For normal flows this is low (1-5), for scans it's higher
        # But cap it properly — it's a connection count, not a port count
        ct_dst_sp = raw.get("ct_dst_sport_ltm", pd.Series(1, index=raw.index)).astype(float)
        ct_src_dp = raw.get("ct_src_dport_ltm", pd.Series(1, index=raw.index)).astype(float)
        # Use the MAX of the two connection-count fields as port diversity estimate
        port_proxy = np.maximum(ct_dst_sp, ct_src_dp).clip(0, 1024).astype(int)

        # conn_rate: SYN-like connections per second
        # For TCP, spkts roughly correlates with connection attempts
        is_tcp = proto.str.lower().str.contains("tcp", na=False)
        syn_estimate = np.where(is_tcp, (spkts / dur).clip(0, 100), 0.0)

        # ICMP rate: only for ICMP protocol flows
        is_icmp = proto.str.lower().str.contains("icmp", na=False)
        icmp_rate = np.where(is_icmp, pkt_rate * 0.9, 0.0)

        # RST rate: derived from connection state containing RST
        has_rst = state.str.contains("RST", case=False, na=False)
        rst_rate = np.where(has_rst, (spkts / dur).clip(0, 50), 0.0)

        # rx_tx ratio
        rx_tx = (dbytes / (sbytes + 1)).clip(0, 100)

        mapped = pd.DataFrame({
            "packets_per_sec": pkt_rate,
            "bytes_per_sec":   byte_rate,
            "unique_ports":    port_proxy,
            "conn_rate":       syn_estimate,
            "icmp_rate":       icmp_rate,
            "rst_rate":        rst_rate,
            "rx_tx_ratio":     rx_tx,
            "label":           label_col.values,
        })

        # Add derived features
        mapped = add_derived_features(mapped)
        # Add zero temporal features (no history for static dataset)
        mapped = add_zero_temporal_features(mapped)

        # Downsample for Pi-friendly training
        normal = mapped[mapped["label"] == 0]
        attack = mapped[mapped["label"] == 1]
        n_normal = min(5000, len(normal))
        n_attack = min(2000, len(attack))

        sampled = pd.concat([
            normal.sample(n=n_normal, random_state=42),
            attack.sample(n=n_attack, random_state=42),
        ], ignore_index=True)

        # Cache for next time
        sampled.to_csv(cache_file, index=False)

        normal_n = (sampled["label"] == 0).sum()
        attack_n = (sampled["label"] == 1).sum()
        print(f"[TRAIN] UNSW-NB15 mapped: {normal_n} normal, {attack_n} attack records")
        return sampled

    except Exception as e:
        print(f"[TRAIN] UNSW-NB15 load failed: {e}")
        print("[TRAIN] Falling back to synthetic data only.")
        return pd.DataFrame()


# ─── Source 2: Synthetic Data ─────────────────────────────────────────────────

def generate_synthetic_dataset(n_normal: int = 2000,
                                n_anomaly: int = 1200,
                                save: bool = True) -> pd.DataFrame:
    """Generate synthetic normal + attack traffic with all 15 features."""
    rng = np.random.default_rng(42)
    n6  = n_anomaly // 6   # 6 attack types

    # ── Normal traffic — 3 realistic subtypes ───────────────────────────────
    # Real home networks have VERY different traffic profiles per device.
    # The model MUST see all of these or it flags idle devices as anomalous.

    n_active    = n_normal // 3       # browsing, downloads, general use
    n_idle      = n_normal // 3       # idle devices — exact zeros everywhere
    n_streaming = n_normal - n_active - n_idle  # streaming, video calls

    # Subtype A: Active normal (web browsing, downloads, some TCP SYN)
    active = pd.DataFrame({
        "packets_per_sec": rng.normal(15,   12,   n_active).clip(0.1),
        "bytes_per_sec":   rng.normal(8000, 6000, n_active).clip(100),
        "unique_ports":    rng.integers(1,  15,   n_active),
        "conn_rate":       rng.normal(0.8,  0.5,  n_active).clip(0.01),
        "icmp_rate":       rng.normal(0.05, 0.02, n_active).clip(0),
        "rst_rate":        rng.normal(0.05, 0.02, n_active).clip(0),
        "rx_tx_ratio":     rng.normal(1.2,  0.3,  n_active).clip(0.1),
        "label": 0,
    })

    # Subtype B: Idle normal (smart TV off, phone sleeping, IoT standby)
    # These have EXACT ZEROS — no TCP SYN, no ICMP, no RST
    idle = pd.DataFrame({
        "packets_per_sec": rng.normal(3,    5,    n_idle).clip(0.1),
        "bytes_per_sec":   rng.normal(1500, 2000, n_idle).clip(50),
        "unique_ports":    rng.integers(0,  3,    n_idle),
        "conn_rate":       np.zeros(n_idle),           # exact zero — no SYN
        "icmp_rate":       np.zeros(n_idle),            # exact zero — no ICMP
        "rst_rate":        np.zeros(n_idle),             # exact zero — no RST
        "rx_tx_ratio":     rng.normal(1.5,  1.0,  n_idle).clip(0.1),
        "label": 0,
    })

    # Subtype C: Streaming normal (Netflix, YouTube, video calls)
    # High bytes, moderate packets, zero SYN (already-established TCP)
    streaming = pd.DataFrame({
        "packets_per_sec": rng.normal(30,   15,    n_streaming).clip(1),
        "bytes_per_sec":   rng.normal(25000, 15000, n_streaming).clip(500),
        "unique_ports":    rng.integers(1,  4,     n_streaming),
        "conn_rate":       rng.normal(0.1,  0.1,   n_streaming).clip(0),
        "icmp_rate":       np.zeros(n_streaming),
        "rst_rate":        rng.normal(0.01, 0.01,  n_streaming).clip(0),
        "rx_tx_ratio":     rng.normal(3.0,  2.0,   n_streaming).clip(0.5),
        "label": 0,
    })

    normal = pd.concat([active, idle, streaming], ignore_index=True)

    # ── Port Scan ─────────────────────────────────────────────────────────────
    port_scan = pd.DataFrame({
        "packets_per_sec": rng.normal(90,   15,   n6).clip(10),
        "bytes_per_sec":   rng.normal(5400, 800,  n6).clip(100),
        "unique_ports":    rng.integers(200, 1024, n6),
        "conn_rate":       rng.normal(28,   5,    n6).clip(1),
        "icmp_rate":       rng.normal(0.05, 0.02, n6).clip(0),
        "rst_rate":        rng.normal(22,   4,    n6).clip(2),
        "rx_tx_ratio":     rng.normal(0.6,  0.15, n6).clip(0.01),
        "label": 1,
    })

    # ── Ping Flood ────────────────────────────────────────────────────────────
    ping_flood = pd.DataFrame({
        "packets_per_sec": rng.normal(250,  50,   n6).clip(20),
        "bytes_per_sec":   rng.normal(8000, 1500, n6).clip(100),
        "unique_ports":    rng.integers(0,  2,    n6),
        "conn_rate":       rng.normal(0.05, 0.02, n6).clip(0),
        "icmp_rate":       rng.normal(230,  40,   n6).clip(10),
        "rst_rate":        rng.normal(0.02, 0.01, n6).clip(0),
        "rx_tx_ratio":     rng.normal(0.4,  0.1,  n6).clip(0.01),
        "label": 1,
    })

    # ── SYN Flood ─────────────────────────────────────────────────────────────
    syn_flood = pd.DataFrame({
        "packets_per_sec": rng.normal(80,   15,   n6).clip(10),
        "bytes_per_sec":   rng.normal(4800, 800,  n6).clip(100),
        "unique_ports":    rng.integers(1,  3,    n6),
        "conn_rate":       rng.normal(60,   10,   n6).clip(5),
        "icmp_rate":       rng.normal(0.02, 0.01, n6).clip(0),
        "rst_rate":        rng.normal(0.4,  0.2,  n6).clip(0),
        "rx_tx_ratio":     rng.normal(0.9,  0.15, n6).clip(0.01),
        "label": 1,
    })

    # ── Data Exfiltration ─────────────────────────────────────────────────────
    exfil = pd.DataFrame({
        "packets_per_sec": rng.normal(35,    8,     n6).clip(5),
        "bytes_per_sec":   rng.normal(60000, 10000, n6).clip(1000),
        "unique_ports":    rng.integers(1,   3,     n6),
        "conn_rate":       rng.normal(0.3,   0.1,   n6).clip(0.01),
        "icmp_rate":       rng.normal(0.01,  0.005, n6).clip(0),
        "rst_rate":        rng.normal(0.02,  0.01,  n6).clip(0),
        "rx_tx_ratio":     rng.normal(0.01,  0.005, n6).clip(0.001),
        "label": 1,
    })

    # ── UDP Flood ─────────────────────────────────────────────────────────────
    udp_flood = pd.DataFrame({
        "packets_per_sec": rng.normal(60,   12,    n6).clip(10),
        "bytes_per_sec":   rng.normal(70000, 8000, n6).clip(5000),
        "unique_ports":    rng.integers(1,   4,    n6),
        "conn_rate":       rng.normal(0.5,   0.2,  n6).clip(0.01),
        "icmp_rate":       rng.normal(0.01,  0.01, n6).clip(0),
        "rst_rate":        rng.normal(0.02,  0.01, n6).clip(0),
        "rx_tx_ratio":     rng.normal(0.8,   0.15, n6).clip(0.01),
        "label": 1,
    })

    # ── Brute Force (Fix C) ───────────────────────────────────────────────────
    brute_force = pd.DataFrame({
        "packets_per_sec": rng.normal(40,   10,   n6).clip(5),
        "bytes_per_sec":   rng.normal(3000, 500,  n6).clip(100),
        "unique_ports":    rng.integers(1,  3,    n6),
        "conn_rate":       rng.normal(15,   5,    n6).clip(2),
        "icmp_rate":       rng.normal(0.01, 0.01, n6).clip(0),
        "rst_rate":        rng.normal(2,    1,    n6).clip(0),
        "rx_tx_ratio":     rng.normal(0.8,  0.2,  n6).clip(0.01),
        "label": 1,
    })

    dataset = pd.concat([normal, port_scan, ping_flood, syn_flood, exfil, udp_flood, brute_force],
                         ignore_index=True)
    dataset = dataset.sample(frac=1, random_state=42).reset_index(drop=True)

    # Compute derived features
    dataset = add_derived_features(dataset)
    # Add zero temporal features (synthetic data has no history)
    dataset = add_zero_temporal_features(dataset)

    if save:
        os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)
        dataset.to_csv(SYNTHETIC_PATH, index=False)

    return dataset


# ─── Source 3+4: Real Collected + Persistent Master ──────────────────────────

def load_collected_data() -> pd.DataFrame:
    """Load real traffic collected by collector.py, if any."""
    if os.path.exists(PROCESSED_FEATURES):
        df = pd.read_csv(PROCESSED_FEATURES)
        # Collected data has no labels — treat all as normal (label=0)
        df["label"] = 0
        # Keep only feature columns + label
        cols = [c for c in FEATURE_COLS if c in df.columns] + ["label"]
        df = df[cols]
        # Add any missing temporal columns
        for tc in ["delta_packets", "delta_ports", "burst_score", "port_accumulator"]:
            if tc not in df.columns:
                df[tc] = 0.0
        print(f"[TRAIN] Collected real data: {len(df)} records")
        return df
    return pd.DataFrame()


def load_master_data() -> pd.DataFrame:
    """Load the persistent master training CSV (union of all past runs)."""
    if os.path.exists(MASTER_DATA_PATH):
        df = pd.read_csv(MASTER_DATA_PATH)
        # Add any missing temporal columns (backward compat with old master data)
        for tc in ["delta_packets", "delta_ports", "burst_score", "port_accumulator"]:
            if tc not in df.columns:
                df[tc] = 0.0
        print(f"[TRAIN] Master training store: {len(df)} records")
        return df
    return pd.DataFrame()


def save_master_data(df: pd.DataFrame):
    """
    Save data to the persistent master training CSV.
    Caps at MAX_MASTER_ROWS to prevent unbounded growth (B10 fix).
    """
    os.makedirs(os.path.dirname(MASTER_DATA_PATH), exist_ok=True)

    if os.path.exists(MASTER_DATA_PATH):
        existing = pd.read_csv(MASTER_DATA_PATH)
        combined = pd.concat([existing, df], ignore_index=True).drop_duplicates()
    else:
        combined = df

    # ── CSV Rotation (B10 fix) ────────────────────────────────────────────────
    if len(combined) > MAX_MASTER_ROWS:
        print(f"[TRAIN] Master CSV rotation: {len(combined)} -> {MAX_MASTER_ROWS} rows (keeping most recent)")
        combined = combined.tail(MAX_MASTER_ROWS)

    combined.to_csv(MASTER_DATA_PATH, index=False)
    print(f"[TRAIN] Master store updated: {len(combined)} total records")


# ─── Model Versioning (B11 fix) ──────────────────────────────────────────────

def backup_model():
    """Backup the current model before overwriting."""
    if not os.path.exists(MODEL_PATH):
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{MODEL_PATH}.{timestamp}.bak"
    shutil.copy2(MODEL_PATH, backup_path)
    print(f"[TRAIN] Model backed up -> {backup_path}")

    # Clean old backups, keep only MODEL_BACKUP_COUNT most recent
    model_dir = os.path.dirname(MODEL_PATH)
    backups = sorted(glob.glob(os.path.join(model_dir, "model.pkl.*.bak")))
    while len(backups) > MODEL_BACKUP_COUNT:
        oldest = backups.pop(0)
        os.remove(oldest)
        print(f"[TRAIN] Removed old backup: {os.path.basename(oldest)}")


# ─── Data Assembler ───────────────────────────────────────────────────────────

def assemble_training_data(use_unsw: bool = True) -> pd.DataFrame:
    """
    Merge all data sources into one training DataFrame:
      UNSW-NB15 + Synthetic + Collected real data + Master store
    """
    sources = []

    # 1. UNSW-NB15 (real, labeled, modern)
    if use_unsw:
        unsw = load_unsw_dataset()
        if not unsw.empty:
            sources.append(unsw)

    # 2. Synthetic (always included as fallback / diversity)
    synthetic = generate_synthetic_dataset(save=True)
    sources.append(synthetic[FEATURE_COLS + ["label"]])

    # 3. Real collected traffic
    collected = load_collected_data()
    if not collected.empty:
        sources.append(collected)

    # 4. Persistent master store (all previous training runs)
    master = load_master_data()
    if not master.empty:
        cols = [c for c in FEATURE_COLS + ["label"] if c in master.columns]
        sources.append(master[cols])

    combined = pd.concat(sources, ignore_index=True)
    combined = combined.dropna(subset=FEATURE_COLS)

    # Ensure all feature columns exist with defaults
    for col in FEATURE_COLS:
        if col not in combined.columns:
            combined[col] = 0.0

    # Save everything back into master store (with rotation)
    save_master_data(combined[FEATURE_COLS + ["label"]])

    normal_n = (combined["label"] == 0).sum()
    attack_n = (combined["label"] == 1).sum()
    print(f"[TRAIN] Total training data: {normal_n} normal, {attack_n} attack records")
    return combined


# ─── Model Training ───────────────────────────────────────────────────────────

def train_model(use_unsw: bool = True) -> Pipeline:
    """
    Train the Random Forest on merged data from all sources.
    Uses proper train/test split for honest validation (B2 fix).
    Backs up old model before saving (B11 fix).
    """
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    df = assemble_training_data(use_unsw=use_unsw)

    X_all = df[FEATURE_COLS].values
    y_all = df["label"].values

    # ── Proper Train/Test Split (B2 fix) ──────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X_all, y_all,
        test_size=TEST_SPLIT_RATIO,
        stratify=y_all,
        random_state=42
    )

    print(f"[TRAIN] Train set: {len(X_train)} samples  |  Test set: {len(X_test)} samples")
    print(f"[TRAIN] Fitting Random Forest ({N_ESTIMATORS} trees)...")

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(
            n_estimators  = N_ESTIMATORS,
            max_depth     = 10,
            random_state  = 42,
            n_jobs        = -1,
            class_weight  = "balanced"
        ))
    ])

    model.fit(X_train, y_train)

    # ── Validation on UNSEEN test data (B2 fix) ──────────────────────────────
    probs_test = model.predict_proba(X_test)[:, 1]
    preds_test = (probs_test > ANOMALY_THRESHOLD).astype(int)

    print("\n[TRAIN] === Validation Report (on UNSEEN test data) ===")
    print(classification_report(y_test, preds_test,
                                 target_names=["Normal", "Anomaly"],
                                 zero_division=0))

    # Also show training accuracy for reference
    probs_train = model.predict_proba(X_train)[:, 1]
    preds_train = (probs_train > ANOMALY_THRESHOLD).astype(int)
    print("[TRAIN] === Training Report (for reference only) ===")
    print(classification_report(y_train, preds_train,
                                 target_names=["Normal", "Anomaly"],
                                 zero_division=0))

    # ── Backup old model (B11 fix) ───────────────────────────────────────────
    backup_model()

    # ── Save new model ────────────────────────────────────────────────────────
    joblib.dump(model, MODEL_PATH, compress=3)
    size_kb = os.path.getsize(MODEL_PATH) / 1024
    print(f"[TRAIN] Model saved -> {MODEL_PATH} ({size_kb:.1f} KB)")

    return model


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WiFi Guardian — Train Model")
    parser.add_argument("--synthetic", action="store_true",
                        help="Use synthetic data only (no UNSW download)")
    parser.add_argument("--no-unsw",   action="store_true",
                        help="Skip UNSW-NB15 dataset")
    args = parser.parse_args()

    use_unsw = USE_UNSW_DATASET and not args.synthetic and not args.no_unsw
    train_model(use_unsw=use_unsw)
