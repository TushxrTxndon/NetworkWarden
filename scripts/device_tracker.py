#!/usr/bin/env python3
"""
WiFi Guardian — Device Tracker (NEW)

Provides three critical capabilities:
  1. Per-device baseline tracking   (rolling mean/std per IP)
  2. Sliding-window temporal history (last N cycles per device)
  3. ARP binding tracker            (IP↔MAC spoof detection)
  4. Cumulative anomaly scoring     (escalate after N suspicious cycles)

All state is in-memory (lost on restart). This is intentional —
baselines should rebuild naturally from live traffic, not persist
stale state from weeks ago.

Usage:
  from scripts.device_tracker import DeviceTracker
  tracker = DeviceTracker()
"""

import os
import sys
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import (
    TEMPORAL_WINDOW_CYCLES,
    CUMULATIVE_ANOMALY_THRESHOLD,
    SLOW_SCAN_PORT_THRESHOLD,
    BASELINE_MIN_SAMPLES,
    BASELINE_DEVIATION_MULT,
    ARP_SPOOF_DETECTION,
)

log = logging.getLogger("DEVICE_TRACKER")


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class DeviceBaseline:
    """Rolling statistics for a single device."""
    sample_count: int = 0
    # Running sums for online mean/variance (Welford's algorithm)
    mean_packets:  float = 0.0
    mean_bytes:    float = 0.0
    mean_ports:    float = 0.0
    mean_conn:     float = 0.0
    mean_icmp:     float = 0.0
    mean_rst:      float = 0.0
    # Running variance (M2 in Welford's)
    m2_packets:    float = 0.0
    m2_bytes:      float = 0.0
    m2_ports:      float = 0.0
    m2_conn:       float = 0.0
    m2_icmp:       float = 0.0
    m2_rst:        float = 0.0

    @property
    def is_trusted(self) -> bool:
        """Baseline needs enough samples to be meaningful."""
        return self.sample_count >= BASELINE_MIN_SAMPLES

    def update(self, feat: dict):
        """Update running statistics with a new observation (Welford's online algorithm)."""
        self.sample_count += 1
        n = self.sample_count

        for attr, key in [
            ("packets", "packets_per_sec"),
            ("bytes",   "bytes_per_sec"),
            ("ports",   "unique_ports"),
            ("conn",    "conn_rate"),
            ("icmp",    "icmp_rate"),
            ("rst",     "rst_rate"),
        ]:
            val   = float(feat.get(key, 0))
            mean  = getattr(self, f"mean_{attr}")
            m2    = getattr(self, f"m2_{attr}")
            delta = val - mean
            mean += delta / n
            delta2 = val - mean
            m2   += delta * delta2
            setattr(self, f"mean_{attr}", mean)
            setattr(self, f"m2_{attr}", m2)

    def get_std(self, attr: str) -> float:
        """Get standard deviation for a given attribute."""
        if self.sample_count < 2:
            return 0.0
        m2 = getattr(self, f"m2_{attr}", 0.0)
        return (m2 / (self.sample_count - 1)) ** 0.5

    def get_z_score(self, attr: str, value: float) -> float:
        """How many standard deviations is `value` from the mean?"""
        mean = getattr(self, f"mean_{attr}", 0.0)
        std  = self.get_std(attr)
        if std < 0.001:
            return 0.0
        return abs(value - mean) / std


@dataclass
class DeviceHistory:
    """Sliding window of recent cycle results for temporal analysis."""
    # Store last N feature snapshots
    feature_history: deque = field(default_factory=lambda: deque(maxlen=TEMPORAL_WINDOW_CYCLES))
    # Track anomaly flags for cumulative scoring
    anomaly_flags:   deque = field(default_factory=lambda: deque(maxlen=TEMPORAL_WINDOW_CYCLES))
    # Track all unique ports seen across the window
    port_sets:       deque = field(default_factory=lambda: deque(maxlen=TEMPORAL_WINDOW_CYCLES))

    def add_cycle(self, feat: dict, was_anomaly: bool):
        """Record one cycle's results."""
        self.feature_history.append(feat)
        self.anomaly_flags.append(was_anomaly)
        self.port_sets.append(int(feat.get("unique_ports", 0)))

    @property
    def burst_score(self) -> float:
        """Fraction of recent cycles that were flagged as anomalous (0.0–1.0)."""
        if not self.anomaly_flags:
            return 0.0
        return sum(self.anomaly_flags) / len(self.anomaly_flags)

    @property
    def port_accumulator(self) -> int:
        """Total unique ports seen across all cycles in the window."""
        return sum(self.port_sets)

    @property
    def consecutive_anomalies(self) -> int:
        """Count of consecutive anomaly flags from the most recent cycle backward."""
        count = 0
        for flag in reversed(self.anomaly_flags):
            if flag:
                count += 1
            else:
                break
        return count

    def get_delta(self, key: str, current_value: float) -> float:
        """Change in a feature vs the previous cycle."""
        if len(self.feature_history) < 1:
            return 0.0
        prev = float(self.feature_history[-1].get(key, 0))
        return current_value - prev

    @property
    def is_slow_scan(self) -> bool:
        """Detect slow/stealthy port scan across multiple cycles."""
        # Only trigger if actively scanning this cycle
        if not self.port_sets or self.port_sets[-1] <= 0:
            return False
            
        # If any recent cycle had > 20 ports, it was a fast scan, so don't echo as a "slow" scan
        if any(p > 20 for p in self.port_sets):
            return False
            
        return self.port_accumulator >= SLOW_SCAN_PORT_THRESHOLD

    @property
    def should_escalate(self) -> bool:
        """Should we escalate alert severity due to sustained suspicious activity?"""
        return self.consecutive_anomalies >= CUMULATIVE_ANOMALY_THRESHOLD


# ─── Main Tracker ─────────────────────────────────────────────────────────────

class DeviceTracker:
    """
    Central tracker for all per-device state.

    Thread-safe: NO (single-threaded inference loop is fine).
    Persistent: NO (rebuilds on restart — intentional design choice).
    """

    def __init__(self):
        self.baselines:    dict[str, DeviceBaseline] = defaultdict(DeviceBaseline)
        self.histories:    dict[str, DeviceHistory]  = defaultdict(DeviceHistory)
        self.arp_bindings: dict[str, str]            = {}  # ip -> mac
        self.arp_alerts:   list = []  # pending ARP spoof alerts

    # ─── Baseline Management ──────────────────────────────────────────────────

    def update_baseline(self, ip: str, feat: dict):
        """Update the rolling baseline for a device (only call for NORMAL traffic)."""
        self.baselines[ip].update(feat)

    def get_baseline(self, ip: str) -> Optional[DeviceBaseline]:
        """Get baseline for a device, or None if not yet trusted."""
        bl = self.baselines.get(ip)
        if bl and bl.is_trusted:
            return bl
        return None

    def get_deviation_scores(self, ip: str, feat: dict) -> dict:
        """
        Compute z-scores for each base feature against this device's baseline.
        Returns empty dict if baseline is not yet trusted.
        """
        bl = self.get_baseline(ip)
        if not bl:
            return {}

        return {
            "z_packets": bl.get_z_score("packets", float(feat.get("packets_per_sec", 0))),
            "z_bytes":   bl.get_z_score("bytes",   float(feat.get("bytes_per_sec", 0))),
            "z_ports":   bl.get_z_score("ports",   float(feat.get("unique_ports", 0))),
            "z_conn":    bl.get_z_score("conn",    float(feat.get("conn_rate", 0))),
            "z_icmp":    bl.get_z_score("icmp",    float(feat.get("icmp_rate", 0))),
            "z_rst":     bl.get_z_score("rst",     float(feat.get("rst_rate", 0))),
        }

    # ─── Temporal History ─────────────────────────────────────────────────────

    def record_cycle(self, ip: str, feat: dict, was_anomaly: bool):
        """Record this cycle's result into the sliding window for temporal analysis."""
        self.histories[ip].add_cycle(feat, was_anomaly)

    def get_temporal_features(self, ip: str, feat: dict) -> dict:
        """
        Compute temporal features for a device based on its recent history.
        These are fed into the model as additional input features.
        """
        history = self.histories.get(ip)
        if not history:
            return {
                "delta_packets":    0.0,
                "delta_ports":      0.0,
                "burst_score":      0.0,
                "port_accumulator": 0,
            }

        return {
            "delta_packets":    round(history.get_delta("packets_per_sec",
                                                         float(feat.get("packets_per_sec", 0))), 4),
            "delta_ports":      round(history.get_delta("unique_ports",
                                                         float(feat.get("unique_ports", 0))), 4),
            "burst_score":      round(history.burst_score, 4),
            "port_accumulator": history.port_accumulator,
        }

    def is_slow_scan(self, ip: str) -> bool:
        """Check if this device is doing a slow/stealthy port scan across cycles."""
        history = self.histories.get(ip)
        return history.is_slow_scan if history else False

    def should_escalate(self, ip: str) -> bool:
        """Check if this device has been suspicious for too many consecutive cycles."""
        history = self.histories.get(ip)
        return history.should_escalate if history else False

    # ─── ARP Spoof Detection ─────────────────────────────────────────────────

    def check_arp_bindings(self, devices: dict) -> list:
        """
        Check for ARP spoofing: IP appearing with a different MAC than previously seen.

        Args:
            devices: {ip: mac} dict from ARP scan

        Returns:
            List of spoof alert dicts: [{"ip": ..., "old_mac": ..., "new_mac": ...}]
        """
        if not ARP_SPOOF_DETECTION:
            return []

        alerts = []
        for ip, mac in devices.items():
            mac = mac.lower()
            if ip in self.arp_bindings:
                if self.arp_bindings[ip] != mac:
                    alert = {
                        "ip":      ip,
                        "old_mac": self.arp_bindings[ip],
                        "new_mac": mac,
                        "time":    datetime.now().isoformat(),
                    }
                    alerts.append(alert)
                    log.warning(
                        f"ARP SPOOF DETECTED: {ip} changed MAC "
                        f"{self.arp_bindings[ip]} → {mac}"
                    )
            self.arp_bindings[ip] = mac

        return alerts

    # ─── Summary ──────────────────────────────────────────────────────────────

    def get_device_count(self) -> int:
        """Number of unique devices tracked."""
        return len(set(list(self.baselines.keys()) + list(self.histories.keys())))

    def get_baseline_count(self) -> int:
        """Number of devices with trusted baselines."""
        return sum(1 for bl in self.baselines.values() if bl.is_trusted)
