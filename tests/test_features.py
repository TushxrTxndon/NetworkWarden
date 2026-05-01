#!/usr/bin/env python3
"""Unit tests for WiFi Guardian feature extraction."""

import os
import sys
import unittest
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from scripts.features import extract_features, get_feature_vector


class TestExtractFeatures(unittest.TestCase):
    """Test feature extraction math."""

    def setUp(self):
        self.normal_record = {
            "ip": "192.168.1.10",
            "mac": "aa:bb:cc:dd:ee:ff",
            "timestamp": "2024-01-01T00:00:00",
            "window_sec": 30,
            "packets_in": 100,
            "packets_out": 80,
            "bytes_in": 50000,
            "bytes_out": 40000,
            "unique_ports": 3,
            "conn_attempts": 5,
            "icmp_count": 1,
            "rst_count": 0,
        }

    def test_basic_rates(self):
        feat = extract_features(self.normal_record)
        self.assertAlmostEqual(feat["packets_per_sec"], 6.0, places=2)
        self.assertAlmostEqual(feat["bytes_per_sec"], 3000.0, places=2)
        self.assertEqual(feat["unique_ports"], 3)
        self.assertAlmostEqual(feat["conn_rate"], 5 / 30, places=3)
        self.assertAlmostEqual(feat["icmp_rate"], 1 / 30, places=3)
        self.assertAlmostEqual(feat["rst_rate"], 0.0, places=3)

    def test_rx_tx_ratio(self):
        feat = extract_features(self.normal_record)
        self.assertAlmostEqual(feat["rx_tx_ratio"], 50000 / 40000, places=3)

    def test_derived_features(self):
        feat = extract_features(self.normal_record)
        self.assertGreater(feat["bytes_per_packet"], 0)
        self.assertGreaterEqual(feat["icmp_fraction"], 0)
        self.assertLessEqual(feat["icmp_fraction"], 1.0)
        self.assertGreaterEqual(feat["syn_fraction"], 0)
        self.assertLessEqual(feat["syn_fraction"], 1.0)
        self.assertGreater(feat["port_scan_ratio"], 0)

    def test_temporal_defaults_to_zero(self):
        """Without temporal input, temporal features should be zero."""
        feat = extract_features(self.normal_record)
        self.assertEqual(feat["delta_packets"], 0.0)
        self.assertEqual(feat["delta_ports"], 0.0)
        self.assertEqual(feat["burst_score"], 0.0)
        self.assertEqual(feat["port_accumulator"], 0)

    def test_temporal_injection(self):
        """Temporal features should be injected when provided."""
        temporal = {
            "delta_packets": 5.5,
            "delta_ports": 3.0,
            "burst_score": 0.4,
            "port_accumulator": 20,
        }
        feat = extract_features(self.normal_record, temporal=temporal)
        self.assertAlmostEqual(feat["delta_packets"], 5.5, places=3)
        self.assertAlmostEqual(feat["delta_ports"], 3.0, places=3)
        self.assertAlmostEqual(feat["burst_score"], 0.4, places=3)
        self.assertEqual(feat["port_accumulator"], 20)

    def test_zero_traffic(self):
        """Should handle zero traffic without division errors."""
        zero_record = {
            "window_sec": 30,
            "packets_in": 0, "packets_out": 0,
            "bytes_in": 0, "bytes_out": 0,
            "unique_ports": 0, "conn_attempts": 0,
            "icmp_count": 0, "rst_count": 0,
        }
        feat = extract_features(zero_record)
        self.assertIsNotNone(feat)
        self.assertEqual(feat["packets_per_sec"], 0.0)

    def test_metadata_preserved(self):
        feat = extract_features(self.normal_record)
        self.assertEqual(feat["ip"], "192.168.1.10")
        self.assertEqual(feat["mac"], "aa:bb:cc:dd:ee:ff")

    def test_feature_vector_shape(self):
        """get_feature_vector should return correct shape."""
        from config import FEATURE_COLS
        vec = get_feature_vector(self.normal_record)
        self.assertEqual(vec.shape, (1, len(FEATURE_COLS)))
        self.assertEqual(vec.dtype, np.float32)

    def test_window_clamp(self):
        """Window of 0 should be clamped to 1 to avoid division by zero."""
        bad_record = dict(self.normal_record)
        bad_record["window_sec"] = 0
        feat = extract_features(bad_record)
        self.assertIsNotNone(feat)
        self.assertGreater(feat["packets_per_sec"], 0)


if __name__ == "__main__":
    unittest.main()
