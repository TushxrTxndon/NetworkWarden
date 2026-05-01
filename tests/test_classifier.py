#!/usr/bin/env python3
"""Unit tests for WiFi Guardian attack classifier."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from scripts.classifier import classify_attack, classify_arp_spoof


class TestClassifier(unittest.TestCase):
    """Test that each attack pattern is correctly classified."""

    def _base_feat(self, **overrides):
        """Return a baseline normal feature dict with overrides."""
        feat = {
            "packets_per_sec": 5.0, "bytes_per_sec": 2000,
            "unique_ports": 3, "conn_rate": 0.2, "icmp_rate": 0.05,
            "rst_rate": 0.05, "rx_tx_ratio": 1.2,
            "bytes_per_packet": 400, "icmp_fraction": 0.01,
            "syn_fraction": 0.04, "port_scan_ratio": 15.0,
            "delta_packets": 0, "delta_ports": 0,
            "burst_score": 0, "port_accumulator": 0,
            "window_sec": 30,
        }
        feat.update(overrides)
        return feat

    def test_ping_flood(self):
        feat = self._base_feat(
            packets_per_sec=250, bytes_per_sec=8000,
            icmp_rate=230, icmp_fraction=0.92,
            bytes_per_packet=32, syn_fraction=0.0,
        )
        result = classify_attack(feat)
        self.assertIn("Ping Flood", result.name)
        self.assertIn(result.confidence, ("High", "Critical"))

    def test_syn_flood(self):
        feat = self._base_feat(
            packets_per_sec=80, bytes_per_sec=5000, unique_ports=2,
            conn_rate=60, rst_rate=0.4,
            syn_fraction=0.75, icmp_fraction=0.0,
            bytes_per_packet=62, port_scan_ratio=0.03,
        )
        result = classify_attack(feat)
        self.assertIn("SYN Flood", result.name)

    def test_port_scan(self):
        feat = self._base_feat(
            packets_per_sec=90, bytes_per_sec=5400, unique_ports=847,
            conn_rate=28, rst_rate=22.0,
            syn_fraction=0.31, port_scan_ratio=30.2,
            icmp_fraction=0.001, bytes_per_packet=60,
        )
        result = classify_attack(feat)
        self.assertIn("Port Scan", result.name)

    def test_brute_force(self):
        feat = self._base_feat(
            packets_per_sec=20, bytes_per_sec=1200, unique_ports=1,
            conn_rate=8, rst_rate=1.5,
            syn_fraction=0.4, icmp_fraction=0.0,
            bytes_per_packet=60, port_scan_ratio=0.12,
        )
        result = classify_attack(feat)
        self.assertIn("Brute Force", result.name)

    def test_data_exfil(self):
        feat = self._base_feat(
            packets_per_sec=30, bytes_per_sec=55000, unique_ports=1,
            conn_rate=0.3, rx_tx_ratio=0.01,
            bytes_per_packet=1833, icmp_fraction=0.0,
            syn_fraction=0.01, port_scan_ratio=3.3,
        )
        result = classify_attack(feat)
        self.assertIn("Exfiltration", result.name)

    def test_udp_flood(self):
        feat = self._base_feat(
            packets_per_sec=60, bytes_per_sec=70000, unique_ports=3,
            conn_rate=0.5, bytes_per_packet=1166,
            icmp_fraction=0.0, syn_fraction=0.008,
            port_scan_ratio=6.0,
        )
        result = classify_attack(feat)
        self.assertIn("UDP", result.name)

    def test_slow_scan(self):
        feat = self._base_feat(
            unique_ports=5, port_accumulator=25,
            packets_per_sec=6, conn_rate=1.0,
            burst_score=0.2, delta_ports=2,
        )
        result = classify_attack(feat)
        self.assertIn("Slow", result.name)

    def test_recon(self):
        feat = self._base_feat(
            unique_ports=16, conn_rate=1.2, rst_rate=2.0,
            port_scan_ratio=12.5, syn_fraction=0.2,
            bytes_per_packet=150, icmp_fraction=0.0,
        )
        result = classify_attack(feat)
        self.assertIn("Reconnaissance", result.name)

    def test_unknown(self):
        feat = self._base_feat(
            unique_ports=3, bytes_per_sec=4000,
            packets_per_sec=15, conn_rate=0.3,
            bytes_per_packet=266, port_scan_ratio=10.0,
        )
        result = classify_attack(feat)
        self.assertIn("Unknown", result.name)

    def test_escalation_boosts_confidence(self):
        """is_escalated=True should boost confidence level."""
        feat = self._base_feat(
            unique_ports=15, conn_rate=1.2, rst_rate=2.0,
            port_scan_ratio=12.5, syn_fraction=0.2,
        )
        normal_result = classify_attack(feat, is_escalated=False)
        escalated_result = classify_attack(feat, is_escalated=True)
        # Escalated confidence should be >= non-escalated
        conf_order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
        self.assertGreaterEqual(
            conf_order.get(escalated_result.confidence, 0),
            conf_order.get(normal_result.confidence, 0)
        )

    def test_arp_spoof(self):
        spoof = {
            "ip": "192.168.1.5",
            "old_mac": "aa:bb:cc:dd:ee:ff",
            "new_mac": "11:22:33:44:55:66",
            "time": "2024-01-01T00:00:00",
        }
        result = classify_arp_spoof(spoof)
        self.assertIn("ARP", result.name)
        self.assertEqual(result.confidence, "Critical")
        self.assertEqual(result.severity, "CRITICAL")
        self.assertEqual(result.mitre_code, "T1557.002")

    def test_all_results_have_mitre(self):
        """Every attack classification should have a MITRE ATT&CK code."""
        feat = self._base_feat(
            packets_per_sec=250, icmp_rate=230, icmp_fraction=0.92,
        )
        result = classify_attack(feat)
        self.assertTrue(result.mitre_code, "MITRE code should not be empty")
        self.assertTrue(result.mitre_name, "MITRE name should not be empty")

    def test_severity_field(self):
        """Every result should have a valid severity."""
        feat = self._base_feat(
            packets_per_sec=250, icmp_rate=230, icmp_fraction=0.92,
        )
        result = classify_attack(feat)
        self.assertIn(result.severity, ("INFO", "WARNING", "CRITICAL"))


if __name__ == "__main__":
    unittest.main()
