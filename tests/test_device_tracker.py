#!/usr/bin/env python3
"""Unit tests for WiFi Guardian DeviceTracker."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from scripts.device_tracker import DeviceTracker, DeviceBaseline, DeviceHistory


class TestDeviceBaseline(unittest.TestCase):
    """Test per-device rolling statistics (Welford's algorithm)."""

    def test_initial_state(self):
        bl = DeviceBaseline()
        self.assertEqual(bl.sample_count, 0)
        self.assertFalse(bl.is_trusted)

    def test_single_update(self):
        bl = DeviceBaseline()
        bl.update({"packets_per_sec": 10.0, "bytes_per_sec": 5000.0,
                    "unique_ports": 3, "conn_rate": 0.5,
                    "icmp_rate": 0.1, "rst_rate": 0.05})
        self.assertEqual(bl.sample_count, 1)
        self.assertAlmostEqual(bl.mean_packets, 10.0)

    def test_trusted_after_min_samples(self):
        bl = DeviceBaseline()
        for i in range(10):
            bl.update({"packets_per_sec": 5.0 + i * 0.1, "bytes_per_sec": 2000,
                        "unique_ports": 3, "conn_rate": 0.2,
                        "icmp_rate": 0.05, "rst_rate": 0.05})
        self.assertTrue(bl.is_trusted)

    def test_z_score(self):
        bl = DeviceBaseline()
        # Feed 20 identical samples
        for _ in range(20):
            bl.update({"packets_per_sec": 5.0, "bytes_per_sec": 2000,
                        "unique_ports": 3, "conn_rate": 0.2,
                        "icmp_rate": 0.05, "rst_rate": 0.05})
        # Feed slightly different values to build variance
        for _ in range(20):
            bl.update({"packets_per_sec": 6.0, "bytes_per_sec": 2100,
                        "unique_ports": 3, "conn_rate": 0.2,
                        "icmp_rate": 0.05, "rst_rate": 0.05})

        # A massive outlier should have a high z-score
        z = bl.get_z_score("packets", 100.0)
        self.assertGreater(z, 5.0)

        # A value near the mean should have a low z-score
        z_normal = bl.get_z_score("packets", 5.5)
        self.assertLess(z_normal, 2.0)


class TestDeviceHistory(unittest.TestCase):
    """Test temporal sliding-window history."""

    def test_empty_history(self):
        h = DeviceHistory()
        self.assertEqual(h.burst_score, 0.0)
        self.assertEqual(h.port_accumulator, 0)
        self.assertEqual(h.consecutive_anomalies, 0)

    def test_burst_score(self):
        h = DeviceHistory()
        h.add_cycle({"unique_ports": 3}, was_anomaly=True)
        h.add_cycle({"unique_ports": 3}, was_anomaly=False)
        h.add_cycle({"unique_ports": 3}, was_anomaly=True)
        self.assertAlmostEqual(h.burst_score, 2 / 3, places=3)

    def test_port_accumulator(self):
        h = DeviceHistory()
        h.add_cycle({"unique_ports": 5}, was_anomaly=False)
        h.add_cycle({"unique_ports": 8}, was_anomaly=False)
        h.add_cycle({"unique_ports": 3}, was_anomaly=False)
        self.assertEqual(h.port_accumulator, 16)

    def test_consecutive_anomalies(self):
        h = DeviceHistory()
        h.add_cycle({"unique_ports": 3}, was_anomaly=False)
        h.add_cycle({"unique_ports": 3}, was_anomaly=True)
        h.add_cycle({"unique_ports": 3}, was_anomaly=True)
        h.add_cycle({"unique_ports": 3}, was_anomaly=True)
        self.assertEqual(h.consecutive_anomalies, 3)

    def test_consecutive_anomalies_broken_by_normal(self):
        h = DeviceHistory()
        h.add_cycle({"unique_ports": 3}, was_anomaly=True)
        h.add_cycle({"unique_ports": 3}, was_anomaly=True)
        h.add_cycle({"unique_ports": 3}, was_anomaly=False)  # breaks the chain
        h.add_cycle({"unique_ports": 3}, was_anomaly=True)
        self.assertEqual(h.consecutive_anomalies, 1)

    def test_delta_computation(self):
        h = DeviceHistory()
        h.add_cycle({"packets_per_sec": 5.0}, was_anomaly=False)
        delta = h.get_delta("packets_per_sec", 10.0)
        self.assertAlmostEqual(delta, 5.0)


class TestDeviceTracker(unittest.TestCase):
    """Test the main DeviceTracker class."""

    def test_arp_spoof_detection(self):
        tracker = DeviceTracker()
        # First scan — learn bindings
        alerts = tracker.check_arp_bindings({
            "192.168.1.5": "aa:bb:cc:dd:ee:ff"
        })
        self.assertEqual(len(alerts), 0)

        # Second scan — same MAC, no alert
        alerts = tracker.check_arp_bindings({
            "192.168.1.5": "aa:bb:cc:dd:ee:ff"
        })
        self.assertEqual(len(alerts), 0)

        # Third scan — MAC changed! Alert!
        alerts = tracker.check_arp_bindings({
            "192.168.1.5": "11:22:33:44:55:66"
        })
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ip"], "192.168.1.5")
        self.assertEqual(alerts[0]["old_mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(alerts[0]["new_mac"], "11:22:33:44:55:66")

    def test_temporal_features_default(self):
        tracker = DeviceTracker()
        temp = tracker.get_temporal_features("192.168.1.5", {"packets_per_sec": 5.0})
        self.assertEqual(temp["delta_packets"], 0.0)
        self.assertEqual(temp["burst_score"], 0.0)

    def test_temporal_features_after_cycles(self):
        tracker = DeviceTracker()
        feat1 = {"packets_per_sec": 5.0, "unique_ports": 3}
        tracker.record_cycle("192.168.1.5", feat1, was_anomaly=False)

        feat2 = {"packets_per_sec": 10.0, "unique_ports": 5}
        temp = tracker.get_temporal_features("192.168.1.5", feat2)
        self.assertAlmostEqual(temp["delta_packets"], 5.0, places=3)
        self.assertAlmostEqual(temp["delta_ports"], 2.0, places=3)

    def test_device_count(self):
        tracker = DeviceTracker()
        tracker.record_cycle("192.168.1.5", {}, was_anomaly=False)
        tracker.record_cycle("192.168.1.6", {}, was_anomaly=False)
        self.assertEqual(tracker.get_device_count(), 2)

    def test_slow_scan_detection(self):
        tracker = DeviceTracker()
        # Simulate a device scanning 3 ports per cycle for 6 cycles
        for i in range(6):
            feat = {"unique_ports": 3, "packets_per_sec": 5.0}
            tracker.record_cycle("192.168.1.5", feat, was_anomaly=False)
        # 6 cycles × 3 ports = 18 > threshold of 15
        self.assertTrue(tracker.is_slow_scan("192.168.1.5"))

    def test_fast_scan_no_echo_alert(self):
        """
        Regression test: a fast port scan (100 ports in 1 cycle) should NOT
        keep triggering 'Slow Scan' alerts in subsequent cycles with 0 ports.
        This was the 'echo alert' bug — port_accumulator stayed > 15 for 9 cycles
        after the scan ended, causing continuous false alerts.
        """
        tracker = DeviceTracker()
        # Cycle 1: fast port scan — 100 ports
        tracker.record_cycle("192.168.1.5", {"unique_ports": 100}, was_anomaly=True)
        # Cycle 2-5: no scanning at all (attacker has stopped)
        for _ in range(4):
            tracker.record_cycle("192.168.1.5", {"unique_ports": 0}, was_anomaly=False)
        # is_slow_scan MUST be False — no active scanning this cycle
        self.assertFalse(
            tracker.is_slow_scan("192.168.1.5"),
            "Fast scan should NOT echo as slow scan in subsequent idle cycles"
        )

    def test_slow_scan_stops_when_idle(self):
        """Verify slow scan flag clears when the device stops scanning."""
        tracker = DeviceTracker()
        # Build up a slow scan
        for _ in range(6):
            tracker.record_cycle("192.168.1.5", {"unique_ports": 3}, was_anomaly=False)
        self.assertTrue(tracker.is_slow_scan("192.168.1.5"))
        # Device goes quiet
        for _ in range(5):
            tracker.record_cycle("192.168.1.5", {"unique_ports": 0}, was_anomaly=False)
        # Should no longer flag as slow scan
        self.assertFalse(
            tracker.is_slow_scan("192.168.1.5"),
            "Slow scan flag should clear when device stops scanning"
        )


if __name__ == "__main__":
    unittest.main()
