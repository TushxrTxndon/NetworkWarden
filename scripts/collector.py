#!/usr/bin/env python3
"""
WiFi Guardian — Data Collector (v5 — ARP Cache + Interface Check)

Changes in v5:
  - ARP scan is now CACHED — refreshed every ARP_REFRESH_CYCLES cycles (default: 10)
    This prevents the ~10s arp-scan from blocking the 5s capture window every cycle
  - Added WiFi interface liveness check before each ARP scan
  - All v4 fixes preserved (DNS counting, bidirectional port tracking, Pi self-monitoring)
"""

import subprocess
import re
import csv
import os
import time
import logging
from collections import defaultdict
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import INTERFACE, CAPTURE_WINDOW_SEC, RAW_DIR

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [COLLECTOR] %(message)s")

# ─── ARP Cache ───────────────────────────────────────────────────────────────

ARP_REFRESH_CYCLES = 10          # refresh ARP scan every N cycles
_arp_cache: dict     = {}        # {ip: mac}
_arp_cycle_count: int = 0        # how many cycles since last refresh


# ─── Interface Liveness Check ────────────────────────────────────────────────

def _is_interface_up(iface: str) -> bool:
    """Check if the WiFi interface is up and operational."""
    try:
        result = subprocess.run(
            ["cat", f"/sys/class/net/{iface}/operstate"],
            capture_output=True, text=True, timeout=2
        )
        return result.stdout.strip() in ("up", "unknown")
    except Exception:
        return True  # assume up if we can't check


# ─── ARP Scan ────────────────────────────────────────────────────────────────

def get_arp_devices(force: bool = False) -> dict:
    """
    Return {ip: mac} from ARP scan.

    Results are CACHED for ARP_REFRESH_CYCLES cycles to avoid blocking
    the packet capture window on every cycle. Pass force=True to bypass.
    """
    global _arp_cache, _arp_cycle_count

    _arp_cycle_count += 1
    if not force and _arp_cache and (_arp_cycle_count % ARP_REFRESH_CYCLES != 1):
        logging.info(f"ARP cache: {len(_arp_cache)} device(s) (refresh in "
                     f"{ARP_REFRESH_CYCLES - (_arp_cycle_count % ARP_REFRESH_CYCLES)} cycles)")
        return dict(_arp_cache)

    # Check interface is up before running arp-scan
    if not _is_interface_up(INTERFACE):
        logging.warning(f"Interface {INTERFACE} is DOWN — check: ip a | grep {INTERFACE}")
        return dict(_arp_cache)  # return stale cache rather than empty

    devices = {}
    try:
        result = subprocess.run(
            ["arp-scan", f"--interface={INTERFACE}", "--localnet"],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines():
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([\w:]+)", line)
            if match:
                devices[match.group(1)] = match.group(2).lower()
    except Exception as e:
        logging.error(f"arp-scan failed: {e}")
        return dict(_arp_cache)  # return stale cache on failure

    _arp_cache = dict(devices)
    logging.info(f"ARP refreshed: {len(devices)} device(s) found")
    return devices


def get_own_ip() -> str:
    """Return this Pi's own IP on the network."""
    try:
        result = subprocess.run(["hostname", "-I"],
                                 capture_output=True, text=True)
        return result.stdout.strip().split()[0]
    except Exception:
        return ""


def get_own_mac() -> str:
    """Return this Pi's MAC address."""
    try:
        result = subprocess.run(
            ["cat", f"/sys/class/net/{INTERFACE}/address"],
            capture_output=True, text=True
        )
        return result.stdout.strip()
    except Exception:
        return "00:00:00:00:00:00"


# ─── Traffic Capture ─────────────────────────────────────────────────────────

def capture_traffic(duration: int = CAPTURE_WINDOW_SEC) -> dict:
    """
    Sniff all packets for `duration` seconds.

    Tracks per-IP:
      packets_in/out, bytes_in/out — volume
      src_ports  — ports THIS device contacts (high = it's scanning out)
      dst_ports  — ports ON this device being hit (high = it's being scanned)
      conn_attempts — TCP SYN count (new connection initiations)
      icmp_count — ICMP packets (ping flood signal)
      rst_count  — RST packets sent (port scan target signal)
      dns_queries — DNS query count (UDP port 53 — DNS tunnel signal)

    unique_ports = max(src_ports, dst_ports) per device
    """
    stats = defaultdict(lambda: {
        "packets_in":    0,
        "packets_out":   0,
        "bytes_in":      0,
        "bytes_out":     0,
        "src_ports":     set(),   # ports this IP is contacting (outward)
        "dst_ports":     set(),   # ports ON this IP being contacted (inward)
        "conn_attempts": 0,
        "icmp_count":    0,
        "rst_count":     0,       # RST packets SENT by this device
        "dns_queries":   0,       # UDP port 53 packets (DNS)
    })

    def handle_packet(pkt):
        if IP not in pkt:
            return

        src  = pkt[IP].src
        dst  = pkt[IP].dst
        size = len(pkt)

        # Volume tracking
        stats[src]["packets_out"] += 1
        stats[src]["bytes_out"]   += size
        stats[dst]["packets_in"]  += 1
        stats[dst]["bytes_in"]    += size

        # UDP Port Tracking (No SYN flags in UDP)
        if UDP in pkt:
            stats[src]["src_ports"].add(pkt[UDP].dport)
            stats[dst]["dst_ports"].add(pkt[UDP].dport)
            # Track DNS queries (UDP port 53)
            if pkt[UDP].dport == 53:
                stats[src]["dns_queries"] += 1

        # TCP SYN = new connection attempt (only track ports on initial connection)
        if TCP in pkt and pkt[TCP].flags == "S":
            stats[src]["conn_attempts"] += 1
            stats[src]["src_ports"].add(pkt[TCP].dport)
            stats[dst]["dst_ports"].add(pkt[TCP].dport)

        # RST = connection rejected (closed port, firewall, etc.)
        if TCP in pkt and pkt[TCP].flags.R:
            stats[src]["rst_count"] += 1

        # ICMP — track for BOTH src (sender) and dst (target of flood)
        if ICMP in pkt:
            stats[src]["icmp_count"] += 1
            stats[dst]["icmp_count"] += 1

    logging.info(f"Sniffing on {INTERFACE} for {duration}s...")
    sniff(iface=INTERFACE, prn=handle_packet, timeout=duration, store=False)

    # Flatten sets → counts
    for ip in stats:
        # unique_ports: whichever is higher — being scanned or actively scanning
        stats[ip]["unique_ports"] = max(
            len(stats[ip]["dst_ports"]),
            len(stats[ip]["src_ports"])
        )
        del stats[ip]["src_ports"]
        del stats[ip]["dst_ports"]

    return dict(stats)


# ─── Snapshot ────────────────────────────────────────────────────────────────

def collect_snapshot() -> list:
    """
    Full collection cycle:
      1. ARP scan → device list (CACHED, refreshes every ARP_REFRESH_CYCLES cycles)
      2. Always add Pi's own IP (catches attacks FROM the Pi)
      3. Traffic capture → per-IP stats
      4. Merge → list of record dicts

    Returns list of record dicts (one per device including the Pi itself).
    """
    timestamp = datetime.now().isoformat()
    devices   = get_arp_devices()

    # ── Always include Pi's own IP ────────────────────────────────────────────
    own_ip  = get_own_ip()
    own_mac = get_own_mac()
    if own_ip and own_ip not in devices:
        devices[own_ip] = own_mac
        logging.info(f"Added Pi's own IP to monitor list: {own_ip}")

    traffic = capture_traffic(CAPTURE_WINDOW_SEC)

    snapshot = []
    for ip, mac in devices.items():
        t = traffic.get(ip, {})
        record = {
            "timestamp":     timestamp,
            "ip":            ip,
            "mac":           mac,
            "window_sec":    CAPTURE_WINDOW_SEC,
            "packets_in":    t.get("packets_in",    0),
            "packets_out":   t.get("packets_out",   0),
            "bytes_in":      t.get("bytes_in",      0),
            "bytes_out":     t.get("bytes_out",     0),
            "unique_ports":  t.get("unique_ports",  0),
            "conn_attempts": t.get("conn_attempts", 0),
            "icmp_count":    t.get("icmp_count",    0),
            "rst_count":     t.get("rst_count",     0),
            "dns_queries":   t.get("dns_queries",   0),
        }
        snapshot.append(record)

    # ── Include unknown IPs with significant traffic ─────────────────────────
    # Attacks from devices NOT in the ARP cache (new devices, spoofed MACs)
    # were previously invisible. Now any IP with >5 packets gets analyzed.
    MIN_PACKETS_FOR_UNKNOWN = 5
    for ip, t in traffic.items():
        if ip not in devices:
            total_pkts = t.get("packets_in", 0) + t.get("packets_out", 0)
            if total_pkts >= MIN_PACKETS_FOR_UNKNOWN:
                logging.info(f"Unknown IP {ip} has {total_pkts} packets — adding to analysis")
                record = {
                    "timestamp":     timestamp,
                    "ip":            ip,
                    "mac":           "unknown",
                    "window_sec":    CAPTURE_WINDOW_SEC,
                    "packets_in":    t.get("packets_in",    0),
                    "packets_out":   t.get("packets_out",   0),
                    "bytes_in":      t.get("bytes_in",      0),
                    "bytes_out":     t.get("bytes_out",     0),
                    "unique_ports":  t.get("unique_ports",  0),
                    "conn_attempts": t.get("conn_attempts", 0),
                    "icmp_count":    t.get("icmp_count",    0),
                    "rst_count":     t.get("rst_count",     0),
                    "dns_queries":   t.get("dns_queries",   0),
                }
                snapshot.append(record)

    return snapshot


def get_discovered_devices() -> dict:
    """
    Return {ip: mac} from ARP cache + Pi self.
    Used by DeviceTracker for ARP spoof checks.
    """
    devices = get_arp_devices()
    own_ip  = get_own_ip()
    own_mac = get_own_mac()
    if own_ip and own_ip not in devices:
        devices[own_ip] = own_mac
    return devices


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs(RAW_DIR, exist_ok=True)
    snapshot = collect_snapshot()

    if not snapshot:
        logging.warning("No devices found. Check INTERFACE in config.py")
        sys.exit(0)

    fname = os.path.join(
        RAW_DIR,
        f"snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )
    with open(fname, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=snapshot[0].keys())
        writer.writeheader()
        writer.writerows(snapshot)

    logging.info(f"Saved {len(snapshot)} records → {fname}")
