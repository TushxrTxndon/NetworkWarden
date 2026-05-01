#!/usr/bin/env python3
"""
WiFi Guardian — Attack Classifier (v5 — Temporal + ARP Spoof + Adaptive)

Changes in v5:
  - Added ARP Spoofing attack type (from DeviceTracker)
  - Added Slow Scan attack type (temporal, cross-cycle port accumulation)
  - Thresholds are now relative to per-device baselines when available
  - Cumulative anomaly escalation — sustained suspicious activity raises confidence
  - All MITRE ATT&CK mappings updated

Decision order (mutually exclusive):
  1. Ping Flood       → icmp_fraction dominant
  2. SYN Flood        → syn_fraction dominant + LOW rst_rate
  3. Port Scan        → unique_ports high + HIGH rst_rate
  4. Brute Force      → moderate conn_rate to 1–2 ports
  5. Data Exfiltration → high bytes + very low rx_tx
  6. UDP / BW Flood   → large bytes_per_packet + high bytes
  7. Slow Scan        → NEW: port_accumulator high across cycles
  8. Reconnaissance   → mild port diversity
  9. Unknown
"""

import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import ANOMALY_THRESHOLD


@dataclass
class AttackResult:
    name:        str
    confidence:  str        # "Critical" / "High" / "Medium" / "Low"
    description: str
    emoji:       str
    mitre_code:  str = ""   # MITRE ATT&CK Technique ID
    mitre_name:  str = ""   # Human-readable MITRE technique name
    evidence:    list = field(default_factory=list)
    severity:    str  = "WARNING"  # "INFO" / "WARNING" / "CRITICAL"


# ─── MITRE ATT&CK Reference ──────────────────────────────────────────────────

MITRE = {
    "port_scan":   ("T1046",     "Network Service Discovery"),
    "ping_flood":  ("T1499.002", "Service Exhaustion Flood"),
    "syn_flood":   ("T1498.001", "Direct Network Flood"),
    "udp_flood":   ("T1498.001", "Direct Network Flood"),
    "exfil":       ("T1041",     "Exfiltration Over C2 Channel"),
    "brute":       ("T1110",     "Brute Force"),
    "recon":       ("T1595",     "Active Scanning"),
    "arp_spoof":   ("T1557.002", "ARP Cache Poisoning"),
    "slow_scan":   ("T1046",     "Network Service Discovery"),
    "unknown":     ("T1499",     "Endpoint Denial of Service"),
}


# ─── ARP Spoof Alert (new) ───────────────────────────────────────────────────

def classify_arp_spoof(spoof_info: dict) -> AttackResult:
    """
    Create an AttackResult for an ARP spoofing event.
    Called separately from the main classifier — ARP spoofs are
    detected by the DeviceTracker, not by the ML model.
    """
    mc, mn = MITRE["arp_spoof"]
    return AttackResult(
        name        = "ARP Spoofing / Cache Poisoning",
        confidence  = "Critical",
        emoji       = "🕵️",
        mitre_code  = mc,
        mitre_name  = mn,
        severity    = "CRITICAL",
        description = (
            f"IP {spoof_info['ip']} changed MAC address from "
            f"{spoof_info['old_mac']} → {spoof_info['new_mac']}. "
            "This may indicate a Man-in-the-Middle (MITM) attack."
        ),
        evidence    = [
            f"old_mac={spoof_info['old_mac']}",
            f"new_mac={spoof_info['new_mac']}",
            f"time={spoof_info.get('time', 'unknown')}",
        ],
    )


# ─── Main Classifier ─────────────────────────────────────────────────────────

def classify_attack(feat: dict, deviation_scores: dict = None,
                     is_escalated: bool = False) -> AttackResult:
    """
    Classify the type of network attack using ratio-based + RST-based rules.

    Args:
        feat:              feature dict with all 15 features
        deviation_scores:  optional z-scores from DeviceTracker baseline
                           (keys: z_packets, z_bytes, z_ports, z_conn, z_icmp, z_rst)
        is_escalated:      True if this device has been suspicious for N consecutive cycles
    """

    # ── Extract features ─────────────────────────────────────────────────────
    pkt_s   = float(feat.get("packets_per_sec",   0))
    byte_s  = float(feat.get("bytes_per_sec",     0))
    ports   = int(feat.get("unique_ports",         0))
    conn_s  = float(feat.get("conn_rate",          0))
    icmp_s  = float(feat.get("icmp_rate",          0))
    rst_s   = float(feat.get("rst_rate",           0))
    rx_tx   = float(feat.get("rx_tx_ratio",        1.0))
    window  = feat.get("window_sec", 15)

    # Derived features
    safe_pkt_s  = max(pkt_s,  0.001)
    safe_conn_r = max(conn_s, 0.01)

    bpp   = float(feat.get("bytes_per_packet",
                            byte_s / safe_pkt_s))
    icmpf = float(feat.get("icmp_fraction",
                            min(icmp_s / safe_pkt_s, 1.0)))
    synf  = float(feat.get("syn_fraction",
                            min(conn_s / safe_pkt_s, 1.0)))
    psr   = float(feat.get("port_scan_ratio",
                            ports / safe_conn_r))

    # Temporal features
    delta_pkt  = float(feat.get("delta_packets",    0.0))
    delta_port = float(feat.get("delta_ports",      0.0))
    burst      = float(feat.get("burst_score",      0.0))
    port_accum = int(feat.get("port_accumulator",   0))

    # Per-device baseline z-scores (if available)
    zs = deviation_scores or {}
    has_baseline = bool(zs)

    # ── Confidence booster: escalation from sustained suspicious activity ────
    def _boost(base_conf: str) -> str:
        """Upgrade confidence if device has been suspicious across cycles."""
        if is_escalated:
            if base_conf == "Low":
                return "Medium"
            elif base_conf == "Medium":
                return "High"
            elif base_conf == "High":
                return "Critical"
        return base_conf

    # ── 1. Ping Flood ─────────────────────────────────────────────────────────
    if (icmpf > 0.4 and icmp_s > 5) or (icmp_s > 15 and icmpf > 0.2):
        confidence = _boost("High" if icmpf > 0.7 or icmp_s > 50 else "Medium")
        mc, mn     = MITRE["ping_flood"]
        evidence   = [
            f"icmp_fraction={icmpf:.2f}  ({icmpf*100:.0f}% of traffic is ICMP — normal: under 1%)",
            f"icmp_rate={icmp_s:.1f}/s",
        ]
        if bpp < 100:
            evidence.append(f"bytes_per_packet={bpp:.0f}B  (confirms tiny ICMP packets)")
        if has_baseline and zs.get("z_icmp", 0) > 3:
            evidence.append(f"z_score_icmp={zs['z_icmp']:.1f}  (>{3}σ above THIS device's baseline)")
        return AttackResult(
            name        = "Ping Flood (ICMP DoS)",
            confidence  = confidence,
            emoji       = "🌊",
            mitre_code  = mc,
            mitre_name  = mn,
            severity    = "CRITICAL" if confidence in ("High", "Critical") else "WARNING",
            description = (
                f"{icmpf*100:.0f}% of all traffic is ICMP ({icmp_s:.0f} pings/sec). "
                "Overwhelms the target with echo requests — classic Denial of Service."
            ),
            evidence    = evidence,
        )

    # ── 2. SYN Flood ─────────────────────────────────────────────────────────
    if (synf > 0.5 and ports <= 5 and rst_s < 5 and conn_s > 5) or (synf > 0.85 and conn_s > 10):
        confidence = _boost("High" if synf > 0.7 and conn_s > 10 else "Medium")
        mc, mn     = MITRE["syn_flood"]
        evidence   = [
            f"syn_fraction={synf:.2f}  ({synf*100:.0f}% of traffic is TCP SYN)",
            f"unique_ports={ports}  (targeting {ports} port(s))",
            f"rst_rate={rst_s:.1f}/s  (LOW — port is open, target sends SYN-ACK not RST)",
        ]
        return AttackResult(
            name        = "SYN Flood (TCP DoS)",
            confidence  = confidence,
            emoji       = "⚡",
            mitre_code  = mc,
            mitre_name  = mn,
            severity    = "CRITICAL" if confidence in ("High", "Critical") else "WARNING",
            description = (
                f"{synf*100:.0f}% of traffic is TCP SYN to {ports} port(s). "
                "Port is open so target sends SYN-ACK — connection table exhaustion."
            ),
            evidence    = evidence,
        )

    # ── 3. Port Scan ─────────────────────────────────────────────────────────
    if ports > 20 and (psr > 5 or rst_s > 3) and synf < 0.85:
        confidence = _boost("High" if (ports > 100 and (psr > 20 or rst_s > 10)) else "Medium")
        mc, mn     = MITRE["port_scan"]
        evidence   = [
            f"unique_ports={ports}  (normal: 1–5)",
            f"rst_rate={rst_s:.1f}/s  (target rejects closed-port connections with RST)",
            f"port_scan_ratio={psr:.1f}  (ports per SYN — HIGH = mapping services)",
        ]
        if has_baseline and zs.get("z_ports", 0) > 3:
            evidence.append(f"z_score_ports={zs['z_ports']:.1f}  (>{3}σ above device baseline)")
        return AttackResult(
            name        = "Port Scan",
            confidence  = confidence,
            emoji       = "🔍",
            mitre_code  = mc,
            mitre_name  = mn,
            severity    = "WARNING",
            description = (
                f"Contacted {ports} unique ports in {window}s. "
                f"Target sent {rst_s:.0f} RST/s back (closed ports). "
                "Attacker is mapping services to find vulnerabilities."
            ),
            evidence    = evidence,
        )

    # ── 4. Brute Force ───────────────────────────────────────────────────────
    # Real brute force (hydra, medusa) against an OPEN service (SSH/RDP/HTTP)
    # produces ZERO RSTs — TCP connects fine, auth fails at application layer.
    # With 30s capture windows, conn_rate gets diluted (60 SYNs / 30s = 2.0/s)
    # so we use a lower threshold + absolute conn_attempts fallback.
    total_conns = conn_s * window   # absolute SYN count in this window
    if (conn_s > 1.5 or total_conns > 30) and ports <= 3 and synf > 0.15:
        confidence = _boost("High" if conn_s > 5 or total_conns > 100 else "Medium")
        mc, mn     = MITRE["brute"]
        evidence   = [
            f"conn_rate={conn_s:.1f}/s  ({total_conns:.0f} SYNs in {window}s to {ports} port(s))",
            f"syn_fraction={synf:.2f}  (many connection attempts)",
        ]
        if rst_s > 0.5:
            evidence.append(f"rst_rate={rst_s:.1f}/s  (some rejected -- port may be filtered)")
        return AttackResult(
            name        = "Brute Force",
            confidence  = confidence,
            emoji       = "\U0001f511",
            mitre_code  = mc,
            mitre_name  = mn,
            severity    = "WARNING",
            description = (
                f"{total_conns:.0f} connection attempts in {window}s to {ports} port(s). "
                "Automated credential attack (SSH, RDP, or web login)."
            ),
            evidence    = evidence,
        )

    # ── 5. Data Exfiltration ─────────────────────────────────────────────────
    if byte_s > 5000 and rx_tx < 0.2 and ports <= 5:
        confidence = _boost("High" if byte_s > 20000 and rx_tx < 0.05 else "Medium")
        mc, mn     = MITRE["exfil"]
        evidence   = [
            f"rx_tx_ratio={rx_tx:.3f}  (sending {1/max(rx_tx,0.001):.0f}× more than receiving)",
            f"bytes_per_sec={byte_s:.0f} ({byte_s/1024:.1f} KB/s outbound)",
            f"bytes_per_packet={bpp:.0f}B  (large packets = bulk transfer)",
        ]
        return AttackResult(
            name        = "Data Exfiltration",
            confidence  = confidence,
            emoji       = "📤",
            mitre_code  = mc,
            mitre_name  = mn,
            severity    = "CRITICAL",
            description = (
                f"Uploading {byte_s/1024:.1f}KB/s, receiving almost nothing "
                f"(rx/tx={rx_tx:.2f}). Possible malware or unauthorized data transfer."
            ),
            evidence    = evidence,
        )

    # ── 5.5 DNS Tunneling ─────────────────────────────────────────────────────
    # High DNS query rate = possible covert C2 channel or data exfiltration via DNS
    dns_rate = float(feat.get("dns_query_rate", 0.0))
    if dns_rate > 10 and pkt_s >= 1.0:
        confidence = _boost("High" if dns_rate > 30 else "Medium")
        mc, mn     = MITRE["exfil"]
        evidence   = [
            f"dns_query_rate={dns_rate:.1f}/s  (normal: <2/s — this is {dns_rate/2:.0f}x elevated)",
            f"UDP port 53 traffic dominates this device's outbound traffic",
        ]
        if has_baseline and zs.get("z_packets", 0) > 2:
            evidence.append(f"z_score_packets={zs['z_packets']:.1f} (above device baseline)")
        return AttackResult(
            name        = "DNS Tunneling / C2 via DNS",
            confidence  = confidence,
            emoji       = "🕳️",
            mitre_code  = mc,
            mitre_name  = mn,
            severity    = "CRITICAL" if dns_rate > 30 else "WARNING",
            description = (
                f"Abnormal DNS query rate: {dns_rate:.0f} queries/sec (normal < 2/s). "
                "DNS tunneling is used to exfiltrate data or maintain C2 channels "
                "through firewalls by encoding data in DNS packets."
            ),
            evidence    = evidence,
        )

    # ── 6. UDP / Bandwidth Flood ─────────────────────────────────────────────
    if bpp > 200 and byte_s > 8000 and icmpf < 0.2 and synf < 0.3:
        confidence = _boost("High" if bpp > 500 and byte_s > 20000 else "Medium")
        mc, mn     = MITRE["udp_flood"]
        evidence   = [
            f"bytes_per_packet={bpp:.0f}B  (large UDP payload — normal: 100–400B)",
            f"bytes_per_sec={byte_s:.0f} ({byte_s/1024:.0f}KB/s bandwidth flood)",
            f"icmp_fraction={icmpf:.2f}  rst_rate={rst_s:.1f}  (not ICMP, not TCP)",
        ]
        return AttackResult(
            name        = "UDP / Bandwidth Flood",
            confidence  = confidence,
            emoji       = "🌀",
            mitre_code  = mc,
            mitre_name  = mn,
            severity    = "CRITICAL" if confidence in ("High", "Critical") else "WARNING",
            description = (
                f"Large-packet flood: {bpp:.0f}B/pkt at {byte_s/1024:.0f}KB/s. "
                "Not ICMP, not SYN — consistent with UDP bandwidth exhaustion."
            ),
            evidence    = evidence,
        )

    # ── 7. Slow Scan (temporal detection) ────────────────────────────────────
    # Guard: if unique_ports is consistently <=2, this is NOT a scan —
    # it's brute force or normal traffic hitting the same port every cycle.
    # A real slow scan probes DIFFERENT ports each cycle.
    if port_accum > 15 and ports > 2 and ports <= 20:
        mc, mn  = MITRE["slow_scan"]
        evidence = [
            f"port_accumulator={port_accum}  (total ports across last N cycles — threshold: 15)",
            f"unique_ports_this_cycle={ports}  (only {ports} per cycle)",
        ]
        if burst > 0:
            evidence.append(f"burst_score={burst:.2f}  ({burst*100:.0f}% of recent cycles suspicious)")

        # High accumulation = real port scan at moderate speed (nmap -T3), not stealth
        if port_accum > 100:
            mc2, mn2 = MITRE["port_scan"]
            return AttackResult(
                name        = "Port Scan",
                confidence  = _boost("High"),
                emoji       = "🔍",
                mitre_code  = mc2,
                mitre_name  = mn2,
                severity    = "WARNING",
                description = (
                    f"Accumulated {port_accum} unique ports across multiple cycles — "
                    f"consistent with nmap or automated scanner."
                ),
                evidence    = evidence,
            )

        return AttackResult(
            name        = "Slow / Stealthy Port Scan",
            confidence  = _boost("Medium"),
            emoji       = "🐌",
            mitre_code  = mc,
            mitre_name  = mn,
            severity    = "WARNING",
            description = (
                f"Accumulated {port_accum} unique ports across multiple cycles, "
                f"but only {ports}/cycle — deliberately slow to evade single-window detection."
            ),
            evidence    = evidence,
        )

    # ── 8. Reconnaissance (slow/stealthy scan) ───────────────────────────────
    if ports > 15 or (conn_s > 1.5 and psr > 8) or rst_s > 2:
        mc, mn  = MITRE["recon"]
        evidence = []
        if ports > 8:
            evidence.append(f"unique_ports={ports}  (elevated but not a full scan)")
        if rst_s > 1:
            evidence.append(f"rst_rate={rst_s:.1f}/s  (some port rejections)")
        if psr > 3:
            evidence.append(f"port_scan_ratio={psr:.1f}")
        if has_baseline and zs.get("z_ports", 0) > 2:
            evidence.append(f"z_score_ports={zs['z_ports']:.1f}  (above device baseline)")
        return AttackResult(
            name        = "Network Reconnaissance",
            confidence  = _boost("Low"),
            emoji       = "👁️",
            mitre_code  = mc,
            mitre_name  = mn,
            severity    = "INFO",
            description = (
                "Moderate port diversity — possible slow/stealthy scan, "
                "vulnerability probe, or automated discovery tool."
            ),
            evidence    = evidence,
        )

    # ── 9. Unknown ───────────────────────────────────────────────────────────
    mc, mn   = MITRE["unknown"]
    dominant = _dominant_feature(feat)
    return AttackResult(
        name        = "Unknown Anomaly",
        confidence  = _boost("Low"),
        emoji       = "❓",
        mitre_code  = mc,
        mitre_name  = mn,
        severity    = "INFO",
        description = (
            "Statistically abnormal but no known attack pattern matched. "
            f"Most deviant feature: {dominant}."
        ),
        evidence    = [f"primary deviation: {dominant}"],
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _dominant_feature(feat: dict) -> str:
    baselines = {
        "packets_per_sec":  5.0,
        "bytes_per_sec":    2000.0,
        "unique_ports":     3.0,
        "conn_rate":        0.2,
        "icmp_rate":        0.05,
        "rst_rate":         0.1,
        "icmp_fraction":    0.01,
        "syn_fraction":     0.05,
        "port_scan_ratio":  2.0,
    }
    max_ratio, dominant = 0.0, "unknown"
    for key, baseline in baselines.items():
        val   = float(feat.get(key, 0))
        ratio = val / max(baseline, 0.001)
        if ratio > max_ratio:
            max_ratio = ratio
            dominant  = f"{key}={val:.3f}  ({ratio:.1f}× above normal)"
    return dominant


def format_attack_result(result: AttackResult, score: float) -> str:
    """Format for terminal and Telegram — includes MITRE ATT&CK reference."""
    sep          = "─" * 48
    evidence_str = "\n".join(f"    • {e}" for e in result.evidence)
    mitre_line   = ""
    if result.mitre_code:
        mitre_line = f"   MITRE ATT&CK : {result.mitre_code} — {result.mitre_name}\n"
    severity_line = f"   Severity     : {result.severity}\n"
    return (
        f"{result.emoji} ATTACK TYPE   : {result.name}\n"
        f"   Confidence   : {result.confidence}\n"
        f"{severity_line}"
        f"   Anomaly Score: {score:+.4f}  (threshold: above {ANOMALY_THRESHOLD})\n"
        f"{mitre_line}"
        f"   Description  : {result.description}\n"
        f"   Evidence     :\n{evidence_str}\n"
        f"   {sep}"
    )


# ─── Self-Test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    """Run: python scripts/classifier.py  →  should show 9/9 ✅"""
    tests = [
        ("Ping Flood",    {"packets_per_sec":250, "bytes_per_sec":8000,  "unique_ports":0,
                           "conn_rate":0.0,  "icmp_rate":230, "rst_rate":0.0,
                           "rx_tx_ratio":0.4,"bytes_per_packet":32,  "icmp_fraction":0.92,
                           "syn_fraction":0.0, "port_scan_ratio":0.0,
                           "delta_packets":0, "delta_ports":0, "burst_score":0, "port_accumulator":0,
                           "window_sec":15}),
        ("SYN Flood",     {"packets_per_sec":80,  "bytes_per_sec":5000,  "unique_ports":2,
                           "conn_rate":60,   "icmp_rate":0,   "rst_rate":0.4,
                           "rx_tx_ratio":0.9,"bytes_per_packet":62,  "icmp_fraction":0.0,
                           "syn_fraction":0.75,"port_scan_ratio":0.03,
                           "delta_packets":0, "delta_ports":0, "burst_score":0, "port_accumulator":0,
                           "window_sec":15}),
        ("Port Scan",     {"packets_per_sec":90,  "bytes_per_sec":5400,  "unique_ports":847,
                           "conn_rate":28,   "icmp_rate":0.1, "rst_rate":22.0,
                           "rx_tx_ratio":0.6,"bytes_per_packet":60,  "icmp_fraction":0.001,
                           "syn_fraction":0.31,"port_scan_ratio":30.2,
                           "delta_packets":0, "delta_ports":0, "burst_score":0, "port_accumulator":0,
                           "window_sec":15}),
        ("Brute Force",   {"packets_per_sec":20,  "bytes_per_sec":1200,  "unique_ports":1,
                           "conn_rate":8,    "icmp_rate":0,   "rst_rate":1.5,
                           "rx_tx_ratio":0.7,"bytes_per_packet":60,  "icmp_fraction":0.0,
                           "syn_fraction":0.4, "port_scan_ratio":0.12,
                           "delta_packets":0, "delta_ports":0, "burst_score":0, "port_accumulator":0,
                           "window_sec":15}),
        ("Data Exfil",    {"packets_per_sec":30,  "bytes_per_sec":55000, "unique_ports":1,
                           "conn_rate":0.3,  "icmp_rate":0,   "rst_rate":0.0,
                           "rx_tx_ratio":0.01,"bytes_per_packet":1833,"icmp_fraction":0.0,
                           "syn_fraction":0.01,"port_scan_ratio":3.3,
                           "delta_packets":0, "delta_ports":0, "burst_score":0, "port_accumulator":0,
                           "window_sec":15}),
        ("UDP Flood",     {"packets_per_sec":60,  "bytes_per_sec":70000, "unique_ports":3,
                           "conn_rate":0.5,  "icmp_rate":0,   "rst_rate":0.0,
                           "rx_tx_ratio":0.8,"bytes_per_packet":1166,"icmp_fraction":0.0,
                           "syn_fraction":0.008,"port_scan_ratio":6.0,
                           "delta_packets":0, "delta_ports":0, "burst_score":0, "port_accumulator":0,
                           "window_sec":15}),
        ("Slow",          {"packets_per_sec":6,   "bytes_per_sec":900,   "unique_ports":5,
                           "conn_rate":1.0,  "icmp_rate":0,   "rst_rate":0.5,
                           "rx_tx_ratio":1.0,"bytes_per_packet":150, "icmp_fraction":0.0,
                           "syn_fraction":0.17, "port_scan_ratio":5.0,
                           "delta_packets":1, "delta_ports":2, "burst_score":0.2, "port_accumulator":25,
                           "window_sec":15}),
        ("Recon",         {"packets_per_sec":6,   "bytes_per_sec":900,   "unique_ports":15,
                           "conn_rate":1.2,  "icmp_rate":0,   "rst_rate":2.0,
                           "rx_tx_ratio":1.0,"bytes_per_packet":150, "icmp_fraction":0.0,
                           "syn_fraction":0.2, "port_scan_ratio":12.5,
                           "delta_packets":0, "delta_ports":0, "burst_score":0, "port_accumulator":0,
                           "window_sec":15}),
        ("Unknown",       {"packets_per_sec":15,  "bytes_per_sec":4000,  "unique_ports":3,
                           "conn_rate":0.3,  "icmp_rate":0.1, "rst_rate":0.1,
                           "rx_tx_ratio":1.5,"bytes_per_packet":266, "icmp_fraction":0.007,
                           "syn_fraction":0.02,"port_scan_ratio":10.0,
                           "delta_packets":0, "delta_ports":0, "burst_score":0, "port_accumulator":0,
                           "window_sec":15}),
    ]

    print("\n=== Classifier Self-Test (v5 — Temporal + ARP + Adaptive) ===\n")
    passed = 0
    for expected, feat in tests:
        r  = classify_attack(feat)
        ok = expected.lower().split()[0] in r.name.lower()
        mark = "✅" if ok else "❌"
        if ok:
            passed += 1
        print(f"  {mark}  {expected:16} → {r.emoji} {r.name} [{r.confidence}]  |  {r.mitre_code}  |  {r.severity}")
        if not ok:
            print(f"      Got: {r.name}")
    print(f"\n  Result: {passed}/{len(tests)} passed\n")
