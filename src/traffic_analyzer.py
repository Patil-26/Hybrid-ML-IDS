"""
traffic_analyzer.py
Tracks packet frequency per IP address over a sliding time window.
Detects DoS attacks based on packet count threshold.
Implements a 3-level escalation system:
  Level 1 — WARNING  (100-149 packets in 5 seconds)
  Level 2 — ALERT    (150-199 packets in 5 seconds)
  Level 3 — BLOCK    (200+ packets in 5 seconds)
"""

from collections import defaultdict
import time

# Store packet timestamps per IP address
traffic_data     = defaultdict(list)
service_data     = defaultdict(list)
dst_host_data    = defaultdict(set)
offense_level    = defaultdict(int)

# ─── Detection Thresholds ─────────────────────────────────────────────
PACKET_THRESHOLD_WARNING = 100
PACKET_THRESHOLD_ALERT   = 150
PACKET_THRESHOLD_BLOCK   = 200
TIME_WINDOW              = 5  # seconds


def analyze_traffic(ip, packet_length, service=0, dst_ip=None, flag=0):
    """
    Analyze traffic from a given IP address.
    Returns features, attack_type and severity.
    """

    now = time.time()

    # Record current packet timestamp
    traffic_data[ip].append(now)
    service_data[ip].append(service)

    if dst_ip:
        dst_host_data[ip].add(dst_ip)

    # Remove timestamps OUTSIDE the time window
    traffic_data[ip] = [
        t for t in traffic_data[ip]
        if now - t <= TIME_WINDOW
    ]

    # Keep service_data in sync with traffic_data length
    if len(service_data[ip]) > len(traffic_data[ip]):
        service_data[ip] = service_data[ip][-len(traffic_data[ip]):]

    packet_count = len(traffic_data[ip])


    # same_srv_rate
    if packet_count > 0 and len(service_data[ip]) > 0:
        same_srv_count = service_data[ip].count(service)
        same_srv_rate  = same_srv_count / len(service_data[ip])
    else:
        same_srv_rate = 0.0

    diff_srv_rate          = 1.0 - same_srv_rate
    dst_host_count         = len(dst_host_data[ip])
    dst_host_same_srv_rate = same_srv_rate
    dst_host_diff_srv_rate = diff_srv_rate
    serror_rate            = 1.0 if flag == 1 else 0.0

    features = {
        "src_bytes":               packet_length,
        "dst_bytes":               packet_length,
        "count":                   packet_count,
        "srv_count":               packet_count,
        "service":                 service,
        "flag":                    flag,
        "same_srv_rate":           round(same_srv_rate, 4),
        "diff_srv_rate":           round(diff_srv_rate, 4),
        "dst_host_count":          dst_host_count,
        "dst_host_same_srv_rate":  round(dst_host_same_srv_rate, 4),
        "dst_host_diff_srv_rate":  round(dst_host_diff_srv_rate, 4),
        "serror_rate":             serror_rate,
        "srv_serror_rate":         serror_rate,
        "dst_host_serror_rate":    serror_rate,
    }

    # ── Escalation System ─────────────────────────────────────────────
    if packet_count >= PACKET_THRESHOLD_BLOCK:
        offense_level[ip] = 3
        return features, "dos_attack", "block"

    elif packet_count >= PACKET_THRESHOLD_ALERT:
        offense_level[ip] = max(offense_level[ip], 2)
        return features, "dos_attack", "alert"

    elif packet_count >= PACKET_THRESHOLD_WARNING:
        offense_level[ip] = max(offense_level[ip], 1)
        return features, "dos_attack", "warning"

    return features, None, None