"""
traffic_analyzer.py
Tracks packet frequency per IP address over a sliding time window.
Detects DoS attacks based on packet count threshold.
Implements a 3-level escalation system.
"""

from collections import defaultdict
import time

# Store packet timestamps per IP address
traffic_data     = defaultdict(list)
service_data     = defaultdict(list)
offense_level    = defaultdict(int)

# ─── Detection Thresholds ─────────────────────────────────────────────
PACKET_THRESHOLD_WARNING = 100
PACKET_THRESHOLD_ALERT   = 150
PACKET_THRESHOLD_BLOCK   = 200
TIME_WINDOW              = 5  # seconds


def analyze_traffic(ip, packet_length, service=0, dst_ip=None, flag=0):
    now = time.time()

    traffic_data[ip].append(now)
    service_data[ip].append(service)

    # Remove timestamps OUTSIDE the time window
    traffic_data[ip] = [t for t in traffic_data[ip] if now - t <= TIME_WINDOW]

    if len(service_data[ip]) > len(traffic_data[ip]):
        service_data[ip] = service_data[ip][-len(traffic_data[ip]):]

    packet_count = len(traffic_data[ip])

    if packet_count > 0 and len(service_data[ip]) > 0:
        same_srv_count = service_data[ip].count(service)
        same_srv_rate  = same_srv_count / len(service_data[ip])
    else:
        same_srv_count = 0
        same_srv_rate  = 0.0

    diff_srv_rate = 1.0 - same_srv_rate
    
    # KDDTrain+ hard ceilings. 
    # The dataset never exceeds 511 for time-based counts, and 255 for host-based counts.
    # Exceeding these confuses the Random Forest splits.
    kdd_count          = min(packet_count, 511)
    kdd_srv_count      = min(same_srv_count, 511)
    kdd_dst_host       = min(packet_count, 255)
    kdd_dst_host_srv   = min(same_srv_count, 255)
    
    # Flag 5 is S0 (SYN) in our aligned mapping
    serror_rate = 1.0 if flag == 5 else 0.0 

    features = {
        "count":                       kdd_count,
        "srv_count":                   kdd_srv_count,
        "service":                     service,
        "flag":                        flag,
        "same_srv_rate":               round(same_srv_rate, 4),
        "diff_srv_rate":               round(diff_srv_rate, 4),
        "dst_host_count":              kdd_dst_host,
        "dst_host_srv_count":          kdd_dst_host_srv,
        "dst_host_same_srv_rate":      round(same_srv_rate, 4),
        "dst_host_diff_srv_rate":      round(diff_srv_rate, 4),
        "serror_rate":                 serror_rate,
        "srv_serror_rate":             serror_rate,
        "dst_host_serror_rate":        serror_rate,
        "dst_host_srv_serror_rate":    serror_rate,
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