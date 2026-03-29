"""
traffic_analyzer.py
Tracks packet frequency per IP address over a sliding time window.
Detects DoS attacks based on packet count threshold.
Also computes connection rate features for the ML model.
Returns a feature dictionary and attack label for each packet.
"""

from collections import defaultdict
import time

# Store packet timestamps per IP address
traffic_data = defaultdict(list)

# Store per-IP service counts for same_srv_rate calculation
service_data = defaultdict(list)

# Store per-IP destination host counts
dst_host_data = defaultdict(set)

# Detection thresholds
PACKET_THRESHOLD = 100
TIME_WINDOW      = 5  # seconds


def analyze_traffic(ip, packet_length, service=0, dst_ip=None, flag=0):
    """
    Analyze traffic from a given IP address.
    Computes rate-based features that were missing from the feature vector.
    Returns a feature dictionary and attack type (or None if normal).
    """

    now = time.time()

    # Record current packet
    traffic_data[ip].append(now)
    service_data[ip].append(service)

    if dst_ip:
        dst_host_data[ip].add(dst_ip)

    # Remove entries outside time window
    traffic_data[ip] = [t for t in traffic_data[ip] if now - t <= TIME_WINDOW]
    service_data[ip] = service_data[ip][-len(traffic_data[ip]):]

    packet_count = len(traffic_data[ip])

    # same_srv_rate — ratio of packets going to same service
    if packet_count > 0 and len(service_data[ip]) > 0:
        same_srv_count = service_data[ip].count(service)
        same_srv_rate  = same_srv_count / len(service_data[ip])
    else:
        same_srv_rate = 0.0

    # diff_srv_rate — ratio of packets going to different services
    diff_srv_rate = 1.0 - same_srv_rate

    # dst_host_count — number of unique destination hosts
    dst_host_count = len(dst_host_data[ip])

    # dst_host_same_srv_rate — approximated from same_srv_rate
    dst_host_same_srv_rate = same_srv_rate

    # dst_host_diff_srv_rate — approximated from diff_srv_rate
    dst_host_diff_srv_rate = diff_srv_rate

    # serror_rate — if flag indicates SYN only (connection error)
    serror_rate = 1.0 if flag == 1 else 0.0

    # Build feature dictionary
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

    # Rule-based DoS detection
    if packet_count > PACKET_THRESHOLD:
        return features, "dos_attack"

    return features, None