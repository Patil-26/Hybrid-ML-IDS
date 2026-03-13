"""
traffic_analyzer.py
Tracks packet frequency per IP address over a sliding time window.
Detects DoS attacks based on packet count threshold.
Returns a feature dictionary and attack label for each packet.
"""

from collections import defaultdict
import time

# Store packet timestamps per IP address
traffic_data = defaultdict(list)

# Detection thresholds
# If an IP sends more than PACKET_THRESHOLD packets
# within TIME_WINDOW seconds it is flagged as a DoS attack
PACKET_THRESHOLD = 100
TIME_WINDOW      = 5  # seconds


def analyze_traffic(ip, packet_length):
    """
    Analyze traffic from a given IP address.
    Returns a feature dictionary and attack type (or None if normal).
    """

    now = time.time()

    # Record current packet timestamp
    traffic_data[ip].append(now)

    # Remove timestamps outside the time window (sliding window)
    traffic_data[ip] = [
        t for t in traffic_data[ip] if now - t <= TIME_WINDOW
    ]

    packet_count = len(traffic_data[ip])

    # Build feature dictionary for ML model
    features = {
        "src_bytes":  packet_length,
        "dst_bytes":  0,
        "count":      packet_count,
        "srv_count":  packet_count
    }

    # Rule-based DoS detection
    if packet_count > PACKET_THRESHOLD:
        return features, "dos_attack"

    return features, None