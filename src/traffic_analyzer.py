from collections import defaultdict
import time

# store packet timestamps per IP
traffic_data = defaultdict(list)

# detection thresholds
PACKET_THRESHOLD = 100
TIME_WINDOW = 5  # seconds


def analyze_traffic(ip, packet_length):

    now = time.time()

    # add current packet time
    traffic_data[ip].append(now)

    # remove old timestamps
    traffic_data[ip] = [
        t for t in traffic_data[ip] if now - t <= TIME_WINDOW
    ]

    packet_count = len(traffic_data[ip])

    # feature dictionary for ML model
    features = {
        "src_bytes": packet_length,
        "dst_bytes": 0,
        "count": packet_count,
        "srv_count": packet_count
    }

    # simple DoS detection logic
    if packet_count > PACKET_THRESHOLD:
        return features, "dos_attack"

    return features, None