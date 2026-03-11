from collections import defaultdict
import time

# store packet timestamps per IP
traffic_data = defaultdict(list)

# detection thresholds
PACKET_THRESHOLD = 100
TIME_WINDOW = 5  # seconds


def analyze_traffic(ip):
    now = time.time()

    # add current packet time
    traffic_data[ip].append(now)

    # remove old timestamps
    traffic_data[ip] = [
        t for t in traffic_data[ip] if now - t <= TIME_WINDOW
    ]

    # check packet rate
    if len(traffic_data[ip]) > PACKET_THRESHOLD:
        return "dos_attack"

    return None