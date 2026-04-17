"""
feature_engineer.py
Extracts network features from raw Scapy packets.
Maps packet attributes to NSL-KDD feature format
for input into the ML model.
"""

import pandas as pd
from scapy.all import TCP, UDP, IP, ICMP, Raw

# NSL-KDD features used during training
MODEL_FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

# Map common destination ports to exactly match Pandas Categorical alphabetical indices
PORT_SERVICE_MAP = {
    80:   22,  # http
    443:  22,  # mapping https to http for proxy
    21:   16,  # ftp
    22:   54,  # ssh
    23:   58,  # telnet
    25:   51,  # smtp
}

# Map TCP flags to exactly match Pandas Categorical alphabetical indices
# KDDTrain+ list: OTH=0, REJ=1, RSTO=2, RSTOS0=3, RSTR=4, S0=5, S1=6, S2=7, S3=8, SF=9, SH=10
TCP_FLAG_MAP = {
    0x002: 5,   # SYN only        → S0 (Index 5)
    0x012: 9,   # SYN-ACK         → SF (Index 9)
    0x010: 9,   # ACK             → SF (Index 9)
    0x018: 9,   # PSH-ACK         → SF (Index 9)
    0x004: 2,   # RST             → RSTO (Index 2)
    0x014: 2,   # RST-ACK         → RSTO (Index 2)
    0x011: 9,   # FIN-ACK         → SF (Index 9)
    0x001: 0,   # FIN only        → OTH (Index 0)
}


def extract_features(packet):
    features = dict.fromkeys(MODEL_FEATURES, 0)

    if packet.haslayer(IP):
        ip_layer = packet[IP]

        # Extract real payload size
        payload_size = len(packet[Raw].load) if packet.haslayer(Raw) else 0

        features["src_bytes"] = payload_size
        features["dst_bytes"] = payload_size

        features["land"] = 1 if ip_layer.src == ip_layer.dst else 0
        features["wrong_fragment"] = 1 if ip_layer.frag > 0 else 0

        if packet.haslayer(TCP):
            features["protocol_type"] = 1
            tcp_layer = packet[TCP]

            flag_value = int(tcp_layer.flags)
            features["flag"] = TCP_FLAG_MAP.get(flag_value, 0)

            features["urgent"] = 1 if tcp_layer.urgptr > 0 else 0

            # Default to 49 (private) if port is unknown, as DoS attacks often target private
            features["service"] = PORT_SERVICE_MAP.get(tcp_layer.dport, 49)

        elif packet.haslayer(UDP):
            features["protocol_type"] = 2
            udp_layer = packet[UDP]
            features["service"] = PORT_SERVICE_MAP.get(udp_layer.dport, 49)

        elif packet.haslayer(ICMP):
            features["protocol_type"] = 0

    return features


def convert_to_dataframe(features):
    return pd.DataFrame([features])
