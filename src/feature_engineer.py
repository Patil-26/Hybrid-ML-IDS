"""
feature_engineer.py
Extracts network features from raw Scapy packets.
Maps packet attributes to NSL-KDD feature format
for input into the ML model.
"""

import pandas as pd
from scapy.all import TCP, UDP, IP, ICMP

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

# Map common destination ports to NSL-KDD service codes
PORT_SERVICE_MAP = {
    80:   1,   # http
    443:  2,   # https
    21:   3,   # ftp
    22:   4,   # ssh
    23:   5,   # telnet
    25:   6,   # smtp
    53:   7,   # domain
    110:  8,   # pop3
    143:  9,   # imap
    3306: 10,  # sql
    8080: 11,  # http-alt
}

# Map TCP flag values to NSL-KDD flag codes
# NSL-KDD uses: SF=normal, S0=no response, REJ=rejected, RSTO=reset
TCP_FLAG_MAP = {
    0x002: 1,   # SYN only        → S0 (connection attempt, no response)
    0x012: 2,   # SYN-ACK         → SF (normal established)
    0x010: 2,   # ACK             → SF (normal)
    0x018: 2,   # PSH-ACK         → SF (normal data transfer)
    0x004: 3,   # RST             → RSTO (reset)
    0x014: 3,   # RST-ACK         → RSTO (reset)
    0x011: 4,   # FIN-ACK         → SF (normal close)
    0x001: 5,   # FIN only        → unusual
}


def extract_features(packet):
    """
    Extract available features from a live Scapy packet.
    Extracts src_bytes, dst_bytes, protocol_type, flag,
    service, land, urgent, wrong_fragment from packet headers.
    Remaining features default to 0 and are filled by preprocessing.
    """

    # Initialize all features to 0
    features = dict.fromkeys(MODEL_FEATURES, 0)

    if packet.haslayer(IP):

        ip_layer = packet[IP]

        # src_bytes — total packet size in bytes
        features["src_bytes"] = len(packet)

        # dst_bytes — approximate as same as src for now
        features["dst_bytes"] = len(packet)

        # land — 1 if src IP equals dst IP (loopback attack indicator)
        features["land"] = 1 if ip_layer.src == ip_layer.dst else 0

        # wrong_fragment — IP fragment offset (unusual = possible attack)
        features["wrong_fragment"] = 1 if ip_layer.frag > 0 else 0

        # Protocol type — TCP=1, UDP=2, ICMP=0
        if packet.haslayer(TCP):
            features["protocol_type"] = 1

            tcp_layer = packet[TCP]

            # flag — TCP connection state mapped to NSL-KDD codes
            flag_value = int(tcp_layer.flags)
            features["flag"] = TCP_FLAG_MAP.get(flag_value, 0)

            # urgent — urgent pointer set (used in some attacks)
            features["urgent"] = 1 if tcp_layer.urgptr > 0 else 0

            # service — destination port mapped to service type
            features["service"] = PORT_SERVICE_MAP.get(tcp_layer.dport, 0)

            # serror_rate — SYN flag without ACK = connection error pattern
            # 1.0 if pure SYN (S0 pattern), 0 otherwise
            if int(tcp_layer.flags) == 0x002:
                features["serror_rate"]     = 1.0
                features["srv_serror_rate"] = 1.0

        elif packet.haslayer(UDP):
            features["protocol_type"] = 2
            udp_layer = packet[UDP]
            features["service"] = PORT_SERVICE_MAP.get(udp_layer.dport, 0)

        elif packet.haslayer(ICMP):
            features["protocol_type"] = 0

    return features


def convert_to_dataframe(features):
    """Convert a feature dictionary into a single-row DataFrame."""
    return pd.DataFrame([features])