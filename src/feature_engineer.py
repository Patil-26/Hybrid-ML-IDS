import pandas as pd


def extract_features(packet):
    """
    Convert a network packet into ML features
    """

    features = {}

    # Packet size
    features["packet_size"] = len(packet)

    # Protocol type
    if packet.haslayer("TCP"):
        features["protocol"] = "tcp"
    elif packet.haslayer("UDP"):
        features["protocol"] = "udp"
    else:
        features["protocol"] = "other"

    # Source and destination ports
    if packet.haslayer("TCP") or packet.haslayer("UDP"):
        features["src_port"] = packet.sport
        features["dst_port"] = packet.dport
    else:
        features["src_port"] = 0
        features["dst_port"] = 0

    return features


def convert_to_dataframe(features):
    """
    Convert extracted features into dataframe for ML model
    """

    df = pd.DataFrame([features])

    return df