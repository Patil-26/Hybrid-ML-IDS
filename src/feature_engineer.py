import pandas as pd

# NSL-KDD features used during training
MODEL_FEATURES = [
'duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
'wrong_fragment','urgent','hot','num_failed_logins','logged_in',
'num_compromised','root_shell','su_attempted','num_root',
'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
'is_host_login','is_guest_login','count','srv_count','serror_rate',
'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
'dst_host_same_srv_rate','dst_host_diff_srv_rate',
'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
'dst_host_serror_rate','dst_host_srv_serror_rate',
'dst_host_rerror_rate','dst_host_srv_rerror_rate'
]


def extract_features(packet):

    features = dict.fromkeys(MODEL_FEATURES, 0)

    # Basic mapping from packet → IDS features

    if packet.haslayer("IP"):
        features["src_bytes"] = len(packet)
        features["dst_bytes"] = len(packet)

    if packet.haslayer("TCP"):
        features["protocol_type"] = 1
    elif packet.haslayer("UDP"):
        features["protocol_type"] = 2
    else:
        features["protocol_type"] = 0

    return features


def convert_to_dataframe(features):

    df = pd.DataFrame([features])

    return df