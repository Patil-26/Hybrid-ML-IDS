"""
preprocessing.py
Handles two tasks:
1. preprocess_input     — prepares live packet features for ML prediction
2. load_and_preprocess_data — loads and prepares NSL-KDD dataset for training
"""

import pandas as pd

# NSL-KDD feature columns used during training
# All 41 features must be present in exact order for the model to work
FEATURE_COLUMNS = [
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


def preprocess_input(packet_features):
    """
    Convert a dictionary of live packet features into a
    41-column DataFrame matching the training feature structure.
    Missing columns are filled with 0.
    """

    df = pd.DataFrame([packet_features])

    # Add any missing columns with default value 0
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0

    # Reorder columns to match training order exactly
    df = df[FEATURE_COLUMNS]

    return df


def load_and_preprocess_data(filepath):
    """
    Load the NSL-KDD dataset from a text file and prepare it for training.
    - Assigns correct column names
    - Converts labels to binary (0 = normal, 1 = attack)
    - Encodes categorical columns as numeric codes
    Returns X (features) and y (labels).
    """

    # NSL-KDD has no header — define column names manually
    columns = FEATURE_COLUMNS + ["label", "difficulty"]

    df = pd.read_csv(filepath, header=None, names=columns)

    # Drop difficulty rating column — not needed for training
    df = df.drop(columns=["difficulty"])

    # Convert labels to binary
    # normal = 0, any attack type = 1
    df["label"] = df["label"].apply(lambda x: 0 if x.strip() == "normal" else 1)

    # Encode categorical columns as numeric codes
    # protocol_type: tcp/udp/icmp → 0/1/2
    # service: http/ftp/smtp etc → numeric
    # flag: SF/S0/REJ etc → numeric
    for col in ["protocol_type", "service", "flag"]:
        df[col] = pd.Categorical(df[col]).codes

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    return X, y