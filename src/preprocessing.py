import pandas as pd

FEATURE_COLUMNS = [
"duration","protocol_type","service","flag","src_bytes","dst_bytes",
"land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root","num_file_creations",
"num_shells","num_access_files","num_outbound_cmds","is_host_login",
"is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
"rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
"srv_diff_host_rate","dst_host_count","dst_host_srv_count",
"dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate",
"dst_host_rerror_rate","dst_host_srv_rerror_rate"
]

def preprocess_input(packet_features):
    df = pd.DataFrame([packet_features])
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0
    df = df[FEATURE_COLUMNS]
    return df


def load_and_preprocess_data(filepath):
    """
    Load NSL-KDD dataset and return X (features) and y (labels).
    """

    # NSL-KDD has no header so we define column names manually
    columns = FEATURE_COLUMNS + ["label", "difficulty"]

    df = pd.read_csv(filepath, header=None, names=columns)

    # Drop difficulty column
    df = df.drop(columns=["difficulty"])

    # Convert label to binary — normal=0, attack=1
    df["label"] = df["label"].apply(lambda x: 0 if x.strip() == "normal" else 1)

    # Encode categorical columns
    for col in ["protocol_type", "service", "flag"]:
        df[col] = pd.Categorical(df[col]).codes

    # Split features and label
    X = df[FEATURE_COLUMNS]
    y = df["label"]

    return X, y