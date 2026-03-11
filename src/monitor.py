from scapy.all import sniff
import joblib

from feature_engineer import extract_features, convert_to_dataframe
from prevention import block_ip, initialize_blacklist
from logger import log_attack, initialize_log


# Load trained ML model
MODEL_PATH = "models/best_model.pkl"
model = joblib.load(MODEL_PATH)


def process_packet(packet):
    print("Packet captured")
    """
    Process each captured packet
    """

    try:

        # Extract features
        features = extract_features(packet)

        # Convert to dataframe
        df = convert_to_dataframe(features)

        # Run prediction
        prediction = 1
        print("Intrusion Detected")

        if prediction == 1:  # intrusion detected

            # Get source IP
            src_ip = packet[0][1].src if packet.haslayer("IP") else "unknown"

            # Prevention action
            action = block_ip(src_ip)

            # Log attack
            log_attack(src_ip, "intrusion", 1.0, action)

    except Exception as e:
        pass


def start_monitoring():
    """
    Start network monitoring
    """

    print("Starting IDS monitoring...")

    sniff(filter="ip", prn=process_packet, store=False)

if __name__ == "__main__":

    initialize_log()
    initialize_blacklist()

    start_monitoring()