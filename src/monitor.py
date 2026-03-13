import os
import joblib
from scapy.all import sniff, IP

from preprocessing import preprocess_input
from traffic_analyzer import analyze_traffic
from logger import initialize_log, log_attack
from prevention import block_ip

# Fix path regardless of where you run from
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "best_model.pkl")

# Load trained model
model = joblib.load(MODEL_PATH)

# Initialize log file with headers if not exists
initialize_log()


def process_packet(packet):
    try:
        if packet.haslayer(IP):

            src_ip = packet[IP].src
            packet_length = len(packet)

            # Analyze traffic → get features + attack type
            features, attack_type = analyze_traffic(src_ip, packet_length)

            # Preprocess → get 41-column feature vector
            processed = preprocess_input(features)

            # ML model prediction
            prediction = model.predict(processed)[0]

            # Confidence score
            confidence = round(model.predict_proba(processed)[0].max(), 4)

            # If attack detected
            if prediction == 1:

                attack_label = attack_type if attack_type else "intrusion"

                print(f"[ALERT] Attack detected from {src_ip} | Type: {attack_label} | Confidence: {confidence}")

                # Block and log
                action = block_ip(src_ip)
                log_attack(src_ip, attack_label, confidence, action)

            else:
                print(f"[OK] Normal traffic from {src_ip} | Confidence: {confidence}")

    except Exception as e:
        print(f"[ERROR] {e}")


def start_monitoring():
    print("=" * 50)
    print("  Hybrid ML-IDS — Real-Time Monitoring Active")
    print("=" * 50)
    sniff(prn=process_packet, store=False)


if __name__ == "__main__":
    start_monitoring()