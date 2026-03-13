import os
import joblib
from scapy.all import sniff, IP

from preprocessing import preprocess_input
from traffic_analyzer import analyze_traffic
from logger import initialize_log, log_attack
from prevention import block_ip

# ─── Paths ────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "best_model.pkl")

# ─── Load Weighted Ensemble Model ─────────────────────────────────────
if not os.path.exists(MODEL_PATH):
    print("[ERROR] No trained model found.")
    print("        Please run: python3 src/evaluation.py first")
    exit(1)

model = joblib.load(MODEL_PATH)
print(f"[INFO] Weighted Ensemble model loaded from {MODEL_PATH}")

# ─── Initialize Log File ──────────────────────────────────────────────
initialize_log()


# ─── Process Each Packet ──────────────────────────────────────────────
def process_packet(packet):
    try:
        if packet.haslayer(IP):

            src_ip = packet[IP].src
            packet_length = len(packet)

            # Step 1 — Analyze traffic, get features + attack type
            features, attack_type = analyze_traffic(src_ip, packet_length)

            # Step 2 — Preprocess into 41-column feature vector
            feature_vector = preprocess_input(features)

            # Step 3 — Weighted ensemble prediction
            prediction = model.predict(feature_vector)[0]

            # Step 4 — Confidence score (probability of predicted class)
            confidence = round(model.predict_proba(feature_vector)[0].max(), 4)

            # Step 5 — Respond based on prediction
            if prediction == 1:

                attack_label = attack_type if attack_type else "intrusion"

                print(f"[ALERT] Attack from {src_ip} | Type: {attack_label} | Confidence: {confidence}")

                # Block IP and log attack
                action = block_ip(src_ip)
                log_attack(src_ip, attack_label, confidence, action)

            else:
                print(f"[OK]    Normal traffic from {src_ip} | Confidence: {confidence}")

    except Exception as e:
        print(f"[ERROR] Failed to process packet: {e}")


# ─── Start Monitoring ─────────────────────────────────────────────────
def start_monitoring():
    print("\n" + "=" * 50)
    print("   Hybrid ML-IDS — Real-Time Monitoring Active")
    print("   Model  : Weighted Soft Voting Ensemble")
    print("   RF: 0.6 | SVM: 0.2 | LR: 0.2")
    print("=" * 50 + "\n")
    sniff(prn=process_packet, store=False)


if __name__ == "__main__":
    start_monitoring()