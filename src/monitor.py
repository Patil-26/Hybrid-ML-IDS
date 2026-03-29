"""
monitor.py
Real-time network packet capture and intrusion detection.
Loads the trained weighted ensemble model and classifies
every live packet as normal or an attack.
"""

import os
import joblib
from scapy.all import sniff, IP

from preprocessing import preprocess_input
from traffic_analyzer import analyze_traffic
from feature_engineer import extract_features
from logger import initialize_log, log_attack
from prevention import block_ip

# ─── Paths ────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "best_model.pkl")

# ─── Load Weighted Ensemble Model ─────────────────────────────────────
if not os.path.exists(MODEL_PATH):
    print("[ERROR] No trained model found.")
    print("        Please run: python3 src/evaluation.py first")
    exit(1)

model = joblib.load(MODEL_PATH)
print("[INFO] Weighted Ensemble model loaded successfully")

# ─── Initialize Log File ──────────────────────────────────────────────
initialize_log()


def process_packet(packet):
    """
    Callback function triggered for every captured packet.
    Extracts features, runs ML prediction, and responds
    if an attack is detected.
    """
    try:
        if packet.haslayer(IP):

            src_ip        = packet[IP].src
            dst_ip        = packet[IP].dst
            packet_length = len(packet)

            # Step 1 — Extract rich features directly from packet headers
            packet_features = extract_features(packet)

            # Step 2 — Analyze traffic patterns over sliding time window
            # Pass service, dst_ip and flag for richer rate-based features
            features, attack_type = analyze_traffic(
                ip            = src_ip,
                packet_length = packet_length,
                service       = packet_features.get("service", 0),
                dst_ip        = dst_ip,
                flag          = packet_features.get("flag", 0)
            )

            # Step 3 — Merge packet-level features into analyzer features
            # packet_features override analyzer defaults where available
            features.update(packet_features)

            # Step 4 — Preprocess into 41-column feature vector
            feature_vector = preprocess_input(features)

            # Step 5 — Weighted ensemble prediction
            prediction = model.predict(feature_vector)[0]

            # Step 6 — Confidence score (max probability across classes)
            confidence = round(model.predict_proba(feature_vector)[0].max(), 4)

            # Step 7 — Trigger if ML model OR rule-based detection fires
            # Rule-based DoS threshold acts as safety net for sparse features
            if prediction == 1 or attack_type is not None:

                attack_label = attack_type if attack_type else "ml_intrusion"

                print(f"[ALERT] Attack from {src_ip} | Type: {attack_label} | Confidence: {confidence}")

                action = block_ip(src_ip)
                log_attack(src_ip, attack_label, confidence, action)

            else:
                print(f"[OK]    Normal traffic from {src_ip} | Confidence: {confidence}")

    except Exception as e:
        print(f"[ERROR] Failed to process packet: {e}")


def start_monitoring():
    """Start real-time packet sniffing."""
    print("\n" + "=" * 55)
    print("   Hybrid ML-IDS — Real-Time Monitoring Active")
    print("   Model  : Weighted Soft Voting Ensemble")
    print("   RF: 0.6 | SVM: 0.2 | LR: 0.2")
    print("   Detection: ML Prediction + Rule-Based (DoS)")
    print("=" * 55 + "\n")
    sniff(prn=process_packet, store=False)


if __name__ == "__main__":
    start_monitoring()