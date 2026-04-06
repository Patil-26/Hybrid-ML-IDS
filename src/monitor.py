"""
monitor.py
Real-time network packet capture and intrusion detection.
Loads the trained weighted ensemble model and classifies
every live packet as normal or an attack.
Implements 3-level escalation: warning → alert → block
"""

import os
import joblib
from scapy.all import sniff, IP

from preprocessing import preprocess_input
from traffic_analyzer import analyze_traffic
from feature_engineer import extract_features
from logger import initialize_log, log_attack
from prevention import handle_ip

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

# ─── Attack Detection Threshold ───────────────────────────────────────
# Lowered from default 0.5 to reduce missed attacks (False Negatives)
# For IDS, missing an attack is more dangerous than a false alarm
ATTACK_THRESHOLD = 0.40

# ─── Initialize Log File ──────────────────────────────────────────────
initialize_log()


def process_packet(packet):
    """
    Callback function triggered for every captured packet.
    Extracts features, runs ML prediction, and responds
    based on severity level.
    """
    try:
        if packet.haslayer(IP):

            src_ip        = packet[IP].src
            dst_ip        = packet[IP].dst
            packet_length = len(packet)

            # Step 1 — Extract rich features directly from packet headers
            packet_features = extract_features(packet)

            # Step 2 — Analyze traffic patterns over sliding time window
            features, attack_type, severity = analyze_traffic(
                ip            = src_ip,
                packet_length = packet_length,
                service       = packet_features.get("service", 0),
                dst_ip        = dst_ip,
                flag          = packet_features.get("flag", 0)
            )

            # Step 3 — Merge features correctly
            # Start with packet_features as base
            # Then overlay analyzer features on top
            # This prevents packet_features from overwriting
            # count, rates etc with 0
            merged   = packet_features.copy()
            merged.update(features)
            features = merged

            # Step 4 — Preprocess into 41-column feature vector
            feature_vector = preprocess_input(features)

            # Step 5 — Get probability scores from ensemble
            proba        = model.predict_proba(feature_vector)[0]
            attack_proba = proba[1]

            # Step 6 — Apply optimized threshold
            prediction = 1 if attack_proba >= ATTACK_THRESHOLD else 0

            # Step 7 — Confidence score
            confidence = round(max(proba), 4)

            # Step 8 — Determine final severity
            # ML model can also escalate to block if prediction == 1
            if prediction == 1 and severity is None:
                severity    = "block"
                attack_type = "ml_intrusion"

            # Step 9 — Respond based on severity level
            if severity == "block":
                print(f"[BLOCK]   Attack from {src_ip} | Type: {attack_type} | Confidence: {confidence}")
                action = handle_ip(src_ip, "block")
                log_attack(src_ip, attack_type, confidence, "block", action)

            elif severity == "alert":
                print(f"[ALERT]   High traffic from {src_ip} | Type: {attack_type} | Confidence: {confidence}")
                action = handle_ip(src_ip, "alert")
                log_attack(src_ip, attack_type, confidence, "alert", action)

            elif severity == "warning":
                print(f"[WARNING] Suspicious traffic from {src_ip} | Confidence: {confidence}")
                action = handle_ip(src_ip, "warning")
                log_attack(src_ip, attack_type, confidence, "warning", action)

            else:
                print(f"[OK]      Normal traffic from {src_ip} | Confidence: {confidence}")

    except Exception as e:
        print(f"[ERROR] Failed to process packet: {e}")


def start_monitoring():
    """Start real-time packet sniffing."""
    print("\n" + "=" * 55)
    print("   Hybrid ML-IDS — Real-Time Monitoring Active")
    print("   Model     : Weighted Soft Voting Ensemble")
    print("   RF: 0.6   | SVM: 0.2 | LR: 0.2")
    print(f"   Threshold : {ATTACK_THRESHOLD} (optimized)")
    print("   Escalation: Warning → Alert → Block")
    print("=" * 55 + "\n")
    sniff(prn=process_packet, store=False)


if __name__ == "__main__":
    start_monitoring()