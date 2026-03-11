import joblib
import pandas as pd
from scapy.all import sniff, IP
from preprocessing import preprocess_input
from logger import log_attack, initialize_log
from prevention import block_ip
from traffic_analyzer import analyze_traffic

print("Starting IDS monitor...")

# initialize log file
initialize_log()

# load trained model
model = joblib.load("models/best_model.pkl")

print("Model loaded successfully")


def process_packet(packet):
    try:

        if packet.haslayer(IP):

            src_ip = packet[IP].src

            # 1️⃣ Traffic behavior analysis
            attack_type = analyze_traffic(src_ip)

            if attack_type == "dos_attack":
                print(f"[ALERT] DoS attack detected from {src_ip}")

                block_ip(src_ip)
                log_attack(src_ip, "dos_attack", 1.0, "blocked")

                return

            # 2️⃣ ML-based detection

            features = {
                "duration": 0,
                "src_bytes": len(packet),
                "dst_bytes": len(packet),
                "count": 1
            }

            df = pd.DataFrame([features])

            processed = preprocess_input(df)

            prediction = model.predict(processed)[0]

            if prediction == 1:

                print(f"[ALERT] Intrusion detected from {src_ip}")

                block_ip(src_ip)
                log_attack(src_ip, "intrusion", 1.0, "blocked")

    except Exception as e:
        print("Error processing packet:", e)


# start packet capture
sniff(prn=process_packet, store=False)