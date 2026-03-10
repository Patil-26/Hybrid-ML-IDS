import csv
import os
from datetime import datetime

LOG_FILE = "logs/attack_logs.csv"


def initialize_log():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                "timestamp",
                "source_ip",
                "prediction",
                "confidence",
                "action"
            ])


def log_attack(source_ip, prediction, confidence, action):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
            timestamp,
            source_ip,
            prediction,
            round(confidence, 4),
            action
        ])

    print(f"[ALERT] {timestamp} | {source_ip} | {prediction} | action={action}")


# this runs only when the file is executed directly
if __name__ == "__main__":
    initialize_log()
