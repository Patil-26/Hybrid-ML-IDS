import os
import csv
from datetime import datetime

LOG_FILE = "logs/attack_logs.csv"


def initialize_log():
    """Create log file with header if it doesn't exist"""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "ip", "attack_type", "confidence", "action"])


def log_attack(ip, attack_type, confidence, action):
    """Write attack to log file"""

    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now(),
            ip,
            attack_type,
            confidence,
            action
        ])