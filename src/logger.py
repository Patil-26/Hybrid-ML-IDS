"""
logger.py
Handles attack event logging with severity levels.
Writes detected attacks and warnings to a CSV file
for dashboard display.
"""

import os
import csv
from datetime import datetime

# ─── Paths ────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "logs", "attack_logs.csv")


def initialize_log():
    """
    Create the log file with column headers if it doesn't exist.
    Called once at system startup.
    """
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "ip",
                "attack_type",
                "confidence",
                "severity",
                "action"
            ])


def log_attack(ip, attack_type, confidence, severity, action):
    """
    Append a detected attack or warning record to the log file.
    Each record includes timestamp, IP, attack type, model
    confidence score, severity level and action taken.

    Severity levels:
    warning  — suspicious activity, monitoring
    alert    — high traffic, likely attack
    block    — confirmed attack, IP blocked
    """
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            str(ip),
            str(attack_type),
            str(confidence),
            str(severity),
            str(action)
        ])