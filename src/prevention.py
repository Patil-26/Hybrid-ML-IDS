"""
prevention.py
Handles IP blocking for detected attackers.
Maintains a blacklist file to prevent duplicate blocking
and persist blocked IPs across sessions.
"""

import os

# ─── Paths ────────────────────────────────────────────────────────────
BASE_DIR       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR        = os.path.join(BASE_DIR, "logs")
BLACKLIST_FILE = os.path.join(LOG_DIR, "blacklist.txt")


def ensure_log_directory():
    """Create logs directory if it doesn't exist."""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)


def load_blocked_ips():
    """
    Load the set of already blocked IP addresses from the blacklist file.
    Returns an empty set if the file doesn't exist yet.
    """
    ensure_log_directory()

    if not os.path.exists(BLACKLIST_FILE):
        open(BLACKLIST_FILE, "w").close()

    with open(BLACKLIST_FILE, "r") as f:
        blocked_ips = set(line.strip() for line in f if line.strip())

    return blocked_ips


def block_ip(ip):
    """
    Block a malicious IP address by adding it to the blacklist file.
    Skips if the IP is already blocked.
    Returns action taken: 'blocked' or 'already_blocked'.
    """
    ensure_log_directory()

    blocked_ips = load_blocked_ips()

    if ip in blocked_ips:
        print(f"[INFO] IP already blocked: {ip}")
        return "already_blocked"

    with open(BLACKLIST_FILE, "a") as f:
        f.write(ip + "\n")

    print(f"[BLOCKED] {ip}")
    return "blocked"