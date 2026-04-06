"""
prevention.py
Handles IP warning and blocking for detected attackers.
Implements a 3-level escalation system:
  Level 1 — WARNING  : log and monitor, do not block
  Level 2 — ALERT    : log and notify, do not block yet
  Level 3 — BLOCK    : add to blacklist
"""

import os

# ─── Paths ────────────────────────────────────────────────────────────
BASE_DIR       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR        = os.path.join(BASE_DIR, "logs")
BLACKLIST_FILE = os.path.join(LOG_DIR, "blacklist.txt")
WARNING_FILE   = os.path.join(LOG_DIR, "warnings.txt")


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


def load_warned_ips():
    """
    Load the set of already warned IP addresses.
    Returns an empty set if the file doesn't exist yet.
    """
    ensure_log_directory()

    if not os.path.exists(WARNING_FILE):
        open(WARNING_FILE, "w").close()

    with open(WARNING_FILE, "r") as f:
        warned_ips = set(line.strip() for line in f if line.strip())

    return warned_ips


def warn_ip(ip):
    """
    Issue a warning for a suspicious IP address.
    Does not block — just logs the warning.
    Returns action taken.
    """
    ensure_log_directory()

    warned_ips = load_warned_ips()

    if ip in warned_ips:
        return "already_warned"

    with open(WARNING_FILE, "a") as f:
        f.write(ip + "\n")

    print(f"[WARNING] Suspicious activity from {ip} — monitoring")
    return "warned"


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


def handle_ip(ip, severity):
    """
    Handle an IP based on its severity level.
    warning → warn and monitor
    alert   → warn more strongly
    block   → add to blacklist
    Returns action taken.
    """
    if severity == "warning":
        return warn_ip(ip)

    elif severity == "alert":
        print(f"[ALERT] High traffic from {ip} — escalating")
        return warn_ip(ip)

    elif severity == "block":
        return block_ip(ip)

    return "no_action"