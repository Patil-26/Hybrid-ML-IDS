import os

# Directory for logs
LOG_DIR = "logs"

# File where blocked IPs will be stored
BLACKLIST_FILE = os.path.join(LOG_DIR, "blacklist.txt")


def ensure_log_directory():
    """Ensure logs directory exists."""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)


def load_blocked_ips():
    """Load already blocked IPs from blacklist file."""
    ensure_log_directory()

    if not os.path.exists(BLACKLIST_FILE):
        open(BLACKLIST_FILE, "w").close()

    with open(BLACKLIST_FILE, "r") as f:
        blocked_ips = set(line.strip() for line in f if line.strip())

    return blocked_ips


def block_ip(ip):
    """Block a malicious IP address."""
    ensure_log_directory()

    blocked_ips = load_blocked_ips()

    if ip in blocked_ips:
        print(f"[INFO] IP already blocked: {ip}")
        return "already_blocked"

    with open(BLACKLIST_FILE, "a") as f:
        f.write(ip + "\n")

    print(f"[ALERT] Blocked IP: {ip}")
    return "blocked"