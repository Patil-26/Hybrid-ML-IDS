import os

BLACKLIST_FILE = "blacklist.txt"


def initialize_blacklist():
    """
    Creates blacklist file if it doesn't exist
    """
    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "w") as f:
            pass


def is_blocked(ip):
    """
    Checks if an IP is already blocked
    """
    if not os.path.exists(BLACKLIST_FILE):
        return False

    with open(BLACKLIST_FILE, "r") as f:
        blocked_ips = f.read().splitlines()

    return ip in blocked_ips


def block_ip(ip):
    """
    Adds malicious IP to blacklist
    """
    if not is_blocked(ip):
        with open(BLACKLIST_FILE, "a") as f:
            f.write(ip + "\n")

        print(f"[PREVENTION] Blocked IP: {ip}")
        return "blocked"

    else:
        print(f"[PREVENTION] IP already blocked: {ip}")
        return "already_blocked"
    
if __name__ == "__main__":
    initialize_blacklist()