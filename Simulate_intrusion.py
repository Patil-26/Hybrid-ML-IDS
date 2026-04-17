"""
simulate_intrusion.py
Simulates a Stealth Port Scan (Probe attack).
Sends single SYN packets to a variety of different destination ports.
Operates slowly to bypass the volumetric DoS thresholds and 
force the ML ensemble to catch the behavioral anomaly.
"""

from scapy.all import IP, TCP, send
import time

TARGET_IP = "192.168.0.1"

# These are the specific ports you mapped in feature_engineer.py
PORTS_TO_SCAN = 

def simulate_port_scan():
    print("\n" + "="*50)
    print(f"  Simulating Stealth Port Scan → {TARGET_IP}")
    print("  Bypassing DoS volume limits...")
    print("  Testing ML Ensemble detection capabilities...")
    print("="*50 + "\n")

    for port in PORTS_TO_SCAN:
        # We use a fixed source port but iterate through destination ports
        print(f"[*] Probing Port {port}...")
        
        send(
            IP(dst=TARGET_IP) / 
            TCP(sport=44444, dport=port, flags="S"), 
            verbose=False
        )
        
        # Sleep for 0.2 seconds. 
        # This keeps the total packet count well below the 100-packet DoS threshold,
        # forcing the traffic to be evaluated by the Random Forest/SVM/LR.
        time.sleep(0.2)

    print("\n[+] Stealth scan complete. Check your dashboard!")

if __name__ == "__main__":
    simulate_port_scan()