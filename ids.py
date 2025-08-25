"""
Intrusion Detection System (IDS)
Author: Pranya Gupta
Description:
    - Monitors ARP spoofing attacks
    - Validates IP-MAC bindings
    - Logs suspicious activity to alerts.csv
"""

from scapy.all import sniff, ARP
import csv
from datetime import datetime

# Known IP-MAC bindings (could be extended with a config file)
trusted_bindings = {
    "192.168.1.1": "00:11:22:33:44:55",  # Example router MAC
}

def log_alert(message):
    """Log alerts into a CSV file with timestamp."""
    with open("alerts.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now(), message])
    print(f"[ALERT] {message}")

def detect_arp(packet):
    """Detect ARP spoofing based on trusted IP-MAC mapping."""
    if packet.haslayer(ARP):
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        if ip in trusted_bindings and trusted_bindings[ip] != mac:
            log_alert(f"ARP Spoofing Detected! IP {ip} is being spoofed by {mac}")

if __name__ == "__main__":
    print("Starting IDS... Monitoring ARP packets.")
    sniff(store=False, prn=detect_arp, filter="arp")
