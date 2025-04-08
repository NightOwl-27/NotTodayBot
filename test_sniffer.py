from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import os

LOG_FILE = "logs/malicious_packets.log"
os.makedirs("logs", exist_ok=True)

# Basic condition for a "malicious" packet — you can replace this with real detection later
def is_malicious(packet):
    if packet.haslayer(TCP) and (packet[TCP].dport == 4444 or packet[TCP].flags == "S"):
        return "Suspicious_TCP"
    elif packet.haslayer(UDP) and packet[UDP].dport == 5555:
        return "Suspicious_UDP"
    return None

def process_packet(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    src = packet[IP].src if IP in packet else "N/A"
    dst = packet[IP].dst if IP in packet else "N/A"
    
    attack_type = is_malicious(packet)
    if attack_type:
        log_entry = f"{timestamp} - INFO - Malicious packet detected [{attack_type}] from {src} to {dst}"
        print(log_entry)
        with open(LOG_FILE, "a") as log:
            log.write(log_entry + "\n")

print("🔎 Starting live packet sniffing...")
sniff(prn=process_packet, store=False)
