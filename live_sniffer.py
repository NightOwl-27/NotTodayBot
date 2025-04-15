import os
import csv
import logging
from time import time
from scapy.all import sniff, IP, TCP, UDP
from my_feature_extractor import LiveFeatureExtractor
from voting_system import is_packet_malicious
import sys
import signal
from scapy.utils import PcapWriter

# --- CONFIGURATION ---
LOG_DIR = "logs"
LOG_TXT_FILE = os.path.join(LOG_DIR, "malicious_packets.log")
LOG_CSV_FILE = os.path.join(LOG_DIR, "malicious_packets_data.csv")
FILTER = "tcp port 80 or tcp port 443 or port 22 or port 53 or port 3389 or udp port 1900 or udp port 47808"

# --- SETUP ---
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=LOG_TXT_FILE,
    level=logging.INFO,
    format='%(asctime)s - INFO - Malicious packet detected [Live]'
)

# --- INIT ---
extractor = LiveFeatureExtractor()

# --- Ensure CSV Header ---
if not os.path.exists(LOG_CSV_FILE):
    with open(LOG_CSV_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["timestamp", "src_ip", "dst_ip", "protocol", "attack_type"])

# --- Packet Callback ---
def process_packet(pkt):
    try:
        ts = time()
        features = extractor.process_packet(pkt, ts)
        if features is None:
            return

        is_malicious, attack_type = is_packet_malicious(features, verbose=False)
        if is_malicious:
            logging.info(f"Detected {attack_type} [Live]")
            src_ip = pkt[IP].src if IP in pkt else "N/A"
            dst_ip = pkt[IP].dst if IP in pkt else "N/A"
            protocol = pkt.proto if IP in pkt else "N/A"

            with open(LOG_CSV_FILE, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([ts, src_ip, dst_ip, protocol, attack_type])

    except Exception as e:
        print("❌ Error processing packet:", e)

def graceful_shutdown(signum, frame):
    print("\n🛑 Shutting down live sniffer.")
    sys.exit(0)
    
signal.signal(signal.SIGTERM, graceful_shutdown)


# --- Start Sniffing ---
print("🚦 Monitoring live traffic...")
sniff(filter=FILTER, prn=process_packet, store=0)
