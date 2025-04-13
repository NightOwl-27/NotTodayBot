import os
import random
import time
from datetime import datetime, timedelta
from collections import Counter
from scapy.all import PcapReader
from my_feature_extractor import LiveFeatureExtractor
from voting_system import is_packet_malicious
from tqdm import tqdm

# Simulation Settings
ATTACK_FILES = {
    "active_wiretap": "pcap_files/Active_Wiretap.pcap",
    "arp_mitm": "pcap_files/ARP_MitM.pcap",
    "fuzzing": "pcap_files/Fuzzing.pcap",
    "os_scan": "pcap_files/OS_Scan.pcap",
    "ssdp_flood": "pcap_files/SSDP_Flood.pcap",
    "ssl_renegotiation": "pcap_files/SSL_Renegotiation.pcap",
    "syn_dos": "pcap_files/SYN_DoS.pcap",
    "video_injection": "pcap_files/Video_Injection.pcap",
}
BENIGN_COUNT = 12500
MALICIOUS_COUNT = 10
SIMULATION_DURATION = 600  # 10 minutes in seconds
LOG_FILE = "logs/simulation_report.txt"

# Helper: Create traffic pattern with spikes and lulls
def generate_intervals(total_packets, duration):
    intervals = [random.uniform(0.001, 0.03) for _ in range(total_packets)]
    scale = duration / sum(intervals)
    return [i * scale for i in intervals]

# Load packets with progress
def load_packets(path, attack_name):
    benign = []
    malicious = []
    count = BENIGN_COUNT + MALICIOUS_COUNT

    with PcapReader(path) as reader:
        print(f"📥 Loading {attack_name} packets...")
        for i, pkt in enumerate(tqdm(reader, total=count, desc=f"Reading {attack_name}", unit="pkt")):
            if i < BENIGN_COUNT:
                benign.append(pkt)
            elif i < count:
                malicious.append(pkt)
            else:
                break
    return benign, malicious

# Load packets and classify
def simulate():
    os.makedirs("logs", exist_ok=True)
    extractor = LiveFeatureExtractor()
    all_packets = []

    for attack_name, pcap_path in ATTACK_FILES.items():
        if not os.path.exists(pcap_path):
            print(f"⚠️ File not found: {pcap_path}")
            continue

        benign, malicious = load_packets(pcap_path, attack_name)

        if len(benign) < BENIGN_COUNT or len(malicious) < MALICIOUS_COUNT:
            print(f"⚠️ Not enough packets in {attack_name}, skipping...")
            continue

        all_packets += [(pkt, 'benign') for pkt in benign]
        all_packets += [(pkt, attack_name) for pkt in malicious]

    random.shuffle(all_packets)
    intervals = generate_intervals(len(all_packets), SIMULATION_DURATION)
    print(f"🚀 Starting simulation with {len(all_packets)} packets...")

    detections = []

    for (packet, label), interval in tqdm(zip(all_packets, intervals), total=len(all_packets), desc="💡 Simulating", unit="pkt"):
        timestamp = time.time()
        vector = extractor.process_packet(packet, timestamp)
        if vector is not None:
            if is_packet_malicious(vector, verbose=False):
                detections.append(label)
        time.sleep(interval)

    # Write report
    total = len(all_packets)
    malicious_detected = len([d for d in detections if d != 'benign'])
    attack_counts = Counter(detections)

    with open(LOG_FILE, "w") as f:
        f.write("Simulation Report\n")
        f.write("=================\n")
        f.write(f"Total packets: {total}\n")
        f.write(f"Malicious packets detected: {malicious_detected}\n")
        for attack, count in attack_counts.items():
            if attack != 'benign':
                percent = (count / total) * 100
                f.write(f"- {attack}: {count} packets ({percent:.2f}%)\n")

    print("✅ Simulation complete. Report written to:", LOG_FILE)

if __name__ == "__main__":
    simulate()

