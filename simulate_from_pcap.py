import os
import time
from collections import Counter
from scapy.all import PcapReader
from my_feature_extractor import LiveFeatureExtractor
from voting_system import is_packet_malicious
from tqdm import tqdm

# --- Configuration ---
PCAP_FILE = "logs/Live_Data.pcap"
LOG_FILE = "logs/simulation_from_real_report.txt"
SIMULATION_DURATION = 600  # optional, affects sleep if re-added

# --- Simulation ---
def simulate_from_real():
    os.makedirs("logs", exist_ok=True)
    if not os.path.exists(PCAP_FILE):
        print(f"❌ PCAP file not found: {PCAP_FILE}")
        return

    extractor = LiveFeatureExtractor()
    detections = []
    total_packets = 0

    print(f"📥 Reading from {PCAP_FILE}")
    with PcapReader(PCAP_FILE) as reader:
        for pkt in tqdm(reader, desc="💡 Simulating Real PCAP", unit="pkt"):
            timestamp = time.time()
            vector = extractor.process_packet(pkt, timestamp)
            total_packets += 1
            if vector is not None:
                detected, attack_type = is_packet_malicious(vector, verbose=False)
                if detected:
                    detections.append(attack_type)

    # --- Report ---
    malicious_detected = len(detections)
    attack_counts = Counter(detections)

    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("Simulation from Live_Data.pcap\n")
        f.write("==================================\n")
        f.write(f"Total packets: {total_packets}\n")
        f.write(f"Malicious packets detected: {malicious_detected}\n")
        for attack, count in attack_counts.items():
            percent = (count / total_packets) * 100
            f.write(f"- {attack}: {count} packets ({percent:.2f}%)\n")

    print(f"✅ Simulation complete. Report saved to {LOG_FILE}")

if __name__ == "__main__":
    simulate_from_real()
