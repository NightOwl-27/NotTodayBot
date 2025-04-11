import os
import numpy as np
from kitsune_core.FeatureExtractor import FE
from tqdm import tqdm

# Directory containing the PCAP files
pcap_dir = "pcap_files"

# Max number of packets to process
MAX_ROWS = 250000

# Iterate through all .pcap files in the directory
for filename in os.listdir(pcap_dir):
    if not filename.endswith(".pcap") or filename.endswith(".pcapng"):
        continue

    pcap_path = os.path.join(pcap_dir, filename)
    output_csv = os.path.join(pcap_dir, filename.replace(".pcap", "_all1500.csv"))

    print(f"\n📦 Processing: {filename}")
    print(f"Extracting up to {MAX_ROWS} packets worth of AfterImage features...")

    # Initialize Kitsune Feature Extractor
    extractor = FE(pcap_path)
    features = []
    count = 0

    # Progress bar for extraction
    with tqdm(total=MAX_ROWS, desc=f"Extracting {filename}") as pbar:
        while count < MAX_ROWS:
            feat = extractor.get_next_vector()
            if feat is None:
                break
            features.append(feat)
            count += 1
            pbar.update(1)

    np.savetxt(output_csv, features, delimiter=",", fmt="%.8f")
    print(f"✅ Features successfully saved to: {output_csv} ({count} rows)")
