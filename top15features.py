import pandas as pd
import numpy as np
import os
from tqdm import tqdm

from collections import defaultdict

# Define where feature maps will be saved
feature_map_file = "model_features.py"

# Supported attack types (CSV name, lowercase key)
attack_types = {
    "ARP MitM": "arp_mitm",
    "Fuzzing": "fuzzing",
    "Active Wiretap": "active_wiretap",
    "OS Scan": "os_scan",
    "SSDP Flood": "ssdp_flood",
    "SSL Renegotiation": "ssl_renegotiation",
    "SYN DoS": "syn_dos",
    "Video Injection": "video_injection"
}

for dataset_name, key in attack_types.items():
    print(f"\n🔍 Matching AfterImage training features for: {dataset_name}")

    # Paths to datasets
    original_path = f"kitsune_datasets/{dataset_name}.csv"
    afterimage_path = f"pcap_files/{dataset_name.replace(' ', '_')}_all1500.csv"

    if not os.path.exists(original_path) or not os.path.exists(afterimage_path):
        print(f"❌ Missing data for {dataset_name}. Skipping.")
        continue

    # Load datasets
    original_115 = pd.read_csv(original_path, header=None)
    afterimage_1500 = pd.read_csv(afterimage_path, header=None)

    # Trim both to equal length
    min_rows = min(len(original_115), len(afterimage_1500))
    original_115 = original_115[:min_rows]
    afterimage_1500 = afterimage_1500[:min_rows]

    selected = {}
    used = set()

    # Match original features 100–114 to best AfterImage columns with tqdm progress bar
    for i in tqdm(range(100, 115), desc=f"🔄 Matching features for {key}"):
        original_col = original_115.iloc[:, i]
        best_corr = 0
        best_match = 0

        for j in range(afterimage_1500.shape[1]):
            if j in used:
                continue
            candidate_col = afterimage_1500.iloc[:, j]
            if np.std(candidate_col) == 0 or np.std(original_col) == 0:
                continue
            corr = np.corrcoef(original_col, candidate_col)[0, 1]
            if np.isnan(corr):
                continue
            if abs(corr) > best_corr:
                best_corr = corr
                best_match = j

        selected[i] = (best_match, best_corr)
        used.add(best_match)
        print(f"✅ Original AfterImage feature {i} ≈ extracted feature {best_match} (corr={best_corr:.4f})")

    # Final ordered list to match model input shape
    ordered_indices = [selected[i][0] for i in range(100, 115)]

    print(f"\n🔥 Final ordered list of extracted features for {key}:")
    print(ordered_indices)

    # Append to model_features.py
    with open(feature_map_file, "a") as f:
        f.write(f'feature_map["{key}"] = {ordered_indices}\n')
