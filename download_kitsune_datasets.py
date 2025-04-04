import os
import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta
import kagglehub

print("🛠 Starting log generation...")

# Setup paths
base_dataset_dir = "kitsune_datasets"
output_log = "logs/malicious_packets.log"
samples_per_dataset = 20000
benign_cutoff = 1_000_000  # First 1M rows assumed benign

# Download full dataset once using KaggleHub
print("⬇️  Downloading datasets from KaggleHub (if not already downloaded)...")
download_path = kagglehub.dataset_download("ymirsky/network-attack-dataset-kitsune")
print("📂 KaggleHub download path:", download_path)

# Copy and organize relevant CSV files into kitsune_datasets
os.makedirs(base_dataset_dir, exist_ok=True)
subdirs = os.listdir(download_path)

attack_paths = {}
for subdir in subdirs:
    subpath = os.path.join(download_path, subdir)
    if not os.path.isdir(subpath):
        continue

    for file in os.listdir(subpath):
        if file.endswith(".csv"):
            src = os.path.join(subpath, file)
            dst = os.path.join(base_dataset_dir, f"{subdir}.csv")
            if not os.path.exists(dst):  # Avoid re-copying
                print(f"🗂 Copying {file} -> {dst}")
                with open(src, "rb") as fsrc, open(dst, "wb") as fdst:
                    fdst.write(fsrc.read())
            attack_paths[subdir] = dst

# Prepare log folder
os.makedirs("logs", exist_ok=True)

with open(output_log, "w") as log_file:
    current_time = datetime.now() - timedelta(days=8)

    for attack, file_path in attack_paths.items():
        print(f"\n🔍 Processing {attack}.csv")

        df = pd.read_csv(file_path, header=None)
        print(f"📊 Loaded {len(df)} rows.")

        if len(df) <= benign_cutoff:
            print("🚫 Not enough data to split benign/malicious.")
            continue

        df = df.sample(frac=1, random_state=42).reset_index(drop=True)

        num_malicious = random.randint(500, 1500)
        num_benign = samples_per_dataset - num_malicious
        print(f"📦 Sampling {num_benign} benign and {num_malicious} malicious...")

        benign_pool = df.iloc[:benign_cutoff]
        attack_pool = df.iloc[benign_cutoff:]

        selected_benign = benign_pool.sample(n=num_benign, random_state=42)
        selected_attack = attack_pool.sample(n=num_malicious, random_state=42)

        combined = pd.concat([selected_benign, selected_attack])
        combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

        print(f"✍️  Writing {len(selected_attack)} log entries for {attack}...")
        for _ in selected_attack.iterrows():
            log_time = current_time.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
            msg = f"{log_time} - INFO - Malicious packet detected [{attack}]"
            log_file.write(msg + "\n")
            current_time += timedelta(seconds=random.randint(8, 15))

print("\n✅ Log simulation complete. Check logs/malicious_packets.log")
