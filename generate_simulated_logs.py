import os
import pandas as pd
import random
from datetime import datetime, timedelta

print("🛠 Generating simulated logs...")

# Setup paths
dataset_dir = "kitsune_datasets"
output_log = "logs/malicious_packets.log"
samples_per_dataset = 20000
benign_cutoff = 1_000_000

# Setup 8-day range (yesterday to 7 days ago)
start_day = datetime.now().date() - timedelta(days=8)
day_slots = [start_day + timedelta(days=i) for i in range(8)]

# Ensure log dir exists
os.makedirs("logs", exist_ok=True)

# Shuffle attack order
attack_files = [f for f in os.listdir(dataset_dir) if f.endswith(".csv")]
random.shuffle(attack_files)

with open(output_log, "w") as log_file:
    for file in attack_files:
        attack_name = file.replace(".csv", "")
        path = os.path.join(dataset_dir, file)

        df = pd.read_csv(path, header=None)
        if len(df) <= benign_cutoff:
            print(f"🚫 Not enough rows in {attack_name} to split.")
            continue

        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        num_malicious = random.randint(500, 1500)
        num_benign = samples_per_dataset - num_malicious

        benign_pool = df.iloc[:benign_cutoff]
        attack_pool = df.iloc[benign_cutoff:]

        selected_attack = attack_pool.sample(n=num_malicious, random_state=42)

        # Assign timestamps over 8 days
        for i, (_, row) in enumerate(selected_attack.iterrows()):
            day = random.choice(day_slots)
            random_time = timedelta(
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59),
            )
            timestamp = datetime.combine(day, datetime.min.time()) + random_time
            timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]

            log_msg = f"{timestamp_str} - INFO - Malicious packet detected [{attack_name}]"
            log_file.write(log_msg + "\n")

print("✅ Simulated logs generated and written to logs/malicious_packets.log")