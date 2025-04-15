# Re-running the simulation code after reset
import os
import pandas as pd
import random
from datetime import datetime, timedelta
from tqdm import tqdm

print("🛠 Generating simulated logs...")

# Setup paths
dataset_dir = "kitsune_datasets"
log_output_path = "logs/malicious_packets.log"
csv_output_path = "logs/malicious_packets_data.csv"
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

log_lines = []
csv_rows = []

for file in tqdm(attack_files, desc="🚀 Processing datasets"):
    attack_name = file.replace(".csv", "")
    if "_labels" in attack_name:
        continue

    path = os.path.join(dataset_dir, file)
    df = pd.read_csv(path, header=None)
    if len(df) <= benign_cutoff:
        print(f"🚫 Not enough rows in {attack_name} to split.")
        continue

    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    num_malicious = random.randint(500, 1500)
    attack_pool = df.iloc[benign_cutoff:]
    selected_attack = attack_pool.sample(n=num_malicious, random_state=42)

    for _, row in selected_attack.iterrows():
        day = random.choice(day_slots)
        random_time = timedelta(
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )
        timestamp = datetime.combine(day, datetime.min.time()) + random_time
        timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]

        log_msg = f"{timestamp_str} - INFO - Malicious packet detected [{attack_name}]"
        log_lines.append(log_msg)

        csv_rows.append([timestamp_str, attack_name] + row.tolist())

# Write log file
with open(log_output_path, "w") as log_file:
    log_file.write("\n".join(log_lines))

# Write malicious packet CSV file
df_out = pd.DataFrame(csv_rows)
df_out.to_csv(csv_output_path, index=False, header=False)

print("✅ Simulated logs and malicious CSV data generated.")