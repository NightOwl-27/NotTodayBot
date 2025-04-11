import os
import kagglehub

print("⬇️  Downloading datasets from KaggleHub (if not already downloaded)...")
download_path = kagglehub.dataset_download("ymirsky/network-attack-dataset-kitsune")
print("📂 KaggleHub download path:", download_path)

# Create destination folder
base_dataset_dir = "kitsune_datasets"
os.makedirs(base_dataset_dir, exist_ok=True)

# Copy only *_dataset.csv files with proper renaming
mapping = {
    "Active Wiretap": "Active_Wiretap_dataset.csv",
    "ARP MitM": "ARP_MitM_dataset.csv",
    "Fuzzing": "Fuzzing_dataset.csv",
    "Mirai Botnet": "Mirai_dataset.csv",
    "OS Scan": "OS_Scan_dataset.csv",
    "SSDP Flood": "SSDP_Flood_dataset.csv",
    "SSL Renegotiation": "SSL_Renegotiation_dataset.csv",
    "SYN DoS": "SYN_DoS_dataset.csv",
    "Video Injection": "Video_Injection_dataset.csv"
}

for folder in os.listdir(download_path):
    folder_path = os.path.join(download_path, folder)
    if not os.path.isdir(folder_path):
        continue

    for label, file_name in mapping.items():
        full_file_path = os.path.join(folder_path, file_name)
        if os.path.exists(full_file_path):
            dest_path = os.path.join(base_dataset_dir, f"{label}.csv")
            print(f"🗂 Copying {file_name} -> {dest_path}")
            with open(full_file_path, "rb") as src, open(dest_path, "wb") as dst:
                dst.write(src.read())

print("✅ Download and organization complete.")