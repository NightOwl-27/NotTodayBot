import os
import subprocess
from pathlib import Path

# Modify these as needed
pcapng_root = Path("H:/Desktop/PcapPng")  # Where your .pcapng folders are
pcap_output_dir = Path("C:/Users/John Ludwick/IdeaProjects/c964-capstone/pcap_files")  # Destination for .pcap files
editcap_path = r"C:\Program Files\Wireshark\editcap.exe"  # Path to Wireshark's editcap tool

if not editcap_path or not Path(editcap_path).exists():
    raise FileNotFoundError("❌ Could not find editcap.exe. Please check your Wireshark installation.")

print("🔁 Starting conversion of .pcapng to .pcap...\n")

for folder in pcapng_root.glob("*/"):
    for file in folder.glob("*.pcapng"):
        attack_name = file.stem.split("_pcap")[0]
        output_file = pcap_output_dir / f"{attack_name}.pcap"

        print(f"🔄 Converting: {file.name} → {output_file.name}")

        try:
            subprocess.run([editcap_path, "-F", "pcap", str(file), str(output_file)], check=True)
            print(f"✅ Converted: {output_file.name}")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to convert {file.name}: {e}")

print("\n🏁 All conversions attempted.")
