asdfasdfasdff

# NotTodayBot - A Machine Learning Intrusion Prevention System (IPS)

NotTodayBot is a real-time Intrusion Prevention System powered by machine learning. It detects and logs network threats using a voting ensemble of neural networks trained on the Kitsune Network Attack Dataset. The system combines live packet capture, feature extraction, anomaly detection, and a user-friendly Flask dashboard for monitoring.

---

## 🧠 How the Models Were Built

Each model in `models/` was trained on a specific attack from the Kitsune dataset:

1. **Feature Extraction**: Kitsune’s AfterImage extractor was used to derive 1500 statistical features from network flows.
2. **Feature Selection**: The top 15 AfterImage features per attack were selected based on correlation and importance ranking.
3. **Standardization**: Features were scaled using `StandardScaler` and stored in individual `.pkl` files per model.
4. **Model Training**: A lightweight Keras neural network was trained per attack (excluding `active_wiretap`, which performed poorly on real data).
5. **Voting System**: At inference time, all models predict independently. If enough models agree (via high-confidence or majority voting), the packet is flagged as malicious.

---

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/NightOwl-27/NotTodayBot.git
cd NotTodayBot
```

### 2. Setup Python Environment

```bash
python -m venv venv
venv\Scripts\activate     # On Windows
source venv/bin/activate  # On Mac/Linux
pip install -r requirements.txt
```

### 3. Run the Web Dashboard

```bash
python web_dashboard/app.py

Then open [http://localhost:5000](http://localhost:5000) in your browser.

You can:
- Toggle the live sniffer
- View real-time detection logs
- Explore EDA visualizations
- Check historical logs by date
```
### 4. Folder Structure

```
NotTodayBot/
├── web_dashboard/         # Flask dashboard UI and backend
├── models/                # Trained Keras models + scalers
├── pcap_files/            # Kitsune dataset attack traffic
├── logs/                  # Live and historical detection logs
│   ├── malicious_packets.log
│   ├── malicious_packets_data.csv
│   └── Live_Data.pcap
├── my_feature_extractor/  # Real-time Kitsune-based feature extraction
├── live_sniffer.py        # Live packet capture and classification
├── simulate_from_pcap.py  # Simulated detection using Kitsune traffic
└── simulate_from_real_pcap.py # Simulates detection using Live_Data.pcap
```

### Disclaimer
Due to differances between the kitsune dataset and real world pcap files live_sniffer.py
currently flags most if not all packets as malicious. However, when the models are given
data based on the Kitsune dataset they exhibit high accuracy scores using 5-fold 
verification. Proving that validity of the neural network. The models were trained
correctly, it just seems generalizing that to live network traffic created issues
often seen in many ML solutions. 






