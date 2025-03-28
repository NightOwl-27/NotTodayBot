import os
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model
from sklearn.preprocessing import StandardScaler
import logging

# Setup logging to file
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename='logs/malicious_packets.log', 
    level=logging.INFO, 
    format='%(asctime)s %(message)s'
)

# Load all models
model_dir = "models"
model_files = [f for f in os.listdir(model_dir) if f.endswith(".h5")]
models = [load_model(os.path.join(model_dir, mf)) for mf in model_files]
model_names = [mf.replace("model_", "").replace(".h5", "") for mf in model_files]
print(f"✅ Loaded models: {model_names}")

# Placeholder for real packet feature extraction
def extract_features_from_packet(packet):
    # Replace this with real feature extraction logic
    return np.random.rand(115)  # 115 features expected

# Voting function
def is_packet_malicious(features):
    features = np.array(features).reshape(1, -1)
    scaler = StandardScaler()
    features = scaler.fit_transform(features)

    votes = []
    for model in models:
        prediction = model.predict(features, verbose=0)
        votes.append(int(prediction[0][0] > 0.5))

    # Only if ALL models agree it's benign, let it through
    return not all(v == 0 for v in votes)

# Simulated packet loop (replace with real-time sniffing later)
for i in range(50):  # Simulate 50 packets
    packet_features = extract_features_from_packet(None)
    if is_packet_malicious(packet_features):
        logging.info(f"🚨 Malicious packet detected [Simulated ID: {i}]")

print("📄 Malicious packets logged to logs/malicious_packets.log")