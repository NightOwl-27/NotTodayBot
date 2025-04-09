import sys
import logging
import os
sys.path.append(os.path.dirname(__file__))
import numpy as np
from time import time
from scapy.all import sniff, IP, TCP, UDP, Raw
from tensorflow.keras.models import load_model
from sklearn.preprocessing import StandardScaler
from my_feature_extractor import LiveFeatureExtractor



# --- CONFIGURATION ---
MODEL_DIR = "models"
LOG_PATH = "logs/malicious_packets.log"
FEATURE_DIM = 115

# Suppress TensorFlow warnings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf
tf.get_logger().setLevel('ERROR')

# --- LOGGING SETUP ---
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format='%(asctime)s - INFO - Malicious packet detected [Live]'
)

# --- LOAD MODELS ---
model_files = [f for f in os.listdir(MODEL_DIR) if f.endswith(".h5")]
models = [load_model(os.path.join(MODEL_DIR, f)) for f in model_files]
print(f"Loaded models: {model_files}")

# --- FEATURE EXTRACTOR SETUP ---
feature_extractor = LiveFeatureExtractor()

# --- FEATURE EXTRACTION ---
def extract_features(packet):
    try:
        features = feature_extractor.extract_from_packet(packet)
        print("Feature vector length:", len(features))
        return features
    except Exception as e:
        print("Feature extraction error:", e)
        return None

# --- VOTING SYSTEM ---
def is_packet_malicious(features):
    features = np.array(features).reshape(1, -1)
    features = StandardScaler().fit_transform(features)
    votes = [int(model.predict(features, verbose=0)[0][0] > 0.5) for model in models]
    return not all(v == 0 for v in votes)

# --- PACKET CALLBACK ---
def process_packet(packet):
    try:
        ts = time()
        features = feature_extractor.process_packet(packet, ts)
        print("Extracted feature length:", len(features))
        if features is None:
            return
        if is_packet_malicious(features):
            msg = "Malicious packet detected [Live]"
            logging.info(msg)
            print("\033[91m" + msg + "\033[0m")
    except Exception as e:
        print("Error processing packet:", e)

# --- START SNIFFING ---
# Ports based on Kitsune's attack types: web (80/443), DNS (53), SSH (22), RDP (3389), SSDP (1900), and custom IoT (47808)
print("Sniffing live traffic (ports: 80, 443, 22, 53, 3389, 1900, 47808)...")
sniff(
    filter="tcp port 80 or tcp port 443 or port 22 or port 53 or port 3389 or udp port 1900 or udp port 47808",
    prn=process_packet,
    store=0
)



