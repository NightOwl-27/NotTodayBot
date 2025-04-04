import os
import numpy as np
from tensorflow.keras.models import load_model
from sklearn.preprocessing import StandardScaler
import logging

# 🔇 Suppress TensorFlow logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf
tf.get_logger().setLevel('ERROR')

# ✅ Create logs folder
os.makedirs("logs", exist_ok=True)

# ✅ Clear previous log file
with open("logs/malicious_packets.log", "w"):
    pass

# ✅ Setup logger
logger = logging.getLogger("NotTodayBot")
logger.setLevel(logging.INFO)
logger.propagate = False  # 🔒 Prevent duplication to root logger

# 🗂️ File handler
file_handler = logging.FileHandler("logs/malicious_packets.log")
file_handler.setFormatter(logging.Formatter("%(asctime)s - INFO - %(message)s"))
logger.addHandler(file_handler)

# 🖥️ Console handler (white output)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("\033[97m%(message)s\033[0m"))
logger.addHandler(console_handler)

# ✅ Load all models
model_dir = "models"
model_files = [f for f in os.listdir(model_dir) if f.endswith(".h5")]
models = [load_model(os.path.join(model_dir, mf)) for mf in model_files]
model_names = [mf.replace("model_", "").replace(".h5", "") for mf in model_files]
print(f"\033[97m✅ Loaded models: {model_names}\033[0m")

# 📦 Simulated packet feature extraction
def extract_features_from_packet(packet):
    return np.random.rand(115)

# 🗳️ Voting system
def is_packet_malicious(features):
    features = np.array(features).reshape(1, -1)
    features = StandardScaler().fit_transform(features)
    votes = [int(model.predict(features, verbose=0)[0][0] > 0.5) for model in models]
    return not all(v == 0 for v in votes)

# 🔁 Simulate packet stream
for i in range(50):
    features = extract_features_from_packet(None)
    if is_packet_malicious(features):
        msg = f"Malicious packet detected [Simulated ID: {i}]"
        logger.info(msg)

print("\033[97m📄 Malicious packets logged to logs/malicious_packets.log\033[0m")