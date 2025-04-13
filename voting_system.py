import os
import numpy as np
import joblib
from tensorflow.keras.models import load_model
from sklearn.preprocessing import StandardScaler
import logging
from model_features import feature_map  

# Suppress TensorFlow logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf
tf.get_logger().setLevel('ERROR')

# Load all models
model_dir = "models"
model_files = [f for f in os.listdir(model_dir) if f.endswith(".h5")]
models = [load_model(os.path.join(model_dir, mf)) for mf in model_files]
scalers = {
    f: joblib.load(os.path.join(model_dir, f"scaler_{f.replace('model_', '').replace('.h5', '')}.pkl"))
    for f in model_files
}
model_names = [mf.replace("model_", "").replace(".h5", "") for mf in model_files]
print(f"\033[97m✅ Loaded models: {model_names}\033[0m")

# Feature extraction (placeholder for live use)
def extract_features_from_packet(packet):
    return np.random.rand(1500)  # Simulate full feature vector

# Voting system with correct feature selection per model
def is_packet_malicious(features, verbose=True):
    features = np.array(features).reshape(1, -1)
    votes = []

    for model_file, model in zip(model_files, models):
        attack_key = model_file.replace("model_", "").replace(".h5", "")
        indices = feature_map.get(attack_key, [])
        selected_indices = list(range(100)) + [100 + i for i in indices]

        selected_features = features[:, selected_indices]
        scaler = scalers[model_file]
        scaled_features = scaler.transform(selected_features)

        vote_prob = model.predict(selected_features, verbose=0)[0][0]
        if verbose:
            print(f"   ➤ {attack_key} Probability: {vote_prob:.4f}")
        votes.append(vote_prob)

    high_confidence = any(v >= 0.90 for v in votes)
    majority_vote = sum(v >= 0.5 for v in votes) >= int(len(votes) * 0.7)

    return high_confidence or majority_vote
