import os
import numpy as np
import joblib
from tensorflow.keras.models import load_model
from sklearn.preprocessing import StandardScaler
import logging

# Suppress TensorFlow logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf
tf.get_logger().setLevel('ERROR')

# Load selected top-15 feature indices
feature_map = {}
selected_indices = []
with open("top15features.csv", "r") as f:
    for line in f:
        parts = line.strip().split(',')
        attack = parts[0].replace('_', ' ').lower()
        indices = list(map(int, parts[1:]))
        feature_map[attack] = indices
        selected_indices.extend(indices)

selected_indices = sorted(set(selected_indices))
feature_to_offset = {fid: i * 15 for i, fid in enumerate(selected_indices)}

# Load models and scalers
model_dir = "models"
model_files = [f for f in os.listdir(model_dir) if f.endswith(".h5")]
models = [load_model(os.path.join(model_dir, mf)) for mf in model_files]
scalers = {}
for f in model_files:
    scaler_path = os.path.join(model_dir, f"scaler_{f.replace('model_', '').replace('.h5', '')}.pkl")
    scalers[f] = joblib.load(scaler_path)

model_names = [mf.replace("model_", "").replace(".h5", "") for mf in model_files]

# Packet classifier using voting across models
LAMBDA_VALUES = [5, 3, 1, 0.1, 0.01]

def is_packet_malicious(features, verbose=False):
    features = np.array(features).reshape(1, -1)
    votes = []
    attack_probs = {}

    for model_file, model in zip(model_files, models):
        attack_key = model_file.replace("model_", "").replace(".h5", "").replace('_', ' ').lower()
        base_indices = feature_map.get(attack_key, [])

        selected_afterimage_indices = []
        for f_id in base_indices:
            if f_id in feature_to_offset:
                offset = feature_to_offset[f_id]
                selected_afterimage_indices.extend(range(offset, offset + 15))
        try:
            selected_features = features[:, selected_afterimage_indices]

            scaler = scalers[model_file]
            scaled_features = scaler.transform(selected_features)

            vote_prob = model.predict(scaled_features)[0][0]
            attack_probs[attack_key] = vote_prob
            votes.append(vote_prob)
        except Exception as e:
            print(f"⚠️ Error processing {attack_key}: {e}")
            continue

    if not attack_probs:
        return False, None

    high_confidence = any(v >= 0.90 for v in votes)
    majority_vote = sum(v >= 0.5 for v in votes) >= int(len(votes) * 0.7)

    if high_confidence or majority_vote:
        most_likely_attack = max(attack_probs, key=attack_probs.get)
        return True, most_likely_attack
    else:
        return False, None
