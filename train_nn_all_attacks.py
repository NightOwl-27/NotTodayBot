import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.optimizers import Adam
from collections import Counter
from kitsune_core.AfterImage import incStatDB
from tqdm import tqdm
import os
import warnings
import joblib
import pickle

warnings.filterwarnings("ignore")

# Load top features per attack
feature_map = {}
with open("top15features.csv", "r") as f:
    for line in f:
        parts = line.strip().split(',')
        attack = parts[0].replace('_', ' ').lower()
        indices = list(map(int, parts[1:]))
        feature_map[attack] = indices

LAMBDA_VALUES = [0.001, 0.005, 0.01, 0.05, 0.1]

attack_types = [
    "Active Wiretap",
    "ARP MitM",
    "Fuzzing",
    "OS Scan",
    "SSDP Flood",
    "SSL Renegotiation",
    "SYN DoS",
    "Video Injection"
]

print("\U0001f9e0 Starting training on all attack types...\n")

results = []
os.makedirs("models", exist_ok=True)
os.makedirs("cached", exist_ok=True)

def extract_afterimage_stats(df, indices, cache_path):
    print(f"📊 Computing AfterImage stats...")
    stats_matrix = []
    dbs = {lam: incStatDB(default_lambda=lam) for lam in LAMBDA_VALUES}

    for i in tqdm(range(len(df)), desc="⏳ Extracting", unit="pkt"):
        row_stats = []
        for fid in indices:
            val = df.iloc[i, fid]
            for lam in LAMBDA_VALUES:
                db = dbs[lam]
                db.update(str(fid), i, val)
                row_stats.extend(db.get_1D_Stats(str(fid)))  # [weight, mean, std]
        stats_matrix.append(row_stats)

    stats_array = np.array(stats_matrix, dtype=np.float32)
    with open(cache_path, 'wb') as f:
        pickle.dump(stats_array, f)
    return stats_array

for attack in attack_types:
    print(f"\n=== 🛡️ Training on {attack} ===")

    cache_path = f"cached/{attack.replace(' ', '_')}_afterimage.pkl"
    if os.path.exists(cache_path):
        print(f"⏩ Skipping {attack} — already cached.")
        continue

    dataset_path = f"kitsune_datasets/{attack}.csv"
    labels_path = f"kitsune_datasets/{attack.replace(' ', '_')}_labels.csv"

    try:
        df = pd.read_csv(dataset_path, header=None)
        labels = pd.read_csv(labels_path, header=None)
        y = pd.to_numeric(labels.iloc[:, 1], errors='coerce').fillna(0).astype(int)
        df["label"] = y

    except Exception as e:
        print(f"Failed to load {attack}: {e}")
        continue

    if len(set(y)) < 2:
        print(f"Skipping {attack} — only one class present.")
        continue

    attack_key = attack.lower()
    indices = feature_map.get(attack_key, [])
    if not indices:
        print(f"⚠️  No feature indices found for {attack_key}, skipping.")
        continue

    print(f"🔢 Extracting AfterImage stats for {attack_key}...")
    cache_path = f"cached/{attack.replace(' ', '_')}_afterimage.pkl"
    afterimage_features = extract_afterimage_stats(df.iloc[:, :100], indices, cache_path)
    X = afterimage_features
    y = df["label"].values

    print(f"📐 Feature shape: {X.shape}")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    scaler_path = f"models/scaler_{attack.replace(' ', '_').lower()}.pkl"
    joblib.dump(scaler, scaler_path)

    min_class_count = min(Counter(y).values())
    if min_class_count < 2:
        print(f"Not enough malicious samples for CV. Skipping.")
        continue

    n_splits = min(5, min_class_count)
    if n_splits < 2:
        print(f"Can't run StratifiedKFold with <2 splits. Skipping.")
        continue

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    fold_accuracies = []

    for fold, (train_idx, test_idx) in enumerate(skf.split(X_scaled, y), 1):
        X_train, X_test = X_scaled[train_idx], X_scaled[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        model = Sequential([
            Dense(64, activation='relu', input_shape=(X_train.shape[1],)),
            Dense(32, activation='relu'),
            Dense(1, activation='sigmoid')
        ])

        model.compile(optimizer=Adam(learning_rate=0.001),
                      loss='binary_crossentropy',
                      metrics=['accuracy'])

        model.fit(X_train, y_train, epochs=20, batch_size=8192, verbose=0)

        y_pred = (model.predict(X_test) > 0.5).astype(int)
        acc = accuracy_score(y_test, y_pred)
        fold_accuracies.append(acc)

        print(f"✅ Fold {fold} Accuracy: {acc:.4f}")

    avg_acc = np.mean(fold_accuracies)
    print(f"📊 {attack} Avg Accuracy: {avg_acc:.4f}")

    model_filename = f"models/model_{attack.replace(' ', '_').lower()}.h5"
    model.save(model_filename)
    print(f"💾 Saved model to {model_filename}")

    results.append({
        "attack": attack,
        "accuracy": avg_acc
    })

print("\nAll Results:")
df_results = pd.DataFrame(results)
print(df_results.sort_values(by="accuracy", ascending=False).reset_index(drop=True))
print("\n✅ Training complete!")
