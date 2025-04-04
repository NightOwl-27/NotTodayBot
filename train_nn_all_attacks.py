import kagglehub
from kagglehub import KaggleDatasetAdapter
import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.optimizers import Adam
from collections import Counter
import os
import warnings
warnings.filterwarnings("ignore")

# 🧠 Attack types (Mirai Botnet removed due to formatting issues)
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

print("🧠 Starting training on all attack types...\n")

results = []
os.makedirs("models", exist_ok=True)

for attack in attack_types:
    print(f"\nTraining on {attack}")

    dataset_path = f"{attack}/{attack.replace(' ', '_')}_dataset.csv"
    labels_path = f"{attack}/{attack.replace(' ', '_')}_labels.csv"
    pandas_kwargs = {"header": None}
    label_kwargs = {"header": None}

    try:
        df = kagglehub.load_dataset(
            KaggleDatasetAdapter.PANDAS,
            "ymirsky/network-attack-dataset-kitsune",
            dataset_path,
            pandas_kwargs=pandas_kwargs
        )

        labels = kagglehub.load_dataset(
            KaggleDatasetAdapter.PANDAS,
            "ymirsky/network-attack-dataset-kitsune",
            labels_path,
            pandas_kwargs=label_kwargs
        )

        # Extract label column (column 1 is the label)
        y = pd.to_numeric(labels.iloc[:, 1], errors='coerce').fillna(0).astype(int)
        df["label"] = y

    except Exception as e:
        print(f"Failed to load {attack}: {e}")
        continue

    if len(set(y)) < 2:
        print(f"Skipping {attack} — only one class present.")
        continue

    X = df.drop("label", axis=1).values
    y = df["label"].values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

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

    # Save model
    model_filename = f"models/model_{attack.replace(' ', '_').lower()}.h5"
    model.save(model_filename)
    print(f"💾 Saved model to {model_filename}")

    results.append({
        "attack": attack,
        "accuracy": avg_acc
    })

# Final Summary
print("\nAll Results:")
df_results = pd.DataFrame(results)
print(df_results.sort_values(by="accuracy", ascending=False).reset_index(drop=True))
print("\nTraining complete!")
