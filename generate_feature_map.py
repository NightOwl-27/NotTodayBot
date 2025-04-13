import numpy as np
import pandas as pd
from kitsune_core.AfterImage import incStatDB
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# Parameters
LAMBDAS = [0.001, 0.005, 0.01, 0.05, 0.1]
TOP_K = 15
DATA_FILES = {
    "active_wiretap": "kitsune_datasets/Active Wiretap.csv",
    "arp_mitm": "kitsune_datasets/ARP MitM.csv",
    "fuzzing": "kitsune_datasets/fuzzing.csv",
    "os_scan": "kitsune_datasets/OS Scan.csv",
    "ssdp_flood": "kitsune_datasets/SSDP Flood.csv",
    "ssl_renegotiation": "kitsune_datasets/SSL Renegotiation.csv",
    "syn_dos": "kitsune_datasets/SYN DoS.csv",
    "video_injection": "kitsune_datasets/Video Injection.csv",
}
OUT_FEATURE_MAP = {}

def run_lambda(lam, data):
    db = incStatDB(default_lambda=lam)
    for i, row in tqdm(data.iterrows(), total=len(data), desc=f"    ⏳ Rows for λ={lam}", leave=False):
        for f in range(100):
            db.update(str(f), i, row[f])
    return lam, [(f, db.get_1D_Stats(str(f))[2]) for f in range(100)]

def extract_top_features(filename, lambdas, top_k, max_parallel=2):
    print(f"\n🔍 Processing file: {filename}")
    data = pd.read_csv(filename)
    if "Unnamed: 0" in data.columns:
        data = data.drop("Unnamed: 0", axis=1)
    assert data.shape[1] >= 100, "Need at least 100 base features"
    data = data.iloc[:, :100]  # Only first 100 base features

    feature_scores = {}

    print(f"⚙️  Running {max_parallel} lambdas at a time...")
    with ThreadPoolExecutor(max_workers=max_parallel) as executor:
        future_to_lam = {executor.submit(run_lambda, lam, data.copy()): lam for lam in lambdas}
        for future in as_completed(future_to_lam):
            lam, scores = future.result()
            feature_scores[lam] = scores

    # Aggregate score across lambdas
    print("  📊 Aggregating scores across all lambdas...")
    avg_scores = {}
    for f in range(100):
        avg_scores[f] = np.mean([feature_scores[lam][f][1] for lam in lambdas])
    top_features = sorted(avg_scores.items(), key=lambda x: x[1], reverse=True)[:top_k]
    return [f[0] for f in top_features]

print("\n🚀 Starting feature extraction for all attack datasets...")
for attack, file in DATA_FILES.items():
    print(f"\n=== 🧠 Extracting features for attack: {attack.upper()} ===")
    OUT_FEATURE_MAP[attack] = extract_top_features(file, LAMBDAS, TOP_K, max_parallel=2)

# Save output as model_features.py compatible format
print("\n💾 Writing feature map to model_features.py...")
with open("model_features.py", "w") as f:
    f.write("feature_map = " + str(OUT_FEATURE_MAP))

print("\n✅ All done! Feature map successfully saved.")
