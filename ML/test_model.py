"""
Test the ML model with real data against the live server.
Tests ALL rows from the dataset + per-category accuracy breakdown.
"""
import sys
import pandas as pd
import requests
from collections import defaultdict

SERVER = "http://localhost:5000"

# ── Check server health ──────────────────────────────────────────────
try:
    r = requests.get(f"{SERVER}/health", timeout=3)
    r.raise_for_status()
except Exception as e:
    print(f"Server not reachable at {SERVER}: {e}")
    sys.exit(1)

# ── Load real data ───────────────────────────────────────────────────
df = pd.concat([
    pd.read_csv("dpi-engine/flow_dataset.csv"),
    pd.read_csv("dpi-engine/data/flow_dataset.csv"),
], ignore_index=True).drop_duplicates()
df = df[df["category"] != "unknown"]

print(f"Total test rows: {len(df)}")
print(f"Categories: {sorted(df['category'].unique())}")
print()

# ── Run predictions ──────────────────────────────────────────────────
correct = 0
total = 0
per_cat = defaultdict(lambda: {"correct": 0, "total": 0, "misses": []})
misses = []

for idx, row in df.iterrows():
    payload = {
        "domain": row["domain"],
        "protocol": row["protocol"],
        "packet_count": int(row["packet_count"]),
        "avg_packet_size": float(row["avg_packet_size"]),
        "flow_duration": float(row["flow_duration"]),
        "packets_per_second": float(row["packets_per_second"]),
        "bytes_per_second": float(row["bytes_per_second"]),
    }
    resp = requests.post(f"{SERVER}/predict", json=payload).json()
    expected = row["category"]
    predicted = resp["category"]
    conf = resp["confidence"]
    match = predicted == expected

    total += 1
    per_cat[expected]["total"] += 1
    if match:
        correct += 1
        per_cat[expected]["correct"] += 1
    else:
        per_cat[expected]["misses"].append(
            (row["domain"], predicted, conf)
        )
        misses.append((row["domain"], expected, predicted, conf))

# ── Per-category accuracy ────────────────────────────────────────────
print("=" * 80)
print("PER-CATEGORY ACCURACY")
print("=" * 80)
print(f"{'Category':<20} {'Correct':<10} {'Total':<10} {'Accuracy':<10}")
print("-" * 50)
for cat in sorted(per_cat.keys()):
    c = per_cat[cat]["correct"]
    t = per_cat[cat]["total"]
    acc = c / t * 100 if t > 0 else 0
    print(f"{cat:<20} {c:<10} {t:<10} {acc:.1f}%")
print("-" * 50)
print(f"{'OVERALL':<20} {correct:<10} {total:<10} {correct/total*100:.1f}%")
print()

# ── Show all misses ──────────────────────────────────────────────────
if misses:
    print("=" * 80)
    print(f"MISCLASSIFIED ({len(misses)} rows)")
    print("=" * 80)
    print(f"{'Domain':<30} {'Expected':<20} {'Predicted':<20} {'Conf'}")
    print("-" * 80)
    for domain, exp, pred, conf in misses:
        print(f"{domain:<30} {exp:<20} {pred:<20} {conf}")
else:
    print("No misclassifications!")

print()
print(f"OVERALL ACCURACY: {correct}/{total} = {correct/total*100:.1f}%")
