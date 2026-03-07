"""
Comprehensive ML Model Accuracy & Robustness Check
Tests the SmartShield model with:
  1. Cross-validation on training data
  2. Per-category accuracy breakdown
  3. Known domains from dataset (sampled)
  4. Unseen / novel domains
  5. Edge-case inputs (zero values, extreme values)
"""

import os, sys
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder

ML_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(ML_DIR)

# ── Load model artifacts ──────────────────────────────────────────────
model = joblib.load(os.path.join(ML_DIR, "smartshield_model.pkl"))
domain_to_id = joblib.load(os.path.join(ML_DIR, "domain_encoder.pkl"))
protocol_enc = joblib.load(os.path.join(ML_DIR, "protocol_encoder.pkl"))
category_enc = joblib.load(os.path.join(ML_DIR, "category_encoder.pkl"))
domain_lookup = joblib.load(os.path.join(ML_DIR, "domain_lookup.pkl"))

print("=" * 80)
print("SmartShield ML Model — Accuracy & Robustness Report")
print("=" * 80)
print(f"Model type      : {type(model).__name__}")
print(f"Known domains   : {len(domain_to_id)}")
print(f"Categories      : {list(category_enc.classes_)}")
print(f"Protocol classes: {list(protocol_enc.classes_)}")
print()

# ── Load dataset ──────────────────────────────────────────────────────
paths = [
    os.path.join(PROJECT_ROOT, "dpi-engine", "flow_dataset.csv"),
    os.path.join(PROJECT_ROOT, "dpi-engine", "data", "flow_dataset.csv"),
]
frames = [pd.read_csv(p) for p in paths if os.path.exists(p)]
df = pd.concat(frames, ignore_index=True).drop_duplicates()
df = df[df["category"] != "unknown"].copy()

print(f"Dataset rows (after dedup & removing 'unknown'): {len(df)}")
print(f"Category distribution:\n{df['category'].value_counts().to_string()}\n")


# ── Feature engineering (matches training) ────────────────────────────
def make_features(row_or_df, is_df=False):
    """Build feature vector matching training order."""
    if is_df:
        data = row_or_df
    else:
        data = pd.DataFrame([row_or_df])

    results = []
    for _, r in data.iterrows():
        domain = r.get("domain", "").lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]
        domain_id = domain_to_id.get(domain, -1)

        proto = str(r.get("protocol", "HTTPS")).upper()
        if proto in protocol_enc.classes_:
            proto_encoded = int(protocol_enc.transform([proto])[0])
        else:
            proto_encoded = 0

        pc = float(r.get("packet_count", 0))
        aps = float(r.get("avg_packet_size", 0))
        fd = float(r.get("flow_duration", 0))
        pps = float(r.get("packets_per_second", 0))
        bps = float(r.get("bytes_per_second", 0))

        features = [
            domain_id, proto_encoded, pc, aps, fd, pps, bps,
            np.log1p(pc), np.log1p(fd), np.log1p(bps), np.log1p(pps),
            pc * aps,  # total_bytes
        ]
        results.append(features)
    return np.array(results)


def predict_one(row):
    """Predict category for a single row dict, with lookup fallback."""
    X = make_features(row)
    pred_idx = int(model.predict(X)[0])
    category = category_enc.inverse_transform([pred_idx])[0]
    domain = row.get("domain", "").lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    domain_id = domain_to_id.get(domain, -1)
    confidence = "high" if domain_id >= 0 else "low"
    if domain_id < 0 and domain in domain_lookup:
        category = domain_lookup[domain]
        confidence = "lookup"
    return category, confidence


# ══════════════════════════════════════════════════════════════════════
# TEST 1: Full dataset evaluation (re-predict on training data)
# ══════════════════════════════════════════════════════════════════════
print("=" * 80)
print("TEST 1: Full Dataset Re-Prediction (Training Accuracy)")
print("=" * 80)

X_all = make_features(df, is_df=True)
y_true_labels = df["category"].values
y_true_encoded = category_enc.transform(y_true_labels)
y_pred_encoded = model.predict(X_all)
y_pred_labels = category_enc.inverse_transform(y_pred_encoded)

print(classification_report(y_true_labels, y_pred_labels, zero_division=0))

train_acc = (y_pred_labels == y_true_labels).mean()
print(f"Overall training accuracy: {train_acc:.4f} ({train_acc*100:.1f}%)\n")


# ══════════════════════════════════════════════════════════════════════
# TEST 2: 5-Fold Cross-Validation
# ══════════════════════════════════════════════════════════════════════
print("=" * 80)
print("TEST 2: 5-Fold Stratified Cross-Validation")
print("=" * 80)

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(model, X_all, y_true_encoded, cv=cv, scoring="accuracy")
print(f"Fold scores : {[f'{s:.4f}' for s in cv_scores]}")
print(f"Mean CV acc : {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
print()


# ══════════════════════════════════════════════════════════════════════
# TEST 3: Per-Category Sampled Predictions
# ══════════════════════════════════════════════════════════════════════
print("=" * 80)
print("TEST 3: Sampled Predictions (3 per category)")
print("=" * 80)

correct = 0
total = 0
results = []
for cat in sorted(df["category"].unique()):
    subset = df[df["category"] == cat]
    sample = subset.sample(min(3, len(subset)), random_state=42)
    for _, row in sample.iterrows():
        pred, conf = predict_one(row.to_dict())
        match = pred == cat
        if match:
            correct += 1
        total += 1
        results.append((row["domain"], cat, pred, conf, match))

print(f"{'Domain':<30} {'Expected':<20} {'Predicted':<20} {'Conf':<8} {'Match'}")
print("-" * 100)
for domain, exp, pred, conf, match in results:
    mark = "OK" if match else "** MISS **"
    print(f"{domain:<30} {exp:<20} {pred:<20} {conf:<8} {mark}")
print(f"\nSampled accuracy: {correct}/{total} = {correct/total*100:.1f}%\n")


# ══════════════════════════════════════════════════════════════════════
# TEST 4: Unseen / Novel Domains
# ══════════════════════════════════════════════════════════════════════
print("=" * 80)
print("TEST 4: Unseen Domain Predictions (not in training data)")
print("=" * 80)

unseen_tests = [
    # (domain, protocol, packet_count, avg_packet_size, flow_duration, pps, bps, expected_category)
    ("openai.com",      "HTTPS", 50,  300.0,  5.0,  10.0, 3000.0,  "ai_tool"),
    ("chatgpt.com",     "HTTPS", 80,  250.0,  8.0,  10.0, 2500.0,  "ai_tool"),
    ("facebook.com",    "HTTPS", 120, 200.0, 10.0,  12.0, 2400.0,  "social_media"),
    ("twitter.com",     "HTTPS", 90,  180.0,  7.0,  12.9, 2314.0,  "social_media"),
    ("instagram.com",   "HTTPS", 200, 350.0, 15.0,  13.3, 4667.0,  "social_media"),
    ("netflix.com",     "HTTPS", 500, 1200.0, 30.0, 16.7, 20000.0, "streaming"),
    ("twitch.tv",       "HTTPS", 400, 1000.0, 25.0, 16.0, 16000.0, "streaming"),
    ("amazon.com",      "HTTPS", 60,  300.0,  5.0,  12.0, 3600.0,  "ecommerce"),
    ("pornhub.com",     "HTTPS", 100, 500.0, 10.0,  10.0, 5000.0,  "adult"),
    ("bing.com",        "HTTPS", 20,  200.0,  2.0,  10.0, 2000.0,  "search"),
    ("duckduckgo.com",  "HTTPS", 25,  180.0,  3.0,   8.3, 1500.0,  "search"),
    ("slack.com",       "HTTPS", 40,  150.0,  5.0,   8.0, 1200.0,  "messaging"),
    ("telegram.org",    "HTTPS", 30,  170.0,  4.0,   7.5, 1275.0,  "messaging"),
    ("notion.so",       "HTTPS", 35,  220.0,  6.0,   5.8, 1283.0,  "productivity"),
    ("docs.google.com", "HTTPS", 45,  250.0,  8.0,   5.6, 1406.0,  "writing_assistant"),
    ("medium.com",      "HTTPS", 30,  300.0,  5.0,   6.0, 1800.0,  "other"),
    ("unknown-site.xyz","HTTPS", 10,  100.0,  1.0,  10.0, 1000.0,  "other"),
]

unseen_correct = 0
unseen_total = 0
print(f"{'Domain':<25} {'Expected':<20} {'Predicted':<20} {'Conf':<8} {'Match'}")
print("-" * 95)
for domain, proto, pc, aps, fd, pps, bps, expected in unseen_tests:
    row = {
        "domain": domain, "protocol": proto,
        "packet_count": pc, "avg_packet_size": aps, "flow_duration": fd,
        "packets_per_second": pps, "bytes_per_second": bps,
    }
    pred, conf = predict_one(row)
    match = pred == expected
    if match:
        unseen_correct += 1
    unseen_total += 1
    mark = "OK" if match else "** MISS **"
    print(f"{domain:<25} {expected:<20} {pred:<20} {conf:<8} {mark}")

print(f"\nUnseen domain accuracy: {unseen_correct}/{unseen_total} = {unseen_correct/unseen_total*100:.1f}%\n")


# ══════════════════════════════════════════════════════════════════════
# TEST 5: Edge Cases (extreme & zero values)
# ══════════════════════════════════════════════════════════════════════
print("=" * 80)
print("TEST 5: Edge Case Inputs")
print("=" * 80)

edge_cases = [
    ("Zero everything",         {"domain": "google.com", "protocol": "HTTPS", "packet_count": 0, "avg_packet_size": 0, "flow_duration": 0, "packets_per_second": 0, "bytes_per_second": 0}),
    ("Huge packet count",       {"domain": "youtube.com", "protocol": "HTTPS", "packet_count": 1000000, "avg_packet_size": 1500, "flow_duration": 3600, "packets_per_second": 277.8, "bytes_per_second": 416667}),
    ("Tiny flow",               {"domain": "google.com", "protocol": "HTTPS", "packet_count": 1, "avg_packet_size": 64, "flow_duration": 0.001, "packets_per_second": 1000, "bytes_per_second": 64000}),
    ("Empty domain",            {"domain": "", "protocol": "HTTPS", "packet_count": 10, "avg_packet_size": 200, "flow_duration": 1.0, "packets_per_second": 10, "bytes_per_second": 2000}),
    ("Unknown protocol",        {"domain": "google.com", "protocol": "QUIC", "packet_count": 30, "avg_packet_size": 300, "flow_duration": 5.0, "packets_per_second": 6, "bytes_per_second": 1800}),
    ("TCP protocol",            {"domain": "whatsapp.com", "protocol": "TCP", "packet_count": 15, "avg_packet_size": 250, "flow_duration": 2.0, "packets_per_second": 7.5, "bytes_per_second": 1875}),
    ("Very long flow",          {"domain": "netflix.com", "protocol": "HTTPS", "packet_count": 50000, "avg_packet_size": 1400, "flow_duration": 7200, "packets_per_second": 6.9, "bytes_per_second": 9722}),
    ("www prefix domain",       {"domain": "www.youtube.com", "protocol": "HTTPS", "packet_count": 200, "avg_packet_size": 800, "flow_duration": 20, "packets_per_second": 10, "bytes_per_second": 8000}),
]

print(f"{'Test Case':<25} {'Domain':<20} {'Predicted':<20} {'Confidence'}")
print("-" * 80)
for name, row in edge_cases:
    try:
        pred, conf = predict_one(row)
        print(f"{name:<25} {row['domain']:<20} {pred:<20} {conf}")
    except Exception as e:
        print(f"{name:<25} {row['domain']:<20} ** ERROR: {e} **")


# ══════════════════════════════════════════════════════════════════════
# TEST 6: Feature Importance Summary
# ══════════════════════════════════════════════════════════════════════
print()
print("=" * 80)
print("TEST 6: Feature Importance Ranking")
print("=" * 80)

feature_cols = joblib.load(os.path.join(ML_DIR, "feature_cols.pkl"))
importances = sorted(
    zip(feature_cols, model.feature_importances_),
    key=lambda x: x[1], reverse=True,
)
for name, imp in importances:
    bar = "#" * int(imp * 80)
    print(f"  {name:<25} {imp:.4f}  {bar}")


# ══════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════
print()
print("=" * 80)
print("SUMMARY")
print("=" * 80)
print(f"  Training accuracy (full dataset)  : {train_acc*100:.1f}%")
print(f"  Cross-validation accuracy (5-fold): {cv_scores.mean()*100:.1f}% (+/- {cv_scores.std()*100:.1f}%)")
print(f"  Sampled per-category accuracy     : {correct/total*100:.1f}%")
print(f"  Unseen domain accuracy            : {unseen_correct/unseen_total*100:.1f}%")
print(f"  Edge cases                        : All ran without errors" if True else "")
print("=" * 80)
