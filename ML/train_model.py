"""
SmartShield ML Model Training Script (v2)
Trains a GradientBoostingClassifier on combined flow datasets.
Uses domain TEXT features + flow statistics for traffic categorization.
Eliminates domain_id to prevent memorization and improve generalization.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import (
    cross_val_score,
    StratifiedKFold,
    train_test_split,
)
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
OUTPUT_DIR = os.path.dirname(__file__)

# ── Domain keyword lists for text feature extraction ──────────────────
KEYWORD_GROUPS = {
    "kw_video":   ["video", "tube", "stream", "watch", "vimeo", "youtube",
                   "netflix", "hulu", "twitch", "dailymotion", "spotify",
                   "hbo", "disney", "peacock", "crunchyroll", "dazn",
                   "tubi", "soundcloud", "pandora", "audible", "jiosaavn",
                   "prime"],
    "kw_social":  ["social", "face", "insta", "snap", "tiktok", "twitter",
                   "tweet", "reddit", "pinterest", "tumblr", "mastodon",
                   "threads", "bluesky", "quora", "medium", "linkedin",
                   "meta", "x.com"],
    "kw_chat":    ["chat", "messag", "whatsapp", "telegram", "signal",
                   "viber", "wechat", "line", "discord", "slack", "element",
                   "matrix", "groupme"],
    "kw_adult":   ["porn", "xxx", "xnxx", "xvideo", "xhamster", "adult",
                   "nsfw", "redtube", "spankbang", "chaturbate", "strip",
                   "onlyfans", "erome", "youporn", "phncdn", "highwebmedia"],
    "kw_search":  ["search", "google.com", "bing", "duck", "yahoo", "yandex",
                   "baidu", "ecosia", "startpage"],
    "kw_ai":      ["ai", "gpt", "claude", "anthropic", "openai", "gemini",
                   "copilot", "hugging", "cohere", "midjourney", "stability",
                   "replicate", "deepmind", "jasper", "perplexity", "grok",
                   "kimi", "moonshot"],
    "kw_shop":    ["shop", "store", "buy", "cart", "amazon", "ebay", "etsy",
                   "walmart", "alibaba", "flipkart", "target", "bestbuy",
                   "wish", "aliexpress", "myntra", "zalando", "rakuten",
                   "commerce", "shopify"],
    "kw_dev":     ["github", "gitlab", "bitbucket", "stack", "code", "dev",
                   "npm", "pypi", "docker", "heroku", "vercel", "netlify",
                   "replit", "codepen", "codesand", "jsfiddle", "readme",
                   "readthedocs"],
    "kw_write":   ["write", "grammar", "grammarly", "quill", "wordtune",
                   "hemingway", "prowriting", "scribens", "language",
                   "writesonic", "rytr", "sudowrite", "overleaf", "doc"],
    "kw_cdn":     ["cdn", "cloudflare", "akamai", "fastly", "cache",
                   "edge", "cloudfront", "bunny", "stackpath", "keycdn",
                   "limelight", "azureedge"],
    "kw_prod":    ["notion", "trello", "asana", "monday", "todoist",
                   "clickup", "airtable", "basecamp", "jira", "linear",
                   "miro", "figma", "canva", "zoom", "teams", "azure",
                   "productivity", "project"],
}

# TLD categories
TLD_MAP = {
    ".com": 0, ".org": 1, ".net": 2, ".io": 3, ".ai": 4,
    ".tv": 5, ".me": 6, ".co": 7, ".app": 8, ".dev": 9,
    ".cn": 10, ".in": 11, ".social": 12,
}


def load_data():
    """Load and combine both flow datasets, deduplicate."""
    paths = [
        os.path.join(PROJECT_ROOT, "dpi-engine", "flow_dataset.csv"),
        os.path.join(PROJECT_ROOT, "dpi-engine", "data", "flow_dataset.csv"),
    ]
    frames = []
    for p in paths:
        if os.path.exists(p):
            frames.append(pd.read_csv(p))
            print(f"Loaded {p}: {len(frames[-1])} rows")
    df = pd.concat(frames, ignore_index=True).drop_duplicates()
    print(f"Combined (deduplicated): {len(df)} rows")
    return df


def build_domain_lookup(df):
    """Build a domain -> category lookup from training data."""
    domain_cat = (
        df.groupby("domain")["category"]
        .agg(lambda x: x.value_counts().index[0])
        .to_dict()
    )
    return domain_cat


def extract_tld(domain):
    """Extract TLD category from domain."""
    d = domain.lower().strip()
    for tld, idx in TLD_MAP.items():
        if d.endswith(tld):
            return idx
    return len(TLD_MAP)  # unknown TLD


def extract_domain_text_features(domain):
    """Extract text-based features from a domain name."""
    d = domain.lower().strip()
    if d.startswith("www."):
        d = d[4:]

    features = {}
    # TLD category
    features["tld_cat"] = extract_tld(d)
    # Domain length
    features["domain_len"] = len(d)
    # Number of dots (subdomain depth)
    features["dot_count"] = d.count(".")
    # Keyword group matches
    for group_name, keywords in KEYWORD_GROUPS.items():
        features[group_name] = int(any(kw in d for kw in keywords))
    return features


def engineer_features(df):
    """Create features from domain text patterns and flow statistics."""
    df = df.copy()

    # ── Domain text features (replaces domain_id) ─────────────────
    text_feats = df["domain"].apply(extract_domain_text_features)
    text_df = pd.DataFrame(text_feats.tolist())
    for col in text_df.columns:
        df[col] = text_df[col].values

    # ── Protocol encoding ─────────────────────────────────────────
    protocol_enc = LabelEncoder()
    df["protocol_encoded"] = protocol_enc.fit_transform(df["protocol"])

    # ── Flow statistics features ──────────────────────────────────
    df["log_packet_count"] = np.log1p(df["packet_count"])
    df["log_flow_duration"] = np.log1p(df["flow_duration"])
    df["log_bytes_per_second"] = np.log1p(df["bytes_per_second"])
    df["log_packets_per_second"] = np.log1p(df["packets_per_second"])
    df["log_avg_packet_size"] = np.log1p(df["avg_packet_size"])
    df["total_bytes"] = df["packet_count"] * df["avg_packet_size"]
    df["log_total_bytes"] = np.log1p(df["total_bytes"])

    # Flow intensity (bytes transferred per second of flow)
    df["flow_intensity"] = df["total_bytes"] / df["flow_duration"].clip(lower=0.001)
    df["log_flow_intensity"] = np.log1p(df["flow_intensity"])

    # Packet size to duration ratio
    df["size_duration_ratio"] = df["avg_packet_size"] / df["flow_duration"].clip(lower=0.001)

    # Domain text feature column names
    text_feature_cols = list(text_df.columns)

    feature_cols = (
        text_feature_cols
        + [
            "protocol_encoded",
            "packet_count",
            "avg_packet_size",
            "flow_duration",
            "packets_per_second",
            "bytes_per_second",
            "log_packet_count",
            "log_flow_duration",
            "log_bytes_per_second",
            "log_packets_per_second",
            "log_avg_packet_size",
            "total_bytes",
            "log_total_bytes",
            "flow_intensity",
            "log_flow_intensity",
            "size_duration_ratio",
        ]
    )

    # Build domain_to_id for backward compatibility (lookup only)
    unique_domains = sorted(df["domain"].unique())
    domain_to_id = {d: i for i, d in enumerate(unique_domains)}

    return df, feature_cols, domain_to_id, protocol_enc


def train():
    df = load_data()

    # Clean: drop unknown category
    df = df[df["category"] != "unknown"].copy()
    print(f"After removing 'unknown': {len(df)} rows")
    print(f"Categories: {sorted(df['category'].unique())}")
    print(f"Distribution:\n{df['category'].value_counts()}\n")

    # Engineer features
    df, feature_cols, domain_to_id, protocol_enc = engineer_features(df)

    # Encode target
    category_enc = LabelEncoder()
    y = category_enc.fit_transform(df["category"])
    X = df[feature_cols].values

    print(f"Features ({len(feature_cols)}): {feature_cols}")
    print(f"X shape: {X.shape}, classes: {list(category_enc.classes_)}\n")

    # ── Train/Test split for honest evaluation ────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    print(f"Train: {X_train.shape[0]}, Test: {X_test.shape[0]}\n")

    # ── Model: Gradient Boosting (better generalization than RF) ──
    model = GradientBoostingClassifier(
        n_estimators=300,
        max_depth=6,
        min_samples_split=10,
        min_samples_leaf=5,
        learning_rate=0.1,
        subsample=0.8,
        random_state=42,
    )

    # Cross-validation on training set
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="accuracy")
    print(f"Cross-validation accuracy: {scores.mean():.4f} (+/- {scores.std():.4f})")
    print(f"Per-fold: {[f'{s:.4f}' for s in scores]}\n")

    # Train final model on ALL data (after evaluating on split)
    model.fit(X_train, y_train)

    # Test set report
    y_test_pred = model.predict(X_test)
    print("=== Test Set Classification Report (20% held out) ===")
    print(classification_report(y_test, y_test_pred,
                                target_names=category_enc.classes_,
                                zero_division=0))
    test_acc = (y_test_pred == y_test).mean()
    print(f"Test accuracy: {test_acc:.4f} ({test_acc*100:.1f}%)\n")

    # Now retrain on ALL data for production
    model.fit(X, y)
    y_pred = model.predict(X)
    print("=== Full Training Set Report (final model) ===")
    print(classification_report(y, y_pred,
                                target_names=category_enc.classes_,
                                zero_division=0))

    # Feature importances
    importances = sorted(
        zip(feature_cols, model.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    )
    print("Feature importances:")
    for name, imp in importances:
        print(f"  {name}: {imp:.4f}")

    # Save artifacts
    joblib.dump(model, os.path.join(OUTPUT_DIR, "smartshield_model.pkl"))
    joblib.dump(domain_to_id, os.path.join(OUTPUT_DIR, "domain_encoder.pkl"))
    joblib.dump(protocol_enc, os.path.join(OUTPUT_DIR, "protocol_encoder.pkl"))
    joblib.dump(category_enc, os.path.join(OUTPUT_DIR, "category_encoder.pkl"))
    joblib.dump(feature_cols, os.path.join(OUTPUT_DIR, "feature_cols.pkl"))

    # Save domain->category lookup for fallback
    domain_lookup = build_domain_lookup(df)
    joblib.dump(domain_lookup, os.path.join(OUTPUT_DIR, "domain_lookup.pkl"))

    print(f"\nSaved model and encoders to {OUTPUT_DIR}/")
    print(f"Domain lookup: {len(domain_lookup)} domains")


if __name__ == "__main__":
    train()
