import os
import warnings
from enum import Enum

import joblib
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel

warnings.filterwarnings("ignore", category=UserWarning)

ML_DIR = os.path.dirname(__file__)

model = joblib.load(os.path.join(ML_DIR, "smartshield_model.pkl"))
domain_to_id = joblib.load(os.path.join(ML_DIR, "domain_encoder.pkl"))
protocol_enc = joblib.load(os.path.join(ML_DIR, "protocol_encoder.pkl"))
category_enc = joblib.load(os.path.join(ML_DIR, "category_encoder.pkl"))
domain_lookup = joblib.load(os.path.join(ML_DIR, "domain_lookup.pkl"))
feature_cols = joblib.load(os.path.join(ML_DIR, "feature_cols.pkl"))

app = FastAPI(title="SmartShield ML Service")


# ── Mode definitions ─────────────────────────────────────────────────
class Mode(str, Enum):
    FREE = "free"
    EXAM = "exam"
    PARENTAL = "parental"


# Categories blocked per mode
MODE_BLOCKED_CATEGORIES: dict[str, set[str]] = {
    Mode.FREE: set(),                                          # nothing blocked
    Mode.EXAM: {"ai_tool", "writing_assistant", "development"},
    Mode.PARENTAL: {"adult", "social_media"},
}

# Current active mode (module-level state)
_current_mode: Mode = Mode.FREE

# ── Domain keyword lists (must match training) ───────────────────────
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
                   "nsfw", "redtube", "spankbang", "chaturbate", "stripchat",
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

TLD_MAP = {
    ".com": 0, ".org": 1, ".net": 2, ".io": 3, ".ai": 4,
    ".tv": 5, ".me": 6, ".co": 7, ".app": 8, ".dev": 9,
    ".cn": 10, ".in": 11, ".social": 12,
}


class FlowFeatures(BaseModel):
    domain: str = ""
    protocol: str = "HTTPS"
    packet_count: int = 0
    avg_packet_size: float = 0.0
    flow_duration: float = 0.0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0


def _extract_base_domain(domain: str) -> str:
    d = domain.lower().strip()
    if d.startswith("www."):
        d = d[4:]
    return d


def _extract_tld(domain: str) -> int:
    for tld, idx in TLD_MAP.items():
        if domain.endswith(tld):
            return idx
    return len(TLD_MAP)


@app.get("/health")
def health():
    return {"status": "ok"}


# ── Mode endpoints ───────────────────────────────────────────────────

class ModeRequest(BaseModel):
    mode: str


@app.get("/mode")
def get_mode():
    return {
        "mode": _current_mode.value,
        "blocked_categories": sorted(MODE_BLOCKED_CATEGORIES[_current_mode]),
    }


@app.post("/mode")
def set_mode(body: ModeRequest):
    global _current_mode
    try:
        _current_mode = Mode(body.mode.lower())
    except ValueError:
        return {
            "status": "error",
            "message": f"Invalid mode '{body.mode}'. Use: free, exam, parental",
        }
    return {
        "status": "ok",
        "mode": _current_mode.value,
        "blocked_categories": sorted(MODE_BLOCKED_CATEGORIES[_current_mode]),
    }


@app.post("/predict")
def predict(flow: FlowFeatures):
    domain = _extract_base_domain(flow.domain)

    # ── Domain text features ──────────────────────────────────────
    tld_cat = _extract_tld(domain)
    domain_len = len(domain)
    dot_count = domain.count(".")
    kw_features = {}
    for group_name, keywords in KEYWORD_GROUPS.items():
        kw_features[group_name] = int(any(kw in domain for kw in keywords))

    # ── Protocol encoding ─────────────────────────────────────────
    proto_upper = flow.protocol.upper()
    if proto_upper in protocol_enc.classes_:
        proto_encoded = int(protocol_enc.transform([proto_upper])[0])
    else:
        proto_encoded = 0

    # ── Flow statistics ───────────────────────────────────────────
    log_pc = np.log1p(flow.packet_count)
    log_fd = np.log1p(flow.flow_duration)
    log_bps = np.log1p(flow.bytes_per_second)
    log_pps = np.log1p(flow.packets_per_second)
    log_aps = np.log1p(flow.avg_packet_size)
    total_bytes = flow.packet_count * flow.avg_packet_size
    log_tb = np.log1p(total_bytes)
    fd_safe = max(flow.flow_duration, 0.001)
    flow_intensity = total_bytes / fd_safe
    log_fi = np.log1p(flow_intensity)
    size_dur_ratio = flow.avg_packet_size / fd_safe

    # ── Build feature vector (must match training order) ──────────
    features = np.array([[
        tld_cat,
        domain_len,
        dot_count,
        kw_features.get("kw_video", 0),
        kw_features.get("kw_social", 0),
        kw_features.get("kw_chat", 0),
        kw_features.get("kw_adult", 0),
        kw_features.get("kw_search", 0),
        kw_features.get("kw_ai", 0),
        kw_features.get("kw_shop", 0),
        kw_features.get("kw_dev", 0),
        kw_features.get("kw_write", 0),
        kw_features.get("kw_cdn", 0),
        kw_features.get("kw_prod", 0),
        proto_encoded,
        flow.packet_count,
        flow.avg_packet_size,
        flow.flow_duration,
        flow.packets_per_second,
        flow.bytes_per_second,
        log_pc,
        log_fd,
        log_bps,
        log_pps,
        log_aps,
        total_bytes,
        log_tb,
        flow_intensity,
        log_fi,
        size_dur_ratio,
    ]])

    prediction = int(model.predict(features)[0])
    category = category_enc.inverse_transform([prediction])[0]

    # Confidence: high if domain is known, medium if keyword match, low otherwise
    domain_known = domain in domain_to_id
    has_keyword = any(v == 1 for v in kw_features.values())

    if domain_known:
        confidence = "high"
    elif has_keyword:
        confidence = "medium"
    else:
        confidence = "low"

    # ── Keyword-based deterministic override ─────────────────────
    # When a domain clearly matches a single category keyword group,
    # override the ML prediction to ensure obvious domains aren't missed.
    KEYWORD_TO_CATEGORY = {
        "kw_adult":  "adult",
        "kw_ai":     "ai_tool",
        "kw_social": "social_media",
        "kw_video":  "streaming",
        "kw_chat":   "messaging",
        "kw_shop":   "ecommerce",
        "kw_dev":    "development",
        "kw_write":  "writing_assistant",
        "kw_search": "search",
        "kw_cdn":    "cloud_cdn",
        "kw_prod":   "productivity",
    }
    matched_groups = [g for g, v in kw_features.items() if v == 1 and g in KEYWORD_TO_CATEGORY]
    if len(matched_groups) == 1:
        # Unambiguous single keyword match — override if ML disagrees
        kw_cat = KEYWORD_TO_CATEGORY[matched_groups[0]]
        if category != kw_cat:
            category = kw_cat
            confidence = "keyword"

    # Domain lookup override for known domains (highest confidence)
    if domain in domain_lookup:
        lookup_cat = domain_lookup[domain]
        if lookup_cat != category:
            category = lookup_cat
            confidence = "lookup"

    # ── Mode-based blocking ───────────────────────────────────────
    blocked = category in MODE_BLOCKED_CATEGORIES[_current_mode]

    return {
        "category": category,
        "confidence": confidence,
        "domain": domain,
        "mode": _current_mode.value,
        "blocked": blocked,
    }
