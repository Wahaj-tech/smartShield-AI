"""
SmartShield Backend — Website Classifier (Layered Pipeline)

Classifies domains using a 4-layer pipeline:
  1. SQLite cache lookup  (instant)
  2. Heuristic AI detection  (domain-name patterns, instant)
  3. Fetch HTML + send to Gemini LLM  (network, rate-limited)
  4. Cache result for future lookups

Rate-limited to 1 Gemini request per second.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from bs4 import BeautifulSoup

from utils.logger import get_logger

log = get_logger("website_classifier")

# ── Configuration ───────────────────────────────────────────────────────────

GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
GEMINI_ENDPOINT: str = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    f"{GEMINI_MODEL}:generateContent"
)

VALID_CATEGORIES = frozenset({
    "AI_TOOL", "STREAMING", "SOCIAL_MEDIA", "MESSAGING", "SEARCH",
    "DEVELOPMENT", "WRITING_ASSISTANT", "ECOMMERCE", "CLOUD_CDN",
    "PRODUCTIVITY", "ADULT", "OTHER",
})

_DB_PATH = Path(__file__).resolve().parent.parent / "domain_categories.db"

# Rate limit: 1 request per second (conservative for free tier)
_RATE_LIMIT = 1
_rate_lock = threading.Lock()
_request_times: List[float] = []

# ── Heuristic AI-detection patterns ────────────────────────────────────────

_AI_KEYWORDS = [
    "ai", "gpt", "openai", "copilot", "claude", "perplexity",
    "midjourney", "llm", "gemini", "anthropic", "huggingface",
    "chatbot", "deepmind", "stability", "replicate", "cohere",
    "bard", "jasper",
]

_AI_TLD = ".ai"


def heuristic_is_ai(domain: str) -> bool:
    """Return True if the domain name strongly suggests an AI tool.

    Checks:
      - .ai TLD
      - Known AI keywords anywhere in the domain name
    """
    d = domain.lower().strip()
    if d.startswith("www."):
        d = d[4:]

    # .ai top-level domain
    if d.endswith(_AI_TLD):
        return True

    # Check keywords against domain parts (split on dots and hyphens)
    parts = re.split(r"[.\-]", d)
    for kw in _AI_KEYWORDS:
        for part in parts:
            if kw == part:          # exact match on a domain segment
                return True
            if kw in part and len(kw) >= 3:  # substring match for longer keywords
                return True

    return False

# ── Database helpers ────────────────────────────────────────────────────────

_db_lock = threading.Lock()


def _get_connection() -> sqlite3.Connection:
    """Return a thread-local SQLite connection with WAL mode."""
    conn = sqlite3.connect(str(_DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    """Create the domain_categories table if it does not exist."""
    with _db_lock:
        conn = _get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS domain_categories (
                    domain      TEXT PRIMARY KEY,
                    category    TEXT NOT NULL,
                    source      TEXT NOT NULL DEFAULT 'LLM',
                    timestamp   TEXT NOT NULL
                )
            """)
            conn.commit()
            log.info("Domain categories database ready at %s", _DB_PATH)
        finally:
            conn.close()


def lookup_cached(domain: str) -> Optional[Dict[str, Any]]:
    """Return cached classification or None."""
    with _db_lock:
        conn = _get_connection()
        try:
            row = conn.execute(
                "SELECT domain, category, source, timestamp "
                "FROM domain_categories WHERE domain = ?",
                (domain,),
            ).fetchone()
            if row:
                return dict(row)
            return None
        finally:
            conn.close()


def store_classification(domain: str, category: str, source: str = "LLM") -> None:
    """Insert or update a domain classification in the cache."""
    ts = datetime.now(timezone.utc).isoformat()
    with _db_lock:
        conn = _get_connection()
        try:
            conn.execute(
                """
                INSERT INTO domain_categories (domain, category, source, timestamp)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    category  = excluded.category,
                    source    = excluded.source,
                    timestamp = excluded.timestamp
                """,
                (domain, category, source, ts),
            )
            conn.commit()
            log.info("Cached classification: %s → %s (source=%s)", domain, category, source)
        finally:
            conn.close()


def get_all_cached() -> list[Dict[str, Any]]:
    """Return every cached classification."""
    with _db_lock:
        conn = _get_connection()
        try:
            rows = conn.execute(
                "SELECT domain, category, source, timestamp "
                "FROM domain_categories ORDER BY timestamp DESC"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# ── HTML fetching ───────────────────────────────────────────────────────────

def fetch_html(domain: str, timeout: float = 5.0) -> Optional[str]:
    """Fetch the homepage HTML for *domain*.  Returns None on failure."""
    url = f"https://{domain}"
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as exc:
        log.warning("Failed to fetch %s: %s", url, exc)
        # Fallback to HTTP
        try:
            url_http = f"http://{domain}"
            resp = requests.get(url_http, headers=headers, timeout=timeout, allow_redirects=True)
            resp.raise_for_status()
            return resp.text
        except requests.RequestException:
            return None


# ── Text extraction ─────────────────────────────────────────────────────────

def extract_visible_text(html: str, max_chars: int = 3000) -> str:
    """Extract meaningful visible text from HTML.

    Prioritises <title>, <meta description>, and opening <p> tags.
    Strips scripts, styles, and noscript blocks.
    """
    soup = BeautifulSoup(html, "html.parser")

    # Remove noise tags
    for tag in soup.find_all(["script", "style", "noscript", "svg", "iframe"]):
        tag.decompose()

    parts: list[str] = []

    # Title
    title_tag = soup.find("title")
    if title_tag and title_tag.string:
        parts.append(f"Title: {title_tag.string.strip()}")

    # Meta description
    meta_desc = soup.find("meta", attrs={"name": "description"})
    if meta_desc and meta_desc.get("content"):
        parts.append(f"Description: {meta_desc['content'].strip()}")

    # Meta keywords
    meta_kw = soup.find("meta", attrs={"name": "keywords"})
    if meta_kw and meta_kw.get("content"):
        parts.append(f"Keywords: {meta_kw['content'].strip()}")

    # Headings (h1-h3)
    for level in ("h1", "h2", "h3"):
        for h in soup.find_all(level, limit=5):
            text = h.get_text(separator=" ", strip=True)
            if text:
                parts.append(text)

    # Paragraphs
    for p in soup.find_all("p", limit=20):
        text = p.get_text(separator=" ", strip=True)
        if len(text) > 20:
            parts.append(text)

    combined = "\n".join(parts)

    # Collapse whitespace
    combined = re.sub(r"\s+", " ", combined).strip()

    return combined[:max_chars]


# ── Rate limiter ────────────────────────────────────────────────────────────

def _wait_for_rate_limit() -> None:
    """Block until we are within the rate limit window."""
    with _rate_lock:
        now = time.monotonic()
        # Purge timestamps older than 1 second
        while _request_times and _request_times[0] < now - 1.0:
            _request_times.pop(0)
        if len(_request_times) >= _RATE_LIMIT:
            sleep_for = 1.0 - (now - _request_times[0])
            if sleep_for > 0:
                time.sleep(sleep_for)
        _request_times.append(time.monotonic())


# ── Gemini classification ──────────────────────────────────────────────────

_GEMINI_PROMPT = """\
Classify the following website.

Domain: {domain}

Content:
{text}

Categories:
AI_TOOL
STREAMING
SOCIAL_MEDIA
MESSAGING
SEARCH
DEVELOPMENT
WRITING_ASSISTANT
ECOMMERCE
CLOUD_CDN
PRODUCTIVITY
ADULT
OTHER

Return JSON only.
{{
  "category": "CATEGORY_NAME"
}}
"""


def classify_with_gemini(domain: str, text: str) -> Optional[str]:
    """Send domain + extracted text to Gemini and return the category string.

    Returns None if the API call fails or the response is unparseable.
    """
    if not GEMINI_API_KEY:
        log.error("GEMINI_API_KEY not set — cannot classify with LLM")
        return None

    prompt = _GEMINI_PROMPT.format(domain=domain, text=text)

    payload = {
        "contents": [
            {
                "parts": [{"text": prompt}]
            }
        ],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 64,
        },
    }

    _wait_for_rate_limit()

    max_retries = 3
    for attempt in range(max_retries):
        try:
            resp = requests.post(
                GEMINI_ENDPOINT,
                params={"key": GEMINI_API_KEY},
                json=payload,
                timeout=20,
            )

            # Handle rate limiting with retry
            if resp.status_code == 429:
                wait_time = (attempt + 1) * 5  # 5s, 10s, 15s
                log.warning("Gemini rate limited (429), retrying in %ds...", wait_time)
                time.sleep(wait_time)
                continue

            resp.raise_for_status()
            data = resp.json()

            # Extract the generated text
            candidates = data.get("candidates", [])
            if not candidates:
                log.warning("Gemini returned no candidates")
                return None

            raw_text = candidates[0]["content"]["parts"][0]["text"].strip()
            log.debug("Gemini raw response: %s", raw_text)

            # Parse JSON from the response (handle markdown code fences)
            json_text = raw_text
            if "```" in json_text:
                # Strip markdown code block
                json_text = re.sub(r"```(?:json)?\s*", "", json_text)
                json_text = json_text.replace("```", "").strip()

            result = json.loads(json_text)
            category = result.get("category", "").upper().strip()

            if category in VALID_CATEGORIES:
                return category

            log.warning("Gemini returned unexpected category: %s", category)
            return "OTHER"

        except requests.RequestException as exc:
            log.error("Gemini API request failed: %s", exc)
            if attempt < max_retries - 1:
                time.sleep((attempt + 1) * 3)
                continue
            return None
        except (json.JSONDecodeError, KeyError, IndexError) as exc:
            log.error("Failed to parse Gemini response: %s", exc)
            return None

    log.error("Gemini API: all retries exhausted")
    return None


# ── Main classification pipeline ────────────────────────────────────────────

def classify_domain(domain: str) -> Dict[str, Any]:
    """Layered classification pipeline:

    1. SQLite cache  →  instant
    2. Heuristic AI detection  →  instant (domain-name patterns)
    3. Fetch HTML + Gemini LLM  →  network call (rate-limited)
    4. Cache result
    """
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]

    # ── Layer 1: Cache ──────────────────────────────────────────────
    cached = lookup_cached(domain)
    if cached:
        log.info("Cache hit: %s → %s", domain, cached["category"])
        return {
            "domain": domain,
            "category": cached["category"],
            "source": cached["source"],
            "cached": True,
        }

    # ── Layer 2: Heuristic AI detection ─────────────────────────────
    if heuristic_is_ai(domain):
        log.info("Heuristic AI match: %s", domain)
        store_classification(domain, "AI_TOOL", source="HEURISTIC")
        return {
            "domain": domain,
            "category": "AI_TOOL",
            "source": "HEURISTIC",
            "cached": False,
        }

    # ── Layer 3: Fetch HTML + Gemini LLM ────────────────────────────
    log.info("LLM classification needed for: %s", domain)
    html = fetch_html(domain)
    if not html:
        store_classification(domain, "OTHER", source="LLM_FALLBACK")
        return {
            "domain": domain,
            "category": "OTHER",
            "source": "LLM_FALLBACK",
            "cached": False,
        }

    text = extract_visible_text(html)
    if len(text) < 30:
        store_classification(domain, "OTHER", source="LLM_FALLBACK")
        return {
            "domain": domain,
            "category": "OTHER",
            "source": "LLM_FALLBACK",
            "cached": False,
        }

    category = classify_with_gemini(domain, text)
    if not category:
        category = "OTHER"
        source = "LLM_FALLBACK"
    else:
        source = "LLM"

    # ── Layer 4: Cache ──────────────────────────────────────────────
    store_classification(domain, category, source=source)

    return {
        "domain": domain,
        "category": category,
        "source": source,
        "cached": False,
    }


# ── Async wrapper (for FastAPI route handlers) ──────────────────────────────

async def classify_domain_async(domain: str) -> Dict[str, Any]:
    """Non-blocking wrapper around classify_domain for async handlers."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, classify_domain, domain)
