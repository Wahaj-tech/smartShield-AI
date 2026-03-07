"""
SmartShield Backend — Domain Enforcer Service

Background service that continuously monitors network traffic for new domains,
classifies them, and dynamically blocks domains whose category is restricted
by the current mode.

Two monitoring mechanisms:
  A. Real-time DNS sniffer — captures DNS queries via tcpdump (instant detection)
  B. CSV scanner fallback  — reads DPI flow CSV periodically (catches any misses)

Classification pipeline (per domain):
  1. Static check  — is domain in CATEGORY_DOMAINS?  (instant)
  2. ML server     — call /predict (fast, no LLM)
  3. If ML confident (high/medium/keyword/lookup) → use ML result, done
  4. If ML low-confidence or failed → AI layer:
       a. SQLite cache  (instant)
       b. Heuristic AI detection  (instant)
       c. Fetch HTML + Gemini LLM  (rate-limited)
  5. Based on category + current mode → block or allow via iptables + /etc/hosts
"""

from __future__ import annotations

import asyncio
import csv
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import requests

from services import blocking_service
from services.website_classifier import (
    classify_domain,
    get_all_cached,
    heuristic_is_ai,
    lookup_cached,
    store_classification,
)
from utils.logger import get_logger

log = get_logger("domain_enforcer")

# ML server endpoint
ML_SERVER_URL = "http://localhost:8001"

# How often to scan for new domains (seconds)
SCAN_INTERVAL = 10.0

# DNS sniffer: regex to extract queried domain from tcpdump output
# tcpdump line example: "... A? chatgpt.com. (29)" or "... AAAA? google.com. (32)"
_DNS_QUERY_RE = re.compile(r"(?:A{1,4})\?\s+(\S+?)\.?\s")

# Domains to ignore in DNS monitoring (infrastructure, CDN, OS traffic)
_DNS_IGNORE_SUFFIXES = frozenset({
    ".local", ".lan", ".internal", ".localhost",
    ".in-addr.arpa", ".ip6.arpa",
})
_DNS_IGNORE_DOMAINS = frozenset({
    "connectivity-check.ubuntu.com",
    "detectportal.firefox.com",
    "nmcheck.gnome.org",
    "ntp.ubuntu.com",
    "time.google.com",
})

# Flow CSV paths (same as routes/flows.py)
FLOW_CSV_PATHS = [
    Path(__file__).resolve().parent.parent.parent / "dpi-engine" / "data" / "flow_dataset.csv",
    Path(__file__).resolve().parent.parent.parent / "dpi-engine" / "data" / "flow_dataset2.csv",
    Path(__file__).resolve().parent.parent.parent / "dpi-engine" / "flow_dataset.csv",
]

# ── State ───────────────────────────────────────────────────────────────────

# domain → { category, confidence, source, blocked }
_domain_registry: Dict[str, Dict[str, Any]] = {}
_registry_lock = threading.Lock()

# Background task handles
_enforcer_task: Optional[asyncio.Task] = None
_dns_task: Optional[asyncio.Task] = None

# Async queue: DNS monitor feeds domains here for the classifier to process
_dns_queue: Optional[asyncio.Queue] = None


# ── Helpers ─────────────────────────────────────────────────────────────────

def _find_csv() -> Optional[Path]:
    for p in FLOW_CSV_PATHS:
        if p.exists():
            return p
    return None


def _extract_domains_from_csv() -> Set[str]:
    """Read all unique domains from the DPI flow CSV."""
    csv_path = _find_csv()
    if not csv_path:
        return set()

    domains: Set[str] = set()
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                d = row.get("domain", "").strip().lower()
                if d and d != "unknown" and "." in d:
                    if d.startswith("www."):
                        d = d[4:]
                    domains.add(d)
    except Exception as exc:
        log.warning("Failed to read flow CSV: %s", exc)

    return domains


def _normalize_domain(domain: str) -> str:
    """Normalize a domain string."""
    d = domain.lower().strip()
    if d.startswith("www."):
        d = d[4:]
    return d


def _classify_via_ml(domain: str) -> Optional[Dict[str, Any]]:
    """Call the ML server /predict endpoint for a domain.

    Returns dict with keys: category, confidence, blocked, mode.
    Returns None on failure.  Fast — no LLM inside predict.
    """
    try:
        resp = requests.post(
            f"{ML_SERVER_URL}/predict",
            json={
                "domain": domain,
                "protocol": "HTTPS",
                "packet_count": 10,
                "avg_packet_size": 400.0,
                "flow_duration": 1.0,
                "packets_per_second": 10.0,
                "bytes_per_second": 4000.0,
            },
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        log.warning("ML predict failed for %s: %s", domain, exc)
        return None


def _get_current_mode() -> str:
    """Get the current mode from the ML server."""
    try:
        resp = requests.get(f"{ML_SERVER_URL}/mode", timeout=5)
        resp.raise_for_status()
        return resp.json().get("mode", "free")
    except requests.RequestException:
        return "free"


def _get_blocked_categories(mode: str) -> Set[str]:
    """Return the set of category names blocked in the given mode."""
    return set(blocking_service.MODE_BLOCKED_CATEGORIES.get(mode, []))


# ── Core enforcement logic ──────────────────────────────────────────────────

def _lookup_static_category(domain: str) -> Optional[str]:
    """Check if domain is in the hardcoded CATEGORY_DOMAINS dict.

    Returns the category string (e.g. 'ai_tool') or None.
    """
    for cat, domains in blocking_service.CATEGORY_DOMAINS.items():
        if domain in [d.lower() for d in domains]:
            return cat
    return None


# ── Core enforcement logic ──────────────────────────────────────────────────

def classify_and_enforce(domain: str) -> Dict[str, Any]:
    """Classify a single domain and enforce blocking if necessary.

    Pipeline:
      1. In-memory registry (already evaluated)
      2. Static CATEGORY_DOMAINS lookup (instant)
      3. ML server /predict (fast, no LLM)
      4. If ML confident → use result
      5. If ML low-confidence → AI layer (cache → heuristic → Gemini LLM)
      6. Block/allow based on category + current mode
    """
    domain = _normalize_domain(domain)

    # ── Already evaluated? ─────────────────────────────────────────
    with _registry_lock:
        if domain in _domain_registry:
            return _domain_registry[domain]

    mode = _get_current_mode()
    blocked_cats = _get_blocked_categories(mode)

    category: Optional[str] = None
    confidence = "none"

    # ── Step 1: Static CATEGORY_DOMAINS lookup (instant) ───────────
    static_cat = _lookup_static_category(domain)
    if static_cat:
        category = static_cat
        confidence = "static"
        log.info("Static match: %s → %s", domain, category)

    # ── Step 2: ML server /predict (fast) ──────────────────────────
    if category is None:
        ml_result = _classify_via_ml(domain)
        if ml_result:
            ml_conf = ml_result.get("confidence", "low")
            if ml_conf in ("high", "medium", "keyword", "lookup"):
                # ML is confident — trust it, no need for AI layer
                category = ml_result.get("category", "other")
                confidence = ml_conf
                log.info("ML confident: %s → %s (%s)", domain, category, confidence)
            else:
                log.info("ML low-confidence for %s, falling through to AI layer", domain)

    # ── Step 3: AI layer (only if ML failed or low-confidence) ─────
    if category is None:
        # 3a. SQLite cache
        cached = lookup_cached(domain)
        if cached:
            category = cached["category"].lower()
            confidence = "cached"
            log.info("Cache hit: %s → %s", domain, category)

        # 3b. Heuristic AI detection
        if category is None and heuristic_is_ai(domain):
            category = "ai_tool"
            confidence = "heuristic"
            store_classification(domain, "AI_TOOL", source="HEURISTIC")
            log.info("Heuristic AI match: %s", domain)

        # 3c. Gemini LLM classification (rate-limited, slow)
        if category is None:
            log.info("LLM classification for: %s", domain)
            try:
                llm_result = classify_domain(domain)
                category = llm_result.get("category", "OTHER").lower()
                confidence = llm_result.get("source", "llm").lower()
                log.info("LLM classified: %s → %s", domain, category)
            except Exception as exc:
                log.error("LLM classification failed for %s: %s", domain, exc)
                category = "other"
                confidence = "failed"

    # ── Step 4: Enforce blocking ───────────────────────────────────
    blocked = category in blocked_cats
    enforced = False
    if blocked and not blocking_service.is_blocked(domain):
        log.info(
            "AUTO-BLOCKING %s (category=%s, confidence=%s, mode=%s)",
            domain, category, confidence, mode,
        )
        result = blocking_service.block_domain(
            domain,
            reason=f"Auto-blocked ({category}, {confidence})",
            auto=True,
        )
        enforced = result.get("status") == "ok"

    # ── Step 5: Store in cache if new classification ───────────────
    if confidence not in ("static", "cached") and category:
        store_classification(domain, category.upper(), source=confidence.upper())

    # ── Register in memory ─────────────────────────────────────────
    entry = {
        "domain": domain,
        "category": category,
        "confidence": confidence,
        "blocked": blocked,
        "enforced": enforced,
    }
    with _registry_lock:
        _domain_registry[domain] = entry

    return entry


def enforce_mode(mode: str) -> Dict[str, Any]:
    """Re-evaluate ALL known domains for a new mode.

    Called when the user changes the mode. This does three things:
    1. Re-evaluates all domains already in registry + cache
    2. Scans the DPI flow CSV for any unclassified domains and classifies them
    3. Blocks/unblocks dynamically classified domains based on the new mode
    """
    blocked_cats = _get_blocked_categories(mode)
    newly_blocked = 0
    newly_unblocked = 0

    # 1. Gather all domains from: registry + LLM cache + flow CSV
    all_domains: Dict[str, str] = {}  # domain → category

    with _registry_lock:
        for domain, info in _domain_registry.items():
            all_domains[domain] = info["category"]

    for entry in get_all_cached():
        d = _normalize_domain(entry["domain"])
        if d not in all_domains:
            all_domains[d] = entry["category"].lower()

    # Also scan CSV for domains not yet classified
    csv_domains = _extract_domains_from_csv()
    unclassified = []
    for d in csv_domains:
        if d not in all_domains and not _lookup_static_category(d):
            unclassified.append(d)

    # Classify unclassified domains (ML first, then AI layer)
    for domain in unclassified:
        try:
            result = classify_and_enforce(domain)
            all_domains[domain] = result.get("category", "other")
        except Exception as exc:
            log.error("Classification failed for %s during mode change: %s", domain, exc)

    # 2. For each domain, check if it should be blocked or unblocked
    for domain, category in all_domains.items():
        # Skip static domains (handled by apply_mode)
        if _lookup_static_category(domain):
            continue

        should_block = category in blocked_cats
        currently_blocked = blocking_service.is_blocked(domain)

        if should_block and not currently_blocked:
            result = blocking_service.block_domain(
                domain,
                reason=f"Auto-blocked ({category})",
                auto=True,
            )
            if result.get("status") == "ok":
                newly_blocked += 1
                log.info("Mode change → blocked %s (category=%s)", domain, category)

        elif not should_block and currently_blocked:
            # Only unblock auto-blocked domains (keep manual blocks)
            blocked_info = blocking_service._blocked.get(domain, {})
            if blocked_info.get("auto", False):
                blocking_service.unblock_domain(domain)
                newly_unblocked += 1
                log.info("Mode change → unblocked %s (category=%s)", domain, category)

        # Update registry
        with _registry_lock:
            if domain in _domain_registry:
                _domain_registry[domain]["blocked"] = should_block

    return {
        "dynamic_blocked": newly_blocked,
        "dynamic_unblocked": newly_unblocked,
        "total_dynamic_domains": len(all_domains),
        "newly_classified": len(unclassified),
    }


# ── Real-time DNS monitor ───────────────────────────────────────────────────

def _should_ignore_domain(domain: str) -> bool:
    """Check if a domain should be ignored (infrastructure/noise)."""
    if not domain or len(domain) < 4 or "." not in domain:
        return True
    for suffix in _DNS_IGNORE_SUFFIXES:
        if domain.endswith(suffix):
            return True
    if domain in _DNS_IGNORE_DOMAINS:
        return True
    # Skip numeric-only domains (IP addresses queried as names)
    if all(c.isdigit() or c == "." for c in domain):
        return True
    return False


async def _dns_monitor() -> None:
    """Sniff DNS queries via tcpdump and feed new domains to the classifier.

    Uses subprocess.Popen in a background thread for reliable line-buffered
    capture of tcpdump output. When a NEW domain is seen, it's placed on
    _dns_queue for the classifier worker to process.
    """
    global _dns_queue
    if _dns_queue is None:
        _dns_queue = asyncio.Queue(maxsize=1000)

    seen: Set[str] = set()

    # Pre-populate seen set with already-known domains
    with _registry_lock:
        seen.update(_domain_registry.keys())
    for cat_domains in blocking_service.CATEGORY_DOMAINS.values():
        for d in cat_domains:
            seen.add(d.lower())

    log.info("DNS monitor starting (pre-populated %d known domains)", len(seen))

    loop = asyncio.get_event_loop()

    def _run_tcpdump_reader():
        """Blocking thread: reads tcpdump stdout line-by-line."""
        while True:
            proc = None
            try:
                proc = subprocess.Popen(
                    ["sudo", "-n", "/usr/bin/tcpdump",
                     "-l", "-i", "any", "-nn",
                     "udp", "port", "53"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    bufsize=0,
                )
                log.info("DNS tcpdump started (pid=%d)", proc.pid)

                for raw_line in proc.stdout:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue

                    # Parse domain from DNS query line
                    match = _DNS_QUERY_RE.search(line)
                    if not match:
                        continue

                    domain = match.group(1).rstrip(".").lower().strip()
                    if domain.startswith("www."):
                        domain = domain[4:]

                    if _should_ignore_domain(domain):
                        continue

                    if domain in seen:
                        continue

                    seen.add(domain)
                    log.info("DNS query detected: %s", domain)

                    # Thread-safe enqueue to asyncio
                    try:
                        loop.call_soon_threadsafe(_dns_queue.put_nowait, domain)
                    except Exception:
                        pass

                log.warning("DNS tcpdump exited (rc=%s)", proc.returncode)

            except Exception as exc:
                log.error("DNS tcpdump error: %s", exc)
            finally:
                if proc and proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()

            # Restart after delay
            time.sleep(3)

    # Run the blocking tcpdump reader in a daemon thread
    dns_thread = threading.Thread(target=_run_tcpdump_reader, daemon=True)
    dns_thread.start()

    # Keep this coroutine alive until cancelled
    try:
        while True:
            await asyncio.sleep(60)
    except asyncio.CancelledError:
        log.info("DNS monitor task cancelled")
        # tcpdump thread is daemon, will die with process


async def _dns_classifier_worker() -> None:
    """Process domains from the DNS queue — classify and enforce blocking.

    Runs as a background asyncio task. Reads domains from _dns_queue
    and runs them through the classification pipeline.
    """
    global _dns_queue
    if _dns_queue is None:
        _dns_queue = asyncio.Queue(maxsize=1000)

    log.info("DNS classifier worker started")

    while True:
        try:
            domain = await _dns_queue.get()

            # Skip if already evaluated
            with _registry_lock:
                if domain in _domain_registry:
                    _dns_queue.task_done()
                    continue

            # Classify in a thread (may involve network calls)
            try:
                result = await asyncio.to_thread(classify_and_enforce, domain)
                if result.get("enforced"):
                    log.info(
                        "DNS → BLOCKED %s (category=%s, confidence=%s)",
                        domain, result["category"], result["confidence"],
                    )
                elif result.get("blocked"):
                    log.info(
                        "DNS → already blocked %s (category=%s)",
                        domain, result["category"],
                    )
                else:
                    log.debug(
                        "DNS → allowed %s (category=%s)",
                        domain, result.get("category", "?"),
                    )
            except Exception as exc:
                log.error("DNS classification failed for %s: %s", domain, exc)

            _dns_queue.task_done()

            # Small delay between classifications for API rate limiting
            await asyncio.sleep(0.3)

        except asyncio.CancelledError:
            log.info("DNS classifier worker shutting down")
            return
        except Exception as exc:
            log.error("DNS worker error: %s", exc)
            await asyncio.sleep(1)


# ── Background CSV scanner (fallback) ──────────────────────────────────────

async def _scan_loop() -> None:
    """Background loop: periodically scan for new domains and classify them.

    Runs in ALL modes — pre-classifies domains so mode switches are instant.
    Only enforces blocking when the current mode requires it.

    This is a FALLBACK mechanism. The primary real-time detection is the
    DNS monitor above.
    """
    await asyncio.sleep(5)
    log.info("CSV scanner started (interval=%.0fs)", SCAN_INTERVAL)

    seen_domains: Set[str] = set()

    while True:
        try:
            # Read new domains from flow CSV
            csv_domains = await asyncio.to_thread(_extract_domains_from_csv)
            new_domains = csv_domains - seen_domains
            seen_domains.update(csv_domains)

            if new_domains:
                log.info("CSV scanner found %d new domains to evaluate", len(new_domains))

            # Classify and enforce each new domain
            for domain in new_domains:
                # Skip static CATEGORY_DOMAINS (already handled by apply_mode)
                if _lookup_static_category(domain):
                    continue

                # Skip domains already evaluated
                with _registry_lock:
                    if domain in _domain_registry:
                        continue

                # Classify in a thread (may involve network calls / LLM)
                try:
                    result = await asyncio.to_thread(classify_and_enforce, domain)
                    if result.get("enforced"):
                        log.info(
                            "CSV → Enforced block on %s → %s",
                            domain, result["category"],
                        )
                except Exception as exc:
                    log.error("CSV classification failed for %s: %s", domain, exc)

                # Small delay between classifications to be nice to APIs
                await asyncio.sleep(0.5)

        except asyncio.CancelledError:
            log.info("CSV scanner stopped")
            return
        except Exception as exc:
            log.error("CSV scanner error: %s", exc)

        await asyncio.sleep(SCAN_INTERVAL)


def start_scanner() -> None:
    """Start the background domain scanner + DNS monitor tasks."""
    global _enforcer_task, _dns_task, _dns_queue

    _dns_queue = asyncio.Queue(maxsize=1000)

    # Start CSV scanner (fallback)
    if _enforcer_task is None or _enforcer_task.done():
        _enforcer_task = asyncio.create_task(_scan_loop())

    # Start DNS monitor + classifier worker
    if _dns_task is None or _dns_task.done():
        _dns_task = asyncio.create_task(_dns_monitor())
        asyncio.create_task(_dns_classifier_worker())

    log.info("Domain enforcer started (DNS monitor + CSV scanner)")


async def stop_scanner() -> None:
    """Stop the background scanner and DNS monitor gracefully."""
    global _enforcer_task, _dns_task

    for task in [_enforcer_task, _dns_task]:
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    # Also cancel any remaining tasks we created
    _enforcer_task = None
    _dns_task = None
    log.info("Domain enforcer stopped")
