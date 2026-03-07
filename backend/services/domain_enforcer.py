"""
SmartShield Backend — Domain Enforcer Service

Background service that continuously monitors network traffic for new domains,
classifies them using ML + LLM fallback, and dynamically blocks domains
whose category is restricted by the current mode.

Architecture flow:
  - Reads new domains from the DPI flow CSV (written in real-time by the engine)
  - For each unseen domain → calls ML server /predict
  - ML returns category + confidence; if confidence is "low" → LLM fallback runs
  - If category is in the current mode's blocked list → block via iptables + /etc/hosts
  - On mode change → re-evaluate ALL known domains and block/unblock accordingly
"""

from __future__ import annotations

import asyncio
import csv
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

# Background task handle
_enforcer_task: Optional[asyncio.Task] = None


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
    Returns None on failure.
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
            timeout=30,  # LLM fallback can be slow
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

def classify_and_enforce(domain: str) -> Dict[str, Any]:
    """Classify a single domain and enforce blocking if necessary.

    Pipeline: cache → heuristic → ML → LLM fallback → block/allow.
    """
    domain = _normalize_domain(domain)

    # Skip if already known and evaluated
    with _registry_lock:
        if domain in _domain_registry:
            return _domain_registry[domain]

    mode = _get_current_mode()
    blocked_cats = _get_blocked_categories(mode)

    # ── Layer 1: Cache ─────────────────────────────────────────────
    cached = lookup_cached(domain)
    if cached:
        category = cached["category"].lower()
        confidence = "cached"
        blocked = category in blocked_cats
        log.info("Cache hit: %s → %s", domain, category)
    # ── Layer 2: Heuristic AI detection ────────────────────────────
    elif heuristic_is_ai(domain):
        category = "ai_tool"
        confidence = "heuristic"
        blocked = category in blocked_cats
        store_classification(domain, "AI_TOOL", source="HEURISTIC")
        log.info("Heuristic AI match: %s", domain)
    else:
        # ── Layer 3: ML server ─────────────────────────────────────
        ml_result = _classify_via_ml(domain)
        if ml_result and ml_result.get("confidence", "low") != "low":
            category = ml_result.get("category", "other")
            confidence = ml_result.get("confidence", "medium")
            blocked = ml_result.get("blocked", False)
        else:
            # ── Layer 4: LLM fallback via classify_domain ──────────
            log.info("ML low-confidence / unreachable, trying LLM for %s", domain)
            try:
                llm_result = classify_domain(domain)
                category = llm_result.get("category", "OTHER").lower()
                confidence = "llm"
                blocked = category in blocked_cats
            except Exception as exc:
                log.error("All classification failed for %s: %s", domain, exc)
                return {
                    "domain": domain,
                    "category": "other",
                    "confidence": "none",
                    "blocked": False,
                    "enforced": False,
                }

    # ── Enforce blocking ───────────────────────────────────────────
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

    Called when the user changes the mode. Checks both:
    - The static CATEGORY_DOMAINS list (handled by blocking_service.apply_mode)
    - The dynamic domain registry (ML + LLM classified domains)
    - The LLM cache database
    """
    blocked_cats = _get_blocked_categories(mode)
    newly_blocked = 0
    newly_unblocked = 0

    # 1. Gather all domains from: registry + LLM cache
    all_domains: Dict[str, str] = {}  # domain → category

    with _registry_lock:
        for domain, info in _domain_registry.items():
            all_domains[domain] = info["category"]

    for entry in get_all_cached():
        d = _normalize_domain(entry["domain"])
        if d not in all_domains:
            all_domains[d] = entry["category"].lower()

    # 2. For each domain, check if it should be blocked or unblocked
    for domain, category in all_domains.items():
        # Skip domains already in the static CATEGORY_DOMAINS (handled by apply_mode)
        is_static = False
        for cat_domains in blocking_service.CATEGORY_DOMAINS.values():
            if domain in [d.lower() for d in cat_domains]:
                is_static = True
                break
        if is_static:
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
    }


# ── Background scanner ─────────────────────────────────────────────────────

async def _scan_loop() -> None:
    """Background loop: periodically scan for new domains and classify them."""
    # Wait a few seconds on startup for services to stabilize
    await asyncio.sleep(5)
    log.info("Domain enforcer scanner started (interval=%.0fs)", SCAN_INTERVAL)

    seen_domains: Set[str] = set()

    while True:
        try:
            mode = _get_current_mode()

            # Skip scanning in free mode (nothing to block)
            if mode == "free":
                await asyncio.sleep(SCAN_INTERVAL)
                continue

            # Read new domains from flow CSV
            csv_domains = await asyncio.to_thread(_extract_domains_from_csv)
            new_domains = csv_domains - seen_domains
            seen_domains.update(csv_domains)

            if new_domains:
                log.info("Found %d new domains to evaluate", len(new_domains))

            # Classify and enforce each new domain
            for domain in new_domains:
                # Skip domains already in the static CATEGORY_DOMAINS
                is_static = False
                for cat_domains in blocking_service.CATEGORY_DOMAINS.values():
                    if domain in [d.lower() for d in cat_domains]:
                        is_static = True
                        break
                if is_static:
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
                            "Enforced block on %s → %s",
                            domain, result["category"],
                        )
                except Exception as exc:
                    log.error("Classification failed for %s: %s", domain, exc)

                # Small delay between classifications to be nice to APIs
                await asyncio.sleep(0.5)

        except asyncio.CancelledError:
            log.info("Domain enforcer scanner stopped")
            return
        except Exception as exc:
            log.error("Domain enforcer scan error: %s", exc)

        await asyncio.sleep(SCAN_INTERVAL)


def start_scanner() -> None:
    """Start the background domain scanner task."""
    global _enforcer_task
    if _enforcer_task is None or _enforcer_task.done():
        _enforcer_task = asyncio.create_task(_scan_loop())
        log.info("Domain enforcer started")


async def stop_scanner() -> None:
    """Stop the background scanner gracefully."""
    global _enforcer_task
    if _enforcer_task and not _enforcer_task.done():
        _enforcer_task.cancel()
        try:
            await _enforcer_task
        except asyncio.CancelledError:
            pass
        log.info("Domain enforcer stopped")
