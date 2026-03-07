"""
SmartShield Backend — Domain Blocking Service

Blocks / unblocks domains at the network level using iptables.
Supports both manual blocking and automatic mode-based blocking.

Mechanism:
  - Pre-caches domain → IP mappings at startup (avoids DNS in request path)
  - Adds iptables OUTPUT rules to REJECT traffic to those IPs
  - Persists the block-list to a JSON file so it survives restarts
  - Tracks whether each block was manual or auto (mode-based)

Requires passwordless sudo for iptables.
Run:  sudo bash setup_blocking.sh   (one-time setup)
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Set

from utils.logger import get_logger

log = get_logger("blocking_service")

# Persistent storage for blocked domains
_BLOCK_FILE = Path(__file__).resolve().parent.parent / "blocked_domains.json"

# Temporary file for /etc/hosts section updates
_HOSTS_TMP = Path("/tmp/smartshield_hosts_block.txt")
_HOSTS_HELPER = "/usr/local/bin/smartshield-hosts"

# In-memory state
# domain → {ips: [...], reason: str, auto: bool}
_blocked: Dict[str, Dict[str, Any]] = {}

# ── DNS Cache (populated at startup) ──────────────────────────────────────
# domain → [ip1, ip2, ...]
_dns_cache: Dict[str, List[str]] = {}

# ── Well-known domains per category (from ML domain_lookup) ────────────────
CATEGORY_DOMAINS: Dict[str, List[str]] = {
    "ai_tool": [
        "anthropic.com", "chatgpt.com", "claude.ai", "claude.com", "cohere.ai",
        "copy.ai", "deepmind.google", "gemini.google.com", "githubcopilot.com",
        "grok.com", "huggingface.co", "jasper.ai", "kimi.com", "midjourney.com",
        "moonshot.cn", "openai.com", "perplexity.ai", "replicate.com",
        "stability.ai", "x.ai",
    ],
    "writing_assistant": [
        "grammarly.com", "grammarly.io", "hemingwayapp.com", "languagetool.org",
        "overleaf.com", "prowritingaid.com", "quillbot.com", "rytr.me",
        "scribens.com", "sudowrite.com", "wordtune.com", "writesonic.com",
    ],
    "development": [
        "bitbucket.org", "codepen.io", "codesandbox.io", "digitalocean.com",
        "docker.com", "github.com", "githubassets.com", "gitlab.com",
        "heroku.com", "jsfiddle.net", "netlify.com", "npmjs.com", "pypi.org",
        "readthedocs.io", "replit.com", "stackoverflow.com", "vercel.com",
    ],
    "adult": [
        "chaturbate.com", "erome.com", "onlyfans.com", "pornhub.com",
        "pornhub.org", "pornhub.xxx", "redtube.com", "spankbang.com",
        "stripchatgirls.com", "xhamster.com", "xhamster.desi", "xhamster19.com",
        "xhamster44.desi", "xnxx-cdn.com", "xnxx.com", "xvideos.com",
        "youporn.com",
    ],
    "social_media": [
        "facebook.com", "instagram.com", "linkedin.com", "mastodon.social",
        "medium.com", "meta.com", "pinterest.com", "quora.com", "reddit.com",
        "snapchat.com", "threads.net", "tiktok.com", "tumblr.com",
        "twitter.com", "x.com",
    ],
}

# Which categories each mode blocks
MODE_BLOCKED_CATEGORIES: Dict[str, List[str]] = {
    "free": [],
    "exam": ["ai_tool", "writing_assistant", "development"],
    "parental": ["adult", "social_media"],
}


# ── helpers ─────────────────────────────────────────────────────────────────

def is_safe_public_ip(ip: str) -> bool:
    """Return True only if *ip* is a real public address safe to block.

    Rejects loopback (127.x), private (10.x, 172.16-31.x, 192.168.x),
    link-local (169.254.x), reserved, and multicast addresses so we never
    accidentally break localhost / LAN traffic with an iptables rule.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified          # 0.0.0.0
    )


def _resolve_domain(domain: str) -> List[str]:
    """Resolve a domain to its IPv4 addresses.  Uses cache if available."""
    if domain in _dns_cache:
        return _dns_cache[domain]
    ips: Set[str] = set()
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        for _fam, _type, _proto, _canon, sockaddr in results:
            ips.add(sockaddr[0])
    except (socket.gaierror, socket.timeout, OSError):
        pass
    result = sorted(ips)
    _dns_cache[domain] = result
    return result


def _populate_dns_cache() -> None:
    """Pre-resolve ALL category domains at startup.

    Called once at module import time, outside any request handler.
    This avoids the DNS-inside-uvicorn deadlock entirely.
    """
    t0 = time.time()
    all_domains: Set[str] = set()
    for cat_domains in CATEGORY_DOMAINS.values():
        for d in cat_domains:
            all_domains.add(d.lower().strip())

    resolved = 0
    skipped_unsafe = 0
    for domain in sorted(all_domains):
        ips: Set[str] = set()
        try:
            results = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
            for _fam, _type, _proto, _canon, sockaddr in results:
                ips.add(sockaddr[0])
        except (socket.gaierror, socket.timeout, OSError):
            pass
        # Filter out dangerous IPs (loopback, private, link-local, etc.)
        safe = {ip for ip in ips if is_safe_public_ip(ip)}
        unsafe = ips - safe
        if unsafe:
            log.warning("DNS cache: %s resolved to unsafe IPs %s — skipped",
                        domain, sorted(unsafe))
            skipped_unsafe += len(unsafe)
        _dns_cache[domain] = sorted(safe)
        if safe:
            resolved += 1

    elapsed = time.time() - t0
    log.info("DNS cache populated: %d/%d domains resolved in %.2fs  "
             "(%d unsafe IPs filtered)",
             resolved, len(all_domains), elapsed, skipped_unsafe)


def _run_iptables(*args: str) -> bool:
    """Run an iptables command via sudo.  Returns True on success."""
    cmd = ["sudo", "-n", "iptables", "-w", "1", *args]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=3,
        )
        if result.returncode != 0:
            # Rule might already exist or not exist — not fatal
            stderr = result.stderr.strip()
            if "does a matching rule exist" not in stderr and "Bad rule" not in stderr:
                log.warning("iptables stderr: %s", stderr)
            return result.returncode == 0
        return True
    except FileNotFoundError:
        log.error("iptables binary not found")
        return False
    except subprocess.TimeoutExpired:
        log.error("iptables command timed out")
        return False


def _add_block_rules(ips: List[str]) -> int:
    """Add iptables REJECT rules for a list of IPs.  Returns count of rules added."""
    added = 0
    for ip in ips:
        if ":" in ip:
            continue  # skip IPv6 for now (ip6tables is separate)
        if not is_safe_public_ip(ip):
            log.debug("Skipping unsafe IP %s", ip)
            continue
        ok = _run_iptables(
            "-I", "OUTPUT",
            "-d", ip,
            "-j", "REJECT",
            "--reject-with", "icmp-port-unreachable",
        )
        if ok:
            added += 1
    return added


def _remove_block_rules(ips: List[str]) -> int:
    """Remove iptables REJECT rules for a list of IPs.  Returns count removed."""
    removed = 0
    for ip in ips:
        if ":" in ip:
            continue
        # Remove one rule per IP (don't loop — faster)
        ok = _run_iptables(
            "-D", "OUTPUT",
            "-d", ip,
            "-j", "REJECT",
            "--reject-with", "icmp-port-unreachable",
        )
        if ok:
            removed += 1
    return removed


def _ensure_localhost_accept() -> None:
    """Insert a top-priority ACCEPT rule for 127.0.0.0/8 at position 1.

    Call this AFTER all REJECT rules have been inserted so the ACCEPT
    rule stays at the very top of the chain (iptables -I inserts at pos 1).
    """
    _run_iptables(
        "-I", "OUTPUT", "1",
        "-d", "127.0.0.0/8", "-j", "ACCEPT",
    )


# ── /etc/hosts blocking ────────────────────────────────────────────────────

def _sync_hosts_file() -> None:
    """Write all currently blocked domains to /etc/hosts via the helper script.

    Maps each blocked domain (and its www. variant) to 0.0.0.0 so the
    OS-level DNS resolver returns an unreachable address.  This stops
    browsers from connecting regardless of DNS-over-HTTPS or IP rotation.
    """
    domains_to_block: Set[str] = set()
    for domain in _blocked:
        d = domain.lower().strip()
        domains_to_block.add(d)
        if not d.startswith("www."):
            domains_to_block.add("www." + d)

    if not domains_to_block:
        # Nothing to block — clear the section
        try:
            subprocess.run(
                ["sudo", "-n", _HOSTS_HELPER, "clear"],
                capture_output=True, text=True, timeout=5,
            )
        except Exception as exc:
            log.warning("Failed to clear /etc/hosts section: %s", exc)
        return

    # Build hosts entries
    lines = []
    for d in sorted(domains_to_block):
        lines.append(f"0.0.0.0 {d}")

    try:
        _HOSTS_TMP.write_text("\n".join(lines) + "\n")
        result = subprocess.run(
            ["sudo", "-n", _HOSTS_HELPER, "write", str(_HOSTS_TMP)],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            log.warning("/etc/hosts update failed: %s", result.stderr.strip())
        else:
            log.info("/etc/hosts updated with %d entries", len(domains_to_block))
    except FileNotFoundError:
        log.warning("smartshield-hosts helper not found — run: sudo bash setup_blocking.sh")
    except Exception as exc:
        log.warning("Failed to update /etc/hosts: %s", exc)


def _flush_output_chain() -> bool:
    """Flush all rules in the OUTPUT chain."""
    return _run_iptables("-F", "OUTPUT")


def _batch_add_block_rules(ips: List[str]) -> bool:
    """Add iptables REJECT rules for many IPs at once using iptables-restore.

    This is much faster than calling iptables individually for each IP.
    """
    if not ips:
        return True

    # Build iptables-restore input
    # We use --noflush to preserve existing rules and append our new ones
    lines = ["*filter"]
    for ip in ips:
        if ":" in ip:
            continue
        if not is_safe_public_ip(ip):
            log.debug("Batch skip unsafe IP %s", ip)
            continue
        lines.append(f"-I OUTPUT -d {ip} -j REJECT --reject-with icmp-port-unreachable")
    lines.append("COMMIT")
    lines.append("")
    restore_input = "\n".join(lines)

    try:
        result = subprocess.run(
            ["sudo", "-n", "iptables-restore", "--noflush"],
            input=restore_input, capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            log.warning("iptables-restore failed: %s", result.stderr.strip())
            # Fallback to sequential
            log.info("Falling back to sequential iptables calls for %d IPs", len(ips))
            for ip in ips:
                if ":" not in ip:
                    _run_iptables(
                        "-I", "OUTPUT", "-d", ip,
                        "-j", "REJECT", "--reject-with", "icmp-port-unreachable",
                    )
            return False
        return True
    except Exception as exc:
        log.error("iptables-restore error: %s", exc)
        return False


def _reapply_all_rules() -> int:
    """Re-add iptables rules for all currently blocked domains."""
    count = 0
    for domain, info in _blocked.items():
        count += _add_block_rules(info.get("ips", []))
    return count


# ── persistence ─────────────────────────────────────────────────────────────

def _save() -> None:
    """Write current blocked list to disk."""
    try:
        data = {
            domain: {
                "ips": info["ips"],
                "reason": info.get("reason", ""),
                "auto": info.get("auto", False),
            }
            for domain, info in _blocked.items()
        }
        _BLOCK_FILE.write_text(json.dumps(data, indent=2))
    except Exception as exc:
        log.error("Failed to save blocked domains: %s", exc)


def _load() -> None:
    """Load blocked domains from disk and re-apply iptables rules."""
    global _blocked
    if not _BLOCK_FILE.exists():
        return
    try:
        data = json.loads(_BLOCK_FILE.read_text())
        for domain, info in data.items():
            ips = info.get("ips", [])
            reason = info.get("reason", "")
            auto = info.get("auto", False)
            _blocked[domain] = {"ips": ips, "reason": reason, "auto": auto}
            _add_block_rules(ips)
        log.info("Restored %d blocked domains from %s", len(_blocked), _BLOCK_FILE)
    except Exception as exc:
        log.error("Failed to load blocked domains: %s", exc)


# ── public API ──────────────────────────────────────────────────────────────

def block_domain(domain: str, reason: str = "", auto: bool = False) -> Dict[str, Any]:
    """Block a domain.  Resolves IPs and adds iptables rules."""
    domain = domain.lower().strip()
    if not domain:
        return {"status": "error", "message": "Empty domain"}

    if domain in _blocked:
        return {"status": "ok", "message": "Already blocked", "domain": domain}

    ips = _resolve_domain(domain)
    if not ips:
        # Could not resolve — still record it so the UI is consistent
        log.warning("Could not resolve %s — blocking by name only", domain)

    # Also try with www. prefix if the bare domain was given
    if not domain.startswith("www."):
        extra = _resolve_domain("www." + domain)
        ips = sorted(set(ips) | set(extra))

    rules_added = _add_block_rules(ips)
    _blocked[domain] = {"ips": ips, "reason": reason, "auto": auto}
    _save()
    _sync_hosts_file()

    log.info("Blocked %s → %d IPs, %d rules", domain, len(ips), rules_added)
    return {
        "status": "ok",
        "domain": domain,
        "ips_blocked": len(ips),
        "rules_added": rules_added,
    }


def unblock_domain(domain: str) -> Dict[str, Any]:
    """Unblock a domain.  Removes iptables rules."""
    domain = domain.lower().strip()

    info = _blocked.pop(domain, None)
    if info is None:
        return {"status": "ok", "message": "Was not blocked", "domain": domain}

    rules_removed = _remove_block_rules(info.get("ips", []))
    _save()
    _sync_hosts_file()

    log.info("Unblocked %s — %d rules removed", domain, rules_removed)
    return {"status": "ok", "domain": domain, "rules_removed": rules_removed}


def list_blocked() -> List[Dict[str, Any]]:
    """Return the list of currently blocked domains."""
    return [
        {
            "domain": d,
            "ips": info["ips"],
            "reason": info.get("reason", ""),
            "auto": info.get("auto", False),
        }
        for d, info in _blocked.items()
    ]


def is_blocked(domain: str) -> bool:
    """Check if a domain is in the block list."""
    return domain.lower().strip() in _blocked


# ── Mode-based auto-blocking ───────────────────────────────────────────────

def apply_mode(mode: str) -> Dict[str, Any]:
    """
    Apply automatic blocking for a given mode.

    All DNS lookups come from the pre-populated _dns_cache (built at startup),
    so this function does ZERO DNS resolution.  Only iptables calls are made.

    Strategy:
      1. Flush all iptables OUTPUT rules (instant).
      2. Remove auto-blocked domains from state (keep manual blocks).
      3. Look up cached IPs for new category domains.
      4. Batch-add all iptables rules via iptables-restore (instant).
    """
    t0 = time.time()
    mode = mode.lower().strip()
    categories_to_block = MODE_BLOCKED_CATEGORIES.get(mode, [])

    # 1) Flush all iptables OUTPUT rules
    _flush_output_chain()

    # 2) Remove auto-blocked domains from state (keep manual ones)
    auto_domains = [d for d, info in _blocked.items() if info.get("auto", False)]
    unblocked_count = len(auto_domains)
    for domain in auto_domains:
        _blocked.pop(domain, None)
    log.info("Mode '%s': removed %d auto-blocked domains from state", mode, unblocked_count)

    # 3) Collect domains to block using CACHED IPs (no DNS!)
    blocked_count = 0
    for cat in categories_to_block:
        cat_domains = CATEGORY_DOMAINS.get(cat, [])
        for domain in cat_domains:
            domain = domain.lower().strip()
            if domain in _blocked:
                continue  # already manually blocked
            ips = _dns_cache.get(domain, [])
            _blocked[domain] = {
                "ips": ips,
                "reason": f"Auto-blocked ({cat})",
                "auto": True,
            }
            blocked_count += 1

    # 4) Collect ALL IPs (manual + auto) and batch-add via iptables-restore
    all_ips: Set[str] = set()
    for domain, info in _blocked.items():
        for ip in info.get("ips", []):
            if ":" not in ip:
                all_ips.add(ip)

    if all_ips:
        _batch_add_block_rules(sorted(all_ips))

    # 5) Re-insert localhost ACCEPT at position 1 (AFTER all REJECT rules)
    _ensure_localhost_accept()

    _save()
    _sync_hosts_file()
    elapsed = time.time() - t0
    log.info("Mode '%s': blocked %d domains (%d IPs) across %s in %.3fs",
             mode, blocked_count, len(all_ips), categories_to_block, elapsed)

    return {
        "status": "ok",
        "mode": mode,
        "unblocked": unblocked_count,
        "blocked": blocked_count,
        "categories": categories_to_block,
    }


# ── init: populate DNS cache and load persisted blocks on import ────────────
_populate_dns_cache()
_load()
_sync_hosts_file()  # ensure /etc/hosts matches persisted state

# On fresh startup the mode defaults to "free", so auto-blocked domains
# left over from a previous session must be cleared immediately.
_auto_domains = [d for d, info in _blocked.items() if info.get("auto", False)]
if _auto_domains:
    log.info("Startup: clearing %d auto-blocked domains (mode defaults to free)", len(_auto_domains))
    _flush_output_chain()
    for _d in _auto_domains:
        _blocked.pop(_d, None)
    # Re-apply only manual blocks
    _reapply_all_rules()
    _save()
    _sync_hosts_file()

_ensure_localhost_accept()  # safety net on every startup
