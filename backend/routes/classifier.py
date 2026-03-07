"""
SmartShield Backend — Website Classifier Routes

Exposes the unknown-domain LLM classifier via REST endpoints.
Includes a classify-and-enforce endpoint that also triggers blocking.
"""

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services import website_classifier
from services import domain_enforcer
from utils.logger import get_logger

log = get_logger("routes.classifier")

router = APIRouter(prefix="/classifier", tags=["Classifier"])


# ── Request / response models ──────────────────────────────────────────────

class ClassifyRequest(BaseModel):
    domain: str


class ClassifyResponse(BaseModel):
    domain: str
    category: str
    source: str
    cached: bool


class EnforceResponse(BaseModel):
    domain: str
    category: str
    confidence: str
    blocked: bool
    enforced: bool


# ── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/classify", response_model=ClassifyResponse)
async def classify_domain(body: ClassifyRequest):
    """Classify an unknown domain using cached result or Gemini LLM."""
    domain = body.domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain must not be empty")

    try:
        result = await website_classifier.classify_domain_async(domain)
        return ClassifyResponse(**result)
    except Exception as exc:
        log.error("Classification failed for %s: %s", domain, exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/enforce", response_model=EnforceResponse)
async def classify_and_enforce(body: ClassifyRequest):
    """Classify a domain AND enforce blocking if current mode requires it.

    This is the main endpoint for on-demand domain evaluation.
    It calls ML → LLM fallback → blocks via iptables + /etc/hosts if needed.
    """
    domain = body.domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain must not be empty")

    try:
        import asyncio
        result = await asyncio.to_thread(
            domain_enforcer.classify_and_enforce, domain
        )
        return EnforceResponse(**result)
    except Exception as exc:
        log.error("Enforce failed for %s: %s", domain, exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/lookup/{domain}")
async def lookup_domain(domain: str):
    """Look up a domain in the classification cache (does NOT trigger LLM)."""
    cached = website_classifier.lookup_cached(domain.strip().lower())
    if cached:
        return {"status": "found", **cached}
    return {"status": "not_found", "domain": domain}


@router.get("/cache")
async def list_cache():
    """Return all cached domain classifications."""
    entries = website_classifier.get_all_cached()
    return {"status": "ok", "count": len(entries), "entries": entries}


@router.get("/registry")
async def list_registry():
    """Return all dynamically classified domains from the enforcer."""
    with domain_enforcer._registry_lock:
        entries = list(domain_enforcer._domain_registry.values())
    return {"status": "ok", "count": len(entries), "entries": entries}
