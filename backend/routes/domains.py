"""
SmartShield Backend — Domain convenience routes

Separate router kept for future expansion (e.g. wildcard helpers,
domain-specific analytics, DNS-level stats).
"""

from fastapi import APIRouter, HTTPException

from dpi_client import DPIConnectionError
from models.rule_models import DomainRule, RuleResponse
from services import rule_service, stats_service

router = APIRouter(tags=["Domains"])


@router.get("/domains/blocked")
async def list_blocked_domains():
    """Return all currently blocked domains (exact + wildcard)."""
    try:
        raw = stats_service.get_stats()
        stats = raw.get("stats", {})
        return {
            "status": "ok",
            "domains": stats.get("domain_list", []),
            "count": stats.get("blocked_domains", 0),
        }
    except DPIConnectionError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
