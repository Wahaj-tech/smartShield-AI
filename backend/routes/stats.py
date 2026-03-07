"""
SmartShield Backend — Stats Routes

GET endpoints for retrieving DPI engine statistics.
"""

from fastapi import APIRouter, HTTPException

from dpi_client import DPIConnectionError
from services import stats_service, mode_service

router = APIRouter(tags=["Statistics"])


@router.get("/stats")
async def get_stats():
    """Return current DPI engine blocking statistics + active mode."""
    try:
        raw = stats_service.get_stats()
        stats = raw.get("stats", {})

        result = {
            "status": "ok",
            "blocked_ips": stats.get("blocked_ips", 0),
            "blocked_apps": stats.get("blocked_apps", 0),
            "blocked_domains": stats.get("blocked_domains", 0),
            "blocked_ports": stats.get("blocked_ports", 0),
            "ip_list": stats.get("ip_list", []),
            "domain_list": stats.get("domain_list", []),
            "app_list": stats.get("app_list", []),
        }

        # Include current mode
        try:
            mode_info = mode_service.get_mode()
            result["mode"] = mode_info.get("mode", "free")
            result["blocked_categories"] = mode_info.get(
                "blocked_categories", []
            )
        except Exception:
            result["mode"] = "free"
            result["blocked_categories"] = []

        return result
    except DPIConnectionError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/apps")
async def get_blocked_apps():
    """Return the list of currently blocked applications."""
    try:
        raw = stats_service.get_stats()
        stats = raw.get("stats", {})
        return {
            "status": "ok",
            "apps": stats.get("app_list", []),
        }
    except DPIConnectionError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/domains")
async def get_blocked_domains():
    """Return the list of currently blocked domains."""
    try:
        raw = stats_service.get_stats()
        stats = raw.get("stats", {})
        return {
            "status": "ok",
            "domains": stats.get("domain_list", []),
        }
    except DPIConnectionError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
