"""
SmartShield Backend — Stats Service

Fetches real-time statistics from the DPI engine.
"""

from typing import Any, Dict

from dpi_client import send_command
from utils.logger import get_logger

log = get_logger("stats_service")


def get_stats() -> Dict[str, Any]:
    """
    Query the DPI engine for current blocking/connection statistics.

    Returns the raw dict from the engine, which typically contains::

        {
            "status": "ok",
            "stats": {
                "blocked_ips": N,
                "blocked_apps": N,
                "blocked_domains": N,
                "blocked_ports": N,
                "ip_list": [...],
                "domain_list": [...],
                "app_list": [...]
            }
        }
    """
    log.info("Fetching stats from DPI engine")
    return send_command({"action": "get_stats"})
