"""
SmartShield Backend — Mode Service

Manages the active filtering mode by communicating with the ML server
and triggering automatic domain blocking via iptables.

Modes:
  - free:     all sites allowed  (auto-unblocks everything)
  - exam:     ai_tool, writing_assistant, development blocked
  - parental: adult, social_media blocked
"""

from typing import Any, Dict

import requests

from services import blocking_service
from utils.logger import get_logger

log = get_logger("mode_service")

ML_SERVER_URL = "http://localhost:8001"


def get_mode() -> Dict[str, Any]:
    """Fetch the current mode from the ML server."""
    log.info("Fetching current mode")
    resp = requests.get(f"{ML_SERVER_URL}/mode", timeout=5)
    resp.raise_for_status()
    return resp.json()


def set_mode(mode: str) -> Dict[str, Any]:
    """Set the active mode on the ML server and apply auto-blocking."""
    log.info("Setting mode to: %s", mode)

    # 1) Tell the ML server
    resp = requests.post(f"{ML_SERVER_URL}/mode", json={"mode": mode}, timeout=5)
    resp.raise_for_status()
    ml_result = resp.json()

    if ml_result.get("status") == "error":
        return ml_result

    # 2) Apply iptables auto-blocking for this mode
    block_result = blocking_service.apply_mode(mode)
    log.info("Auto-blocking result: %s", block_result)

    # 3) Return combined info
    return {
        **ml_result,
        "auto_blocked": block_result.get("blocked", 0),
        "auto_unblocked": block_result.get("unblocked", 0),
    }
