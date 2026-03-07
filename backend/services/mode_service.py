"""
SmartShield Backend — Mode Service

Manages the active filtering mode by communicating with the ML server.
Modes:
  - free:     all sites allowed
  - exam:     ai_tool, writing_assistant, development blocked
  - parental: adult, social_media blocked
"""

from typing import Any, Dict

import requests

from utils.logger import get_logger

log = get_logger("mode_service")

ML_SERVER_URL = "http://localhost:5000"


def get_mode() -> Dict[str, Any]:
    """Fetch the current mode from the ML server."""
    log.info("Fetching current mode")
    resp = requests.get(f"{ML_SERVER_URL}/mode", timeout=5)
    resp.raise_for_status()
    return resp.json()


def set_mode(mode: str) -> Dict[str, Any]:
    """Set the active mode on the ML server."""
    log.info("Setting mode to: %s", mode)
    resp = requests.post(f"{ML_SERVER_URL}/mode", json={"mode": mode}, timeout=5)
    resp.raise_for_status()
    return resp.json()
