"""
SmartShield Backend — Configuration
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# DPI Engine connection
# ---------------------------------------------------------------------------
DPI_HOST: str = os.getenv("DPI_HOST", "127.0.0.1")
DPI_PORT: int = int(os.getenv("DPI_PORT", "9091"))
DPI_TIMEOUT: float = float(os.getenv("DPI_TIMEOUT", "5.0"))   # seconds

# ---------------------------------------------------------------------------
# Backend server
# ---------------------------------------------------------------------------
API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
API_PORT: int = int(os.getenv("API_PORT", "8000"))

# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------
WS_STATS_INTERVAL: float = float(os.getenv("WS_STATS_INTERVAL", "1.0"))  # seconds

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
