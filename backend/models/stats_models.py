"""
SmartShield Backend — Statistics Pydantic models
"""

from __future__ import annotations

from typing import Any, Dict, List

from pydantic import BaseModel, Field


class StatsResponse(BaseModel):
    """Top-level statistics returned by ``GET /stats``."""
    status: str = "ok"
    blocked_ips: int = 0
    blocked_apps: int = 0
    blocked_domains: int = 0
    blocked_ports: int = 0
    ip_list: List[str] = Field(default_factory=list)
    domain_list: List[str] = Field(default_factory=list)
    app_list: List[str] = Field(default_factory=list)


class AppStats(BaseModel):
    """Per-application statistics."""
    app: str
    count: int = 0


class DomainStats(BaseModel):
    """Per-domain statistics."""
    domain: str
    count: int = 0
