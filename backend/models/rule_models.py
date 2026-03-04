"""
SmartShield Backend — Rule Pydantic models
"""

from pydantic import BaseModel, Field


class DomainRule(BaseModel):
    """Payload for blocking / unblocking a domain."""
    domain: str = Field(..., min_length=1, examples=["youtube.com"])


class IPRule(BaseModel):
    """Payload for blocking / unblocking an IP address."""
    ip: str = Field(..., min_length=7, examples=["1.2.3.4"])


class PortRule(BaseModel):
    """Payload for blocking / unblocking a destination port."""
    port: int = Field(..., ge=1, le=65535, examples=[8080])


class AppRule(BaseModel):
    """Payload for blocking / unblocking an application type."""
    app: str = Field(..., min_length=1, examples=["YOUTUBE"])


class RuleResponse(BaseModel):
    """Standard response returned after a rule mutation."""
    status: str = Field(..., examples=["ok"])
    message: str | None = None
