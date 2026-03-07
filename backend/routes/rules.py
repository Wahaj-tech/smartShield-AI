"""
SmartShield Backend — Rule Routes

POST endpoints for blocking / unblocking domains, IPs, apps, and ports.
Domain blocking uses iptables (works without DPI engine).
Other rules forward to the DPI engine via TCP.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from dpi_client import DPIConnectionError
from models.rule_models import (
    AppRule,
    DomainRule,
    IPRule,
    PortRule,
    RuleResponse,
)
from services import rule_service
from services import blocking_service

router = APIRouter(tags=["Rules"])


# ── Domain block request with optional reason ──────────────────────────────

class DomainBlockRequest(BaseModel):
    domain: str
    reason: str = Field(default="", examples=["Manually blocked"])


# ── Domain block / unblock  (iptables-based — always works) ────────────────

@router.post("/block/domain", response_model=RuleResponse)
async def block_domain(body: DomainBlockRequest):
    result = blocking_service.block_domain(body.domain, body.reason)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("message"))
    # Also try to tell the DPI engine (best-effort, ignore failure)
    try:
        rule_service.block_domain(body.domain)
    except Exception:
        pass
    return RuleResponse(status="ok")


@router.post("/unblock/domain", response_model=RuleResponse)
async def unblock_domain(body: DomainRule):
    result = blocking_service.unblock_domain(body.domain)
    try:
        rule_service.unblock_domain(body.domain)
    except Exception:
        pass
    return RuleResponse(status="ok")


@router.get("/blocked/domains")
async def get_blocked_domains():
    return {"status": "ok", "domains": blocking_service.list_blocked()}


@router.post("/block/ip", response_model=RuleResponse)
async def block_ip(body: IPRule):
    try:
        result = rule_service.block_ip(body.ip)
        return RuleResponse(status=result.get("status", "ok"))
    except DPIConnectionError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/block/app", response_model=RuleResponse)
async def block_app(body: AppRule):
    try:
        result = rule_service.block_app(body.app)
        return RuleResponse(status=result.get("status", "ok"))
    except DPIConnectionError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/block/port", response_model=RuleResponse)
async def block_port(body: PortRule):
    try:
        result = rule_service.block_port(body.port)
        return RuleResponse(status=result.get("status", "ok"))
    except DPIConnectionError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Unblock endpoints (IP, app, port — DPI engine) ─────────────────────────


@router.post("/unblock/ip", response_model=RuleResponse)
async def unblock_ip(body: IPRule):
    try:
        result = rule_service.unblock_ip(body.ip)
        return RuleResponse(status=result.get("status", "ok"))
    except DPIConnectionError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/unblock/app", response_model=RuleResponse)
async def unblock_app(body: AppRule):
    try:
        result = rule_service.unblock_app(body.app)
        return RuleResponse(status=result.get("status", "ok"))
    except DPIConnectionError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/unblock/port", response_model=RuleResponse)
async def unblock_port(body: PortRule):
    try:
        result = rule_service.unblock_port(body.port)
        return RuleResponse(status=result.get("status", "ok"))
    except DPIConnectionError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
