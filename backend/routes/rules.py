"""
SmartShield Backend — Rule Routes

POST endpoints for blocking / unblocking domains, IPs, apps, and ports.
"""

from fastapi import APIRouter, HTTPException

from dpi_client import DPIConnectionError
from models.rule_models import (
    AppRule,
    DomainRule,
    IPRule,
    PortRule,
    RuleResponse,
)
from services import rule_service

router = APIRouter(tags=["Rules"])


# ── Block endpoints ─────────────────────────────────────────────────────────

@router.post("/block/domain", response_model=RuleResponse)
async def block_domain(body: DomainRule):
    try:
        result = rule_service.block_domain(body.domain)
        return RuleResponse(status=result.get("status", "ok"))
    except DPIConnectionError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


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


# ── Unblock endpoints ───────────────────────────────────────────────────────

@router.post("/unblock/domain", response_model=RuleResponse)
async def unblock_domain(body: DomainRule):
    try:
        result = rule_service.unblock_domain(body.domain)
        return RuleResponse(status=result.get("status", "ok"))
    except DPIConnectionError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


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
