"""
SmartShield Backend — Rule Service

Thin service layer that translates high-level rule operations into DPI
engine commands via ``dpi_client``.
"""

from typing import Dict, Any

from dpi_client import send_command
from utils.logger import get_logger

log = get_logger("rule_service")


# ── Block commands ──────────────────────────────────────────────────────────

def block_domain(domain: str) -> Dict[str, Any]:
    log.info("Blocking domain: %s", domain)
    return send_command({"action": "block_domain", "domain": domain})


def block_ip(ip: str) -> Dict[str, Any]:
    log.info("Blocking IP: %s", ip)
    return send_command({"action": "block_ip", "ip": ip})


def block_app(app: str) -> Dict[str, Any]:
    log.info("Blocking app: %s", app)
    return send_command({"action": "block_app", "app": app})


def block_port(port: int) -> Dict[str, Any]:
    log.info("Blocking port: %d", port)
    return send_command({"action": "block_port", "port": port})


# ── Unblock commands ────────────────────────────────────────────────────────

def unblock_domain(domain: str) -> Dict[str, Any]:
    log.info("Unblocking domain: %s", domain)
    return send_command({"action": "unblock_domain", "domain": domain})


def unblock_ip(ip: str) -> Dict[str, Any]:
    log.info("Unblocking IP: %s", ip)
    return send_command({"action": "unblock_ip", "ip": ip})


def unblock_app(app: str) -> Dict[str, Any]:
    log.info("Unblocking app: %s", app)
    return send_command({"action": "unblock_app", "app": app})


def unblock_port(port: int) -> Dict[str, Any]:
    log.info("Unblocking port: %d", port)
    return send_command({"action": "unblock_port", "port": port})
