"""
SmartShield Backend — WebSocket Manager

Manages connected dashboard clients and broadcasts live DPI statistics
to all of them at a configurable interval.
"""

from __future__ import annotations

import asyncio
import json
from typing import List

from fastapi import WebSocket, WebSocketDisconnect

import config
from dpi_client import DPIConnectionError, send_command
from services import mode_service
from utils.logger import get_logger

log = get_logger("websocket_manager")


class WebSocketManager:
    """
    Keeps track of active WebSocket connections and periodically pushes
    DPI engine statistics to every connected client.
    """

    def __init__(self) -> None:
        self._connections: List[WebSocket] = []
        self._task: asyncio.Task | None = None

    # ── Connection lifecycle ────────────────────────────────────────────

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.append(ws)
        log.info("WebSocket client connected  (%d total)", len(self._connections))

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self._connections:
            self._connections.remove(ws)
        log.info("WebSocket client disconnected  (%d total)", len(self._connections))

    # ── Broadcasting ────────────────────────────────────────────────────

    async def broadcast(self, data: dict) -> None:
        """Send *data* to every connected client, dropping dead sockets."""
        dead: List[WebSocket] = []
        message = json.dumps(data)

        for ws in self._connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.disconnect(ws)

    # ── Background stats loop ──────────────────────────────────────────

    async def _stats_loop(self) -> None:
        """Periodically fetch stats from the DPI engine and broadcast."""
        while True:
            try:
                # Run the blocking TCP call in a thread so we don't stall
                # the asyncio event loop.
                raw = await asyncio.to_thread(
                    send_command, {"action": "get_stats"}
                )
                stats = raw.get("stats", {})

                payload = {
                    "blocked_ips": stats.get("blocked_ips", 0),
                    "blocked_apps": stats.get("blocked_apps", 0),
                    "blocked_domains": stats.get("blocked_domains", 0),
                    "blocked_ports": stats.get("blocked_ports", 0),
                    "ip_list": stats.get("ip_list", []),
                    "domain_list": stats.get("domain_list", []),
                    "app_list": stats.get("app_list", []),
                }

                # Include current mode info in broadcast
                try:
                    mode_info = await asyncio.to_thread(mode_service.get_mode)
                    payload["mode"] = mode_info.get("mode", "free")
                    payload["blocked_categories"] = mode_info.get(
                        "blocked_categories", []
                    )
                except Exception:
                    payload["mode"] = "free"
                    payload["blocked_categories"] = []

                if self._connections:
                    await self.broadcast(payload)

            except DPIConnectionError:
                # Engine may not be running yet — silently retry.
                pass
            except asyncio.CancelledError:
                return
            except Exception as exc:
                log.error("Stats loop error: %s", exc)

            await asyncio.sleep(config.WS_STATS_INTERVAL)

    def start_broadcast_loop(self) -> None:
        """Start the background stats broadcaster (call once at startup)."""
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._stats_loop())
            log.info("Stats broadcast loop started (interval=%.1fs)", config.WS_STATS_INTERVAL)

    async def stop_broadcast_loop(self) -> None:
        """Cancel the background loop gracefully."""
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            log.info("Stats broadcast loop stopped")


# Singleton used by the application
manager = WebSocketManager()
