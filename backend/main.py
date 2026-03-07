"""
SmartShield Backend — FastAPI Application Entry Point

Run with:
    cd backend/
    uvicorn main:app --reload
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from routes import rules, stats, domains, mode
from websocket_manager import manager as ws_manager
from utils.logger import get_logger

log = get_logger("main")


# ── Lifespan (startup / shutdown) ───────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("SmartShield backend starting up")
    ws_manager.start_broadcast_loop()
    yield
    log.info("SmartShield backend shutting down")
    await ws_manager.stop_broadcast_loop()


# ── App creation ────────────────────────────────────────────────────────────

app = FastAPI(
    title="SmartShield DPI Backend",
    description="REST + WebSocket control plane for the SmartShield DPI engine",
    version="1.0.0",
    lifespan=lifespan,
)

# Allow dashboard (running on any origin during development) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Route registration ─────────────────────────────────────────────────────

app.include_router(rules.router)
app.include_router(stats.router)
app.include_router(domains.router)
app.include_router(mode.router)


# ── WebSocket endpoint ─────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            # Keep the connection alive; we don't expect inbound messages
            # but we must await recv so FastAPI detects disconnections.
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)


# ── Health check ────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok"}
