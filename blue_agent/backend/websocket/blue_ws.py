"""Live log + tool-call WebSocket stream for the Blue dashboard."""

from __future__ import annotations

import asyncio
import uuid
from typing import Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from blue_agent.backend.services import blue_service

router = APIRouter()


class BlueConnectionManager:
    def __init__(self) -> None:
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)

    async def broadcast(self, payload: dict) -> None:
        async with self._lock:
            stale: list[WebSocket] = []
            for ws in self._connections:
                try:
                    await ws.send_json(payload)
                except Exception:
                    stale.append(ws)
            for ws in stale:
                self._connections.discard(ws)


manager = BlueConnectionManager()

# Register the broadcast callback so service layer can push events in real-time
blue_service.set_broadcast_callback(manager.broadcast)


@router.websocket("/ws/blue")
async def blue_log_stream(ws: WebSocket) -> None:
    """Streams {type, payload} envelopes to the Blue dashboard in real-time."""
    await manager.connect(ws)
    try:
        # Wipe backend history so reload always starts clean
        blue_service.clear_history()
        # Signal the frontend to clear all existing state (fresh session)
        await ws.send_json({"type": "session_start", "payload": {"session_id": str(uuid.uuid4())}})

        # Periodic status updates
        tick = 0
        while True:
            await asyncio.sleep(5)
            tick += 1

            status = await blue_service.get_agent_status()
            await ws.send_json({"type": "agent_status", "payload": status.model_dump(mode="json")})

            if tick % 3 == 0:
                scan_stats = blue_service.get_ssh_scan_stats()
                await ws.send_json({"type": "scan_stats", "payload": scan_stats})
                await ws.send_json({"type": "heartbeat", "payload": {}})

    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        await manager.disconnect(ws)
