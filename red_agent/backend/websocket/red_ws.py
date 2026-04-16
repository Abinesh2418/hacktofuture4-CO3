"""Live log + tool-call WebSocket stream for the Red dashboard."""

from __future__ import annotations

import asyncio
import uuid
from typing import Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from red_agent.backend.services import red_service

router = APIRouter()


class RedConnectionManager:
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


manager = RedConnectionManager()


@router.websocket("/ws/red")
async def red_log_stream(ws: WebSocket) -> None:
    """Streams `{type, payload}` envelopes to the Red dashboard.

    Envelope types:
      - `log`            : a LogEntry
      - `tool_call`      : a ToolCall snapshot
      - `chat_response`  : an agent chat message
      - `mission_phase`  : current mission phase update
      - `heartbeat`      : keepalive ping

    Also accepts incoming messages for mission control:
      - `{type: "mission_control", payload: {action, mission_id}}`
    """
    await manager.connect(ws)
    try:
        # Wipe backend history so reload always starts clean
        red_service.clear_history()
        # Signal the frontend to clear all existing state (fresh session)
        await ws.send_json({"type": "session_start", "payload": {"session_id": str(uuid.uuid4())}})

        while True:
            try:
                data = await asyncio.wait_for(ws.receive_json(), timeout=15)
                # Handle incoming mission control commands
                if data.get("type") == "mission_control":
                    action = data.get("payload", {}).get("action")
                    mid = data.get("payload", {}).get("mission_id")
                    if action and mid:
                        if action == "pause":
                            await red_service.pause_mission(mid)
                        elif action == "resume":
                            await red_service.resume_mission(mid)
                        elif action == "abort":
                            await red_service.abort_mission(mid)
            except asyncio.TimeoutError:
                # No message received in 15s — send heartbeat
                await ws.send_json({"type": "heartbeat", "payload": {}})
    except WebSocketDisconnect:
        await manager.disconnect(ws)
    except Exception:
        await manager.disconnect(ws)
        raise
