"""Live log + tool-call WebSocket stream for the Red dashboard."""

from __future__ import annotations

import asyncio
from typing import Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from red_agent.backend.services import red_service

router = APIRouter()


class RedConnectionManager:
    def __init__(self) -> None:
        self._connections: Set[WebSocket] = set()
        # NOTE: deliberately NOT using asyncio.Lock — it binds to whatever loop
        # first awaits it, which breaks when CrewAI worker threads try to
        # broadcast from their own temp loops. connect/disconnect happen on
        # the main loop; broadcast iterates a snapshot so the set doesn't
        # need a lock for readers.
        self._main_loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Called once at startup so background threads can schedule broadcasts
        on the main uvicorn loop."""
        self._main_loop = loop

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws)

    async def broadcast(self, payload: dict) -> None:
        stale: list[WebSocket] = []
        for ws in list(self._connections):
            try:
                await ws.send_json(payload)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self._connections.discard(ws)

    def broadcast_threadsafe(self, payload: dict) -> None:
        """Broadcast from any thread — schedules on the main loop if available,
        otherwise falls back to a temporary loop."""
        if self._main_loop and self._main_loop.is_running():
            asyncio.run_coroutine_threadsafe(self.broadcast(payload), self._main_loop)
        else:
            try:
                asyncio.run(self.broadcast(payload))
            except RuntimeError:
                pass


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
        # Replay recent state on connect so the UI can hydrate immediately.
        for call in await red_service.recent_tool_calls(limit=20):
            await ws.send_json({"type": "tool_call", "payload": call.model_dump(mode="json")})
        for entry in await red_service.recent_logs(limit=50):
            await ws.send_json({"type": "log", "payload": entry.model_dump(mode="json")})
        # Replay the deterministic auto-pwn lane.
        from red_agent.backend.services.auto_pwn import recent_steps
        for step in recent_steps(limit=50):
            await ws.send_json({"type": "auto_pwn_step", "payload": step.model_dump(mode="json")})

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
