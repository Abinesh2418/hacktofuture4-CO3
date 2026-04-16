"""Red Agent Backend — single agent + proactive copilot.

Two parallel LLM streams:
  1. Agent LLM  — runs tools on Kali, writes to shared memory
  2. Copilot LLM — reads memory, proactively narrates to user, answers questions

Endpoints:
  POST /chat              — user messages (copilot answers / starts missions)
  POST /mission/start     — start a pentest
  POST /mission/clear     — abort + clear all state
  GET  /mission/status    — current mission state
  GET  /mission/report    — structured report
  GET  /health            — liveness
  WS   /ws/red            — live event stream
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

import httpx as _httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from red_agent.agent import (
    RedTeamAgent, AgentEvent, AgentResult,
    AgentMemory, ToolMemoryEntry,
    AZURE_URL, AZURE_API_KEY,
)

logger = logging.getLogger(__name__)

app = FastAPI(title="Red Agent API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ══════════════════════════════════════════════════════════════════════
# State
# ══════════════════════════════════════════════════════════════════════

class MissionState:
    def __init__(self) -> None:
        self.agent: RedTeamAgent | None = None
        self.task: asyncio.Task | None = None
        self.copilot_task: asyncio.Task | None = None
        self.result: AgentResult | None = None
        self.mission_id: str | None = None
        self.phase: str = "IDLE"
        self.target: str = ""

    def clear(self) -> None:
        for t in (self.task, self.copilot_task):
            if t and not t.done():
                t.cancel()
        if self.agent:
            self.agent.reset()
        self.agent = None
        self.task = None
        self.copilot_task = None
        self.result = None
        self.mission_id = None
        self.phase = "IDLE"
        self.target = ""


state = MissionState()


# ══════════════════════════════════════════════════════════════════════
# WebSocket Manager
# ══════════════════════════════════════════════════════════════════════

class WSManager:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
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
            stale = []
            for ws in self._connections:
                try:
                    await ws.send_json(payload)
                except Exception:
                    stale.append(ws)
            for ws in stale:
                self._connections.discard(ws)


ws_manager = WSManager()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _broadcast_chat(content: str, role: str = "agent") -> None:
    """Send a chat message to all connected frontends."""
    await ws_manager.broadcast({
        "type": "chat_response",
        "payload": {
            "id": str(uuid.uuid4()),
            "role": role,
            "content": content,
            "timestamp": _now(),
            "tool_calls": [],
        },
    })


# ══════════════════════════════════════════════════════════════════════
# Agent event → WebSocket bridge (raw tool status)
# ══════════════════════════════════════════════════════════════════════

async def _on_agent_event(event: AgentEvent) -> None:
    """Forward tool status to the activity panel. Chat comes from copilot."""

    if event.type == "tool_start":
        tool_name = event.data.get("tool", "")
        phase = event.data.get("phase", "scan")
        category = "exploit" if phase == "EXPLOIT" else "scan"
        await ws_manager.broadcast({
            "type": "tool_call",
            "payload": {
                "id": f"tc-{tool_name}-{uuid.uuid4().hex[:6]}",
                "name": tool_name,
                "category": category,
                "status": "RUNNING",
                "params": event.data.get("args", {}),
                "result": None,
                "started_at": event.timestamp,
                "finished_at": None,
            },
        })

    elif event.type == "tool_done":
        tool_name = event.data.get("tool", "")
        ok = event.data.get("ok", False)
        phase = event.data.get("phase", "scan")
        category = "exploit" if phase == "EXPLOIT" else "scan"
        await ws_manager.broadcast({
            "type": "tool_call",
            "payload": {
                "id": f"tc-{tool_name}-done-{uuid.uuid4().hex[:4]}",
                "name": tool_name,
                "category": category,
                "status": "DONE" if ok else "FAILED",
                "params": {},
                "result": {"findings_count": event.data.get("findings_count", 0)},
                "started_at": event.timestamp,
                "finished_at": _now(),
            },
        })

    elif event.type == "phase":
        phase = event.data.get("phase", "IDLE")
        state.phase = phase
        await ws_manager.broadcast({
            "type": "mission_phase",
            "payload": {"mission_id": state.mission_id or "", "phase": phase},
        })

    elif event.type == "error":
        await ws_manager.broadcast({
            "type": "log",
            "payload": {
                "timestamp": event.timestamp,
                "level": "ERROR",
                "message": event.data.get("error", "Unknown error"),
                "tool_id": None,
            },
        })


# ══════════════════════════════════════════════════════════════════════
# Copilot LLM — proactive narrator + question answerer
# ══════════════════════════════════════════════════════════════════════

COPILOT_SYSTEM = """You are a penetration testing copilot providing live commentary on an
ongoing pentest. You see the agent's memory — every tool it ran and the results.

Your job:
1. When given new tool results, provide a SHORT insightful commentary (2-3 sentences max):
   - What was found and why it matters
   - What the agent will likely do next
   - Flag anything critical (credentials, SQLi confirmed, etc.)
2. When the user asks a question, answer from memory — concise and specific.

Style: brief, technical, no filler. Use markdown for emphasis on critical findings.
Don't repeat raw tool output — interpret it. Don't say "the agent ran nmap" — say what nmap found.
"""


async def _copilot_llm(prompt: str, max_tokens: int = 512) -> str:
    """Single copilot LLM call."""
    try:
        async with _httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                AZURE_URL,
                headers={"api-key": AZURE_API_KEY, "Content-Type": "application/json"},
                json={
                    "model": "gpt-4o",
                    "messages": [
                        {"role": "system", "content": COPILOT_SYSTEM},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": max_tokens,
                    "temperature": 0.3,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "")
    except Exception as exc:
        logger.warning("Copilot LLM error: %s", exc)
    return ""


async def _copilot_loop(agent: RedTeamAgent) -> None:
    """Background task: watches agent memory, proactively narrates to the user.

    Runs alongside the agent. Every time new tool results appear in memory,
    asks the copilot LLM for a brief commentary and broadcasts it to the frontend.
    """
    seen_count = 0

    while True:
        await asyncio.sleep(2)

        # Check if agent is still alive
        if state.phase in ("IDLE",) or state.agent is not agent:
            return

        memory = agent.memory
        current_count = len(memory.entries)

        if current_count > seen_count:
            # New tool results appeared — generate commentary
            new_entries = memory.entries[seen_count:]
            seen_count = current_count

            # Build context for copilot
            new_summaries = "\n".join(f"- {e.summary()}" for e in new_entries)
            full_memory = memory.snapshot()

            prompt = (
                f"Phase: {state.phase}\n"
                f"Target: {state.target}\n\n"
                f"New results just in:\n{new_summaries}\n\n"
                f"Full memory:\n{full_memory}\n\n"
                f"Provide a brief live commentary on the new results."
            )

            commentary = await _copilot_llm(prompt)
            if commentary:
                await _broadcast_chat(f"🔍 {commentary}")

        # Check if mission completed
        if state.phase in ("DONE", "FAILED"):
            # Generate final summary
            final_prompt = (
                f"Mission {state.phase} against {state.target}.\n\n"
                f"Full memory:\n{memory.snapshot()}\n\n"
                f"Provide a final 3-4 sentence executive summary of the pentest results."
            )
            final = await _copilot_llm(final_prompt, max_tokens=300)
            if final:
                await _broadcast_chat(f"📋 **Executive Summary**\n\n{final}")
            return


# ══════════════════════════════════════════════════════════════════════
# Mission runner
# ══════════════════════════════════════════════════════════════════════

async def _run_mission(target: str) -> None:
    state.mission_id = str(uuid.uuid4())[:8]
    state.target = target
    state.phase = "RECON"
    state.result = None

    agent = RedTeamAgent(target=target, on_event=_on_agent_event)
    state.agent = agent

    # Start copilot in parallel
    state.copilot_task = asyncio.create_task(_copilot_loop(agent))

    try:
        result = await agent.run()
        state.result = result
        state.phase = "DONE"

        await ws_manager.broadcast({
            "type": "mission_phase",
            "payload": {"mission_id": state.mission_id, "phase": "DONE"},
        })

    except asyncio.CancelledError:
        state.phase = "IDLE"
    except Exception as exc:
        state.phase = "FAILED"
        logger.exception("Mission failed")
        await _broadcast_chat(f"**Mission failed:** {exc}")


# ══════════════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════════════

class ChatRequest(BaseModel):
    message: str
    target: str | None = None


class MissionStartRequest(BaseModel):
    target: str


@app.post("/chat")
async def chat(req: ChatRequest):
    import re
    text = req.message.strip()
    target = req.target or ""

    # Detect target in message
    match = re.search(r"(?:attack|scan|pentest|hack|target)\s+(https?://\S+|\d+\.\d+\.\d+\.\d+\S*)", text, re.IGNORECASE)
    if match:
        target = match.group(1).rstrip("`'\"\n\r\t ")

    # Start a new mission
    if target and state.phase in ("IDLE", "DONE", "FAILED"):
        state.clear()
        state.task = asyncio.create_task(_run_mission(target))
        return {
            "id": str(uuid.uuid4()),
            "role": "agent",
            "content": f"Mission started against **{target}**. Watch the dashboard for live updates.",
            "timestamp": _now(),
            "tool_calls": [],
        }

    # Target but mission running
    if target and state.phase not in ("IDLE", "DONE", "FAILED"):
        return {
            "id": str(uuid.uuid4()),
            "role": "agent",
            "content": f"Mission already running (phase: {state.phase}). Hit **CLEAR ALL** first.",
            "timestamp": _now(),
            "tool_calls": [],
        }

    # Agent exists — use copilot to answer from memory
    if state.agent and state.phase != "IDLE":
        memory = state.agent.memory
        result_context = ""
        if state.result:
            r = state.result
            result_context = (
                f"\n\nFinal Result: risk={r.risk_score}/10, "
                f"vulns={len(r.vulnerabilities)}, creds={len(r.credentials_found)}, "
                f"dbms={r.dbms}, duration={r.duration_seconds}s\n"
                f"Vulnerabilities: {json.dumps(r.vulnerabilities, default=str)}\n"
                f"Credentials: {json.dumps(r.credentials_found, default=str)}"
            )

        prompt = (
            f"Phase: {state.phase}\n"
            f"Target: {state.target}\n\n"
            f"Memory:\n{memory.snapshot()}\n"
            f"{result_context}\n\n"
            f"User question: {text}"
        )

        answer = await _copilot_llm(prompt, max_tokens=1024)
        return {
            "id": str(uuid.uuid4()),
            "role": "agent",
            "content": answer or "Still processing — no findings to report yet.",
            "timestamp": _now(),
            "tool_calls": [],
        }

    # No mission
    return {
        "id": str(uuid.uuid4()),
        "role": "agent",
        "content": (
            "I'm Red Arsenal — an autonomous penetration testing agent.\n\n"
            "Type a target URL to start a pentest, e.g.:\n"
            "`attack http://172.25.8.172:5000`"
        ),
        "timestamp": _now(),
        "tool_calls": [],
    }


@app.post("/mission/start")
async def start_mission(req: MissionStartRequest):
    if state.phase not in ("IDLE", "DONE", "FAILED"):
        return {"error": f"Mission already running (phase: {state.phase})"}
    state.clear()
    state.task = asyncio.create_task(_run_mission(req.target))
    return {"mission_id": state.mission_id, "target": req.target, "status": "started"}


@app.post("/mission/clear")
async def clear_mission():
    state.clear()
    await ws_manager.broadcast({
        "type": "mission_phase",
        "payload": {"mission_id": "", "phase": "IDLE"},
    })
    return {"status": "cleared"}


@app.get("/mission/status")
async def mission_status():
    return {
        "mission_id": state.mission_id,
        "phase": state.phase,
        "target": state.target,
        "has_report": state.result is not None,
    }


@app.get("/mission/report")
async def mission_report():
    if not state.result:
        return {"error": "No report available"}
    return state.result.to_dict()


@app.get("/health")
async def health():
    return {"status": "ok", "agent": "red", "version": "2.0.0"}


# ══════════════════════════════════════════════════════════════════════
# WebSocket
# ══════════════════════════════════════════════════════════════════════

@app.websocket("/ws/red")
async def ws_red(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        await ws.send_json({
            "type": "mission_phase",
            "payload": {"mission_id": state.mission_id or "", "phase": state.phase},
        })
        while True:
            try:
                data = await asyncio.wait_for(ws.receive_json(), timeout=30)
                if data.get("type") == "mission_control":
                    action = data.get("payload", {}).get("action")
                    if action == "clear":
                        state.clear()
                        await ws_manager.broadcast({
                            "type": "mission_phase",
                            "payload": {"mission_id": "", "phase": "IDLE"},
                        })
            except asyncio.TimeoutError:
                await ws.send_json({"type": "heartbeat", "payload": {}})
    except WebSocketDisconnect:
        await ws_manager.disconnect(ws)
    except Exception:
        await ws_manager.disconnect(ws)
