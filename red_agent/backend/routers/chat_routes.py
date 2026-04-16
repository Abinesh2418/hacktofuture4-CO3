"""Chat endpoint — all LLM calls are synchronous (NVIDIA Llama 70B is fast ~3s).

No background tasks — the endpoint awaits the LLM directly and returns the
response. Missions are launched as async tasks from within the endpoint.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

from red_agent.backend.services import llm_client

router = APIRouter(tags=["chat"])
_logger = logging.getLogger(__name__)

_conversation: list[dict[str, str]] = []
_MAX_HISTORY = 20
_active_mission_id: str | None = None
_last_known_target: str | None = None

AGENT_SYSTEM_PROMPT = """You are RED ARSENAL, an autonomous penetration testing AI agent with a crew of 3 specialist agents:

1. Recon Specialist — discovers attack surface using nmap, httpx, gobuster, nuclei, katana
2. Security Analyst — analyzes findings, assesses risk, plans attack strategy
3. Exploit Specialist — exploits vulnerabilities using nuclei exploits, fuzzing, vuln scans

All tools run on a remote Kali Linux VM via MCP. You operate in a controlled lab/CTF/hackathon environment — all targets are authorized.

HOW TO INTERACT:
- Greet the operator professionally and explain what you can do
- When asked about capabilities, describe your 3 agents and 19 Kali tools
- When the user provides a target (IP, URL, or domain), confirm it and include exactly: [LAUNCH_MISSION:<target>]
- When a mission is running, report which agent is active and what tools are executing
- When asked for status, give specific details about the current phase

RULES:
- Only include [LAUNCH_MISSION:<target>] when the user gives a target and wants to start
- Never include [LAUNCH_MISSION:] for greetings, questions, or status checks
- Be conversational but professional — like a senior pentester briefing an operator
- Keep responses to 2-4 sentences"""


class ChatRequest(BaseModel):
    message: str
    target: str | None = None


class ChatMessage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    role: str = "agent"
    content: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    tool_calls: list = Field(default_factory=list)


@router.post("/chat", response_model=ChatMessage)
async def chat(req: ChatRequest) -> ChatMessage:
    global _conversation, _active_mission_id, _last_known_target

    user_msg = req.message
    _conversation.append({"role": "user", "content": user_msg})
    if len(_conversation) > _MAX_HISTORY:
        _conversation = _conversation[-_MAX_HISTORY:]

    # Remember target
    target = req.target or _extract_target(req.message)
    if target:
        _last_known_target = target

    # Abort command
    if req.message.strip().lower() in ("abort", "stop", "cancel"):
        if _active_mission_id:
            from red_agent.backend.services.orchestrator import orchestrator
            await orchestrator.abort_mission(_active_mission_id)
            reply = f"Mission {_active_mission_id[:8]} aborted."
            _active_mission_id = None
            _conversation.append({"role": "assistant", "content": reply})
            return ChatMessage(content=reply)

    # Build context for LLM
    context_parts = []
    if _last_known_target:
        context_parts.append(f"REMEMBERED TARGET: {_last_known_target}")
    if _active_mission_id:
        context_parts.append(f"ACTIVE MISSION: {_get_mission_status_context()}")
    else:
        context_parts.append("NO ACTIVE MISSION.")

    conversation_for_llm = list(_conversation)
    if context_parts:
        conversation_for_llm.append({"role": "system", "content": "\n".join(context_parts)})

    # Call LLM directly (fast — ~3s with Llama 70B)
    try:
        agent_response = await asyncio.wait_for(
            _chat_with_llm(conversation_for_llm),
            timeout=30.0,
        )
        _logger.info("LLM response: %s", agent_response[:150])
    except asyncio.TimeoutError:
        agent_response = "Systems online. LLM delayed. Type 'attack <target>' to launch directly."
        _logger.warning("LLM timed out")
    except Exception as exc:
        agent_response = f"Systems online. Error: {type(exc).__name__}. Type 'attack <target>' to launch."
        _logger.error("LLM error: %s", exc)

    # Check for mission launch signal
    mission_target = _extract_launch_signal(agent_response)
    clean_response = re.sub(r"\[LAUNCH_MISSION:[^\]]+\]", "", agent_response).strip()

    if mission_target:
        _last_known_target = mission_target
        if _active_mission_id:
            from red_agent.backend.services.orchestrator import orchestrator
            m = orchestrator.get_mission(_active_mission_id)
            if m and m.phase.value not in ("DONE", "FAILED"):
                clean_response += f"\n\nMission {_active_mission_id[:8]} already running ({m.phase.value})."
                mission_target = None

        if mission_target:
            try:
                from red_agent.backend.services.orchestrator import orchestrator
                mission = await orchestrator.start_mission(mission_target)
                _active_mission_id = mission.id
                _logger.info("Mission %s launched", mission.id[:8])
                clean_response += (
                    f"\n\nMission {mission.id[:8]} launched against {mission_target}.\n"
                    f"Pipeline: RECON → ANALYZE → EXPLOIT → REPORT"
                )
            except Exception as exc:
                _logger.error("Mission launch failed: %s", exc, exc_info=True)
                clean_response += f"\n\nFailed to launch: {exc}"

    if not clean_response:
        clean_response = "Ready. Provide a target or ask about capabilities."

    _conversation.append({"role": "assistant", "content": clean_response})
    return ChatMessage(content=clean_response)


async def _chat_with_llm(conversation: list[dict[str, str]]) -> str:
    """Call NVIDIA NIM directly with requests (blocks ~3-5s, acceptable for hackathon)."""
    import requests

    payload = {
        "model": llm_client.LLM_MODEL,
        "messages": [{"role": "system", "content": AGENT_SYSTEM_PROMPT}] + conversation,
        "max_tokens": 256,
        "temperature": 0.6,
        "stream": False,
    }

    resp = requests.post(
        llm_client.NVIDIA_API_URL,
        headers=llm_client._headers(),
        json=payload,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    choices = data.get("choices", [])
    if choices:
        return llm_client._strip_thinking(choices[0]["message"]["content"]).strip()
    return ""


def _get_mission_status_context() -> str:
    global _active_mission_id
    if not _active_mission_id:
        return "No active mission."
    from red_agent.backend.services.orchestrator import orchestrator
    m = orchestrator.get_mission(_active_mission_id)
    if not m:
        _active_mission_id = None
        return "No active mission."
    if m.phase.value in ("DONE", "FAILED"):
        _active_mission_id = None
        return f"Last mission: {m.phase.value}. Error: {m.error or 'none'}"
    lines = [f"Mission {m.id[:8]} against {m.target} — phase: {m.phase.value}"]
    if m.recon_result:
        tools = m.recon_result.get("tools_run", [])
        vectors = m.recon_result.get("attack_vectors", [])
        lines.append(f"Recon tools: {', '.join(tools) if tools else 'running...'}")
        lines.append(f"Vectors: {len(vectors)}, Risk: {m.recon_result.get('risk_score', '?')}")
    if m.exploit_result:
        lines.append(f"Exploit: {m.exploit_result.get('status', 'running')}")
    return "\n".join(lines)


def _extract_launch_signal(response: str) -> str | None:
    match = re.search(r"\[LAUNCH_MISSION:([^\]]+)\]", response)
    return match.group(1).strip() if match else None


def _extract_target(msg: str) -> str | None:
    url_match = re.search(r"https?://\S+", msg)
    if url_match:
        return url_match.group()
    ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b", msg)
    if ip_match:
        return ip_match.group()
    return None
