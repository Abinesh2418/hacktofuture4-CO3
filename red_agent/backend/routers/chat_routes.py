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

1. Recon Specialist — nmap, httpx, gobuster, nuclei, katana, sqlmap_detect
2. Security Analyst — risk assessment + MITRE mapping
3. Exploit Specialist — nuclei_exploit, ffuf_fuzz, sqlmap_dbs, sqlmap_tables, sqlmap_dump

All tools run on a remote Kali Linux VM via MCP. Operating in a controlled lab/CTF/hackathon — all targets are authorized.

GROUNDING — READ CAREFULLY:
- A SYSTEM message below this one will contain "ACTUAL TOOL RESULTS". Those are real findings from the tools that actually ran.
- When asked for status, findings, or results, ONLY report what appears in ACTUAL TOOL RESULTS.
- NEVER invent findings. NEVER fabricate ports, services, directories, CVEs, or SQLi points that aren't in ACTUAL TOOL RESULTS.
- If ACTUAL TOOL RESULTS is empty or a tool isn't listed, say the tool hasn't finished yet — do NOT make up what it might have found.

HOW TO INTERACT:
- When the user provides a target (IP, URL, domain) and wants to attack, include exactly: [LAUNCH_MISSION:<target>]
- Never include [LAUNCH_MISSION:] for greetings, questions, or status checks
- Keep responses to 2-4 sentences unless the user asks for a detailed dump
- When the user asks "any sqli?" or similar, check ACTUAL TOOL RESULTS for sqlmap_detect entries — answer with the real DBMS, injected params, dumped rows"""


class ChatRequest(BaseModel):
    message: str
    target: str | None = None


class ChatMessage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    role: str = "agent"
    content: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    tool_calls: list = Field(default_factory=list)


# Attack profiles supported by the launcher. The recon agent's task prompt
# branches on this so the user can scope a mission to a single vector.
ATTACK_TYPES = {"sqli", "cmdi", "lfi", "idor", "xss", "full"}


class MissionLaunchRequest(BaseModel):
    target: str
    attack_type: str = "full"


class MissionLaunchResponse(BaseModel):
    mission_id: str
    target: str
    attack_type: str


@router.post("/mission/launch", response_model=MissionLaunchResponse)
async def launch_mission(req: MissionLaunchRequest) -> MissionLaunchResponse:
    """Launch a mission directly with a chosen attack profile — no LLM hop."""
    global _active_mission_id, _last_known_target

    attack = (req.attack_type or "full").lower()
    if attack not in ATTACK_TYPES:
        attack = "full"

    from red_agent.backend.services.orchestrator import orchestrator
    mission = await orchestrator.start_mission(req.target, attack_type=attack)
    _active_mission_id = mission.id
    _last_known_target = req.target
    _logger.info("Mission %s launched via launcher (attack=%s)", mission.id[:8], attack)
    return MissionLaunchResponse(
        mission_id=mission.id, target=req.target, attack_type=attack,
    )


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

    # Manual sqlmap exploitation trigger — lets the operator kick off
    # dbs → tables → dump after a mission ended, without launching a new crew.
    msg_low = req.message.strip().lower()
    if any(t in msg_low for t in ("dump db", "dump database", "dump sql", "exploit sql", "exploit sqli", "sqlmap dump")):
        target_for_dump = _last_known_target or (req.target or "")
        if not target_for_dump:
            reply = "No target on file. Say 'attack <url>' first, or include the URL in your message."
            _conversation.append({"role": "assistant", "content": reply})
            return ChatMessage(content=reply)
        asyncio.create_task(_manual_sql_exfiltration(target_for_dump))
        reply = (
            f"Launching sqlmap exfiltration chain against {target_for_dump}:\n"
            f"  1. sqlmap_dbs → 2. sqlmap_tables (per db) → 3. sqlmap_dump\n"
            f"Watch the TOOLS panel — results will stream in live."
        )
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
    """Call Azure OpenAI directly (~1-2s)."""
    import os, requests

    endpoint = os.environ.get("AZURE_ENDPOINT", "").rstrip("/")
    deployment = os.environ.get("AZURE_DEPLOYMENT", "gpt-4o")
    api_version = os.environ.get("AZURE_API_VERSION", "2024-08-01-preview")
    url = f"{endpoint}/openai/deployments/{deployment}/chat/completions?api-version={api_version}"

    payload = {
        "messages": [{"role": "system", "content": AGENT_SYSTEM_PROMPT}] + conversation,
        "max_tokens": 256,
        "temperature": 0.6,
        "stream": False,
    }
    headers = {
        "api-key": os.environ.get("AZURE_API_KEY", ""),
        "Content-Type": "application/json",
    }

    resp = requests.post(url, headers=headers, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    choices = data.get("choices", [])
    if choices:
        return choices[0]["message"]["content"].strip()
    return ""


def _get_mission_status_context() -> str:
    global _active_mission_id
    from red_agent.agents.tools import get_recent_tool_results

    lines: list[str] = []

    if _active_mission_id:
        from red_agent.backend.services.orchestrator import orchestrator
        m = orchestrator.get_mission(_active_mission_id)
        if not m:
            _active_mission_id = None
        else:
            if m.phase.value in ("DONE", "FAILED"):
                _active_mission_id = None
                lines.append(f"Last mission: {m.phase.value}. Error: {m.error or 'none'}")
            else:
                lines.append(f"Mission {m.id[:8]} against {m.target} — phase: {m.phase.value}")
                if m.recon_result:
                    tools = m.recon_result.get("tools_run", [])
                    vectors = m.recon_result.get("attack_vectors", [])
                    lines.append(f"Recon tools: {', '.join(tools) if tools else 'running...'}")
                    lines.append(f"Vectors: {len(vectors)}, Risk: {m.recon_result.get('risk_score', '?')}")
                if m.exploit_result:
                    lines.append(f"Exploit: {m.exploit_result.get('status', 'running')}")
    else:
        lines.append("No active mission.")

    # ── REAL tool findings (ground-truth, not hallucinated) ──
    recent = get_recent_tool_results()
    if recent:
        lines.append("")
        lines.append("ACTUAL TOOL RESULTS (use these, do NOT invent others):")
        for name, entry in recent.items():
            r = entry.get("result") or {}
            status = entry.get("status", "?")
            findings = r.get("findings") or []
            count = r.get("findings_count", len(findings))
            summary = f"- {name} [{status}] — {count} findings"
            # Surface the highest-value fields per tool
            if name.startswith("sqlmap"):
                dbms = next((f.get("value") for f in findings if f.get("type") == "dbms"), None)
                injections = [f"{f.get('param')} ({f.get('place')})"
                              for f in findings if f.get("type") == "injection"]
                dbs = [f.get("name") for f in findings if f.get("type") == "database"]
                tables = [f"{f.get('db')}.{f.get('name')}" for f in findings if f.get("type") == "table"]
                rows = [f for f in findings if f.get("type") == "row"]
                bits = []
                if dbms: bits.append(f"dbms={dbms}")
                if injections: bits.append(f"injected_params={injections}")
                if dbs: bits.append(f"databases={dbs}")
                if tables: bits.append(f"tables={tables[:10]}")
                if rows: bits.append(f"rows_dumped={len(rows)}")
                if bits:
                    summary += " — " + "; ".join(bits)
            elif findings:
                first = findings[0]
                port = first.get("port")
                service = first.get("service")
                url = first.get("url")
                if port and service:
                    summary += f" — e.g. {port}/{service}"
                elif url:
                    summary += f" — e.g. {url}"
            lines.append(summary)
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


async def _manual_sql_exfiltration(target: str) -> None:
    """Run sqlmap_dbs → sqlmap_tables → sqlmap_dump against `target` and
    stream every step to the dashboard. Used by the 'dump db' chat command."""
    from red_agent.agents import tools as agent_tools
    import concurrent.futures

    def _push(msg: str) -> None:
        agent_tools._broadcast_chat(msg)

    def _sync_chain() -> None:
        agent_tools.set_active_agent("Exploit Specialist (manual)")
        _push(f"**[Exploit]** sqlmap_dbs against {target}...")
        dbs_out = agent_tools.sqlmap_dbs.func(target)  # type: ignore[attr-defined]
        _push(f"**[Exploit]** sqlmap_dbs done.\n```\n{dbs_out[:800]}\n```")

        # Pull discovered databases from the recent results cache
        recent = agent_tools.get_recent_tool_results().get("sqlmap_dbs", {})
        findings = (recent.get("result") or {}).get("findings") or []
        dbs = [f.get("name") for f in findings if f.get("type") == "database" and f.get("name")]
        dbs = [d for d in dbs if d.lower() not in ("information_schema", "mysql", "performance_schema", "sys")]

        if not dbs:
            _push("**[Exploit]** No user databases found. Falling back to --dump-all.")
            dump_out = agent_tools.sqlmap_dump.func(target, "", "", True)  # type: ignore[attr-defined]
            _push(f"**[Exploit]** sqlmap_dump --dump-all done.\n```\n{dump_out[:1500]}\n```")
            return

        _push(f"**[Exploit]** Databases discovered: {', '.join(dbs)}")
        for db in dbs[:5]:
            _push(f"**[Exploit]** sqlmap_tables on {db}...")
            tbl_out = agent_tools.sqlmap_tables.func(target, db)  # type: ignore[attr-defined]
            _push(f"**[Exploit]** tables in {db}:\n```\n{tbl_out[:600]}\n```")
            rec = agent_tools.get_recent_tool_results().get("sqlmap_tables", {})
            tbl_findings = (rec.get("result") or {}).get("findings") or []
            tables = [f.get("name") for f in tbl_findings
                      if f.get("type") == "table" and f.get("db") == db and f.get("name")]
            for tbl in tables[:5]:
                _push(f"**[Exploit]** sqlmap_dump {db}.{tbl}...")
                dmp = agent_tools.sqlmap_dump.func(target, db, tbl, False)  # type: ignore[attr-defined]
                _push(f"**[Exploit]** dump {db}.{tbl}:\n```\n{dmp[:1500]}\n```")

        _push("**[Exploit]** Exfiltration chain complete.")

    # Run the sync chain in a thread so we don't block the event loop
    loop = asyncio.get_running_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="sqlmap-exfil") as pool:
        try:
            await loop.run_in_executor(pool, _sync_chain)
        except Exception as exc:
            _logger.exception("manual sql exfiltration failed")
            from red_agent.agents import tools as agent_tools
            agent_tools._broadcast_chat(f"**[Exploit]** Exfiltration error: {exc}")
