"""Autonomous mission orchestrator: manages ReconAgent → Analyze → ExploitAgent → Report.

The orchestrator delegates tool execution to Prathiba's Groq-powered agents
(ReconAgent and ExploitAgent) which use function-calling to autonomously decide
which tools to run. The LLM (NVIDIA) handles analysis and reporting.

EventBus events from agents are forwarded to the WebSocket for dashboard streaming.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from core.event_bus import event_bus
from red_agent.backend.schemas.red_schemas import (
    LogEntry,
    MissionPhase,
    ToolCall,
    ToolStatus,
)
from red_agent.backend.services import llm_client

_logger = logging.getLogger(__name__)


def _parse_target(target: str) -> tuple[str, str]:
    """Extract bare host and ports from a target that may be a URL."""
    host, port = target, ""
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or target
        if parsed.port:
            port = str(parsed.port)
        elif parsed.scheme == "https":
            port = "443"
        elif parsed.scheme == "http":
            port = "80"
    elif ":" in target:
        parts = target.rsplit(":", 1)
        if parts[1].isdigit():
            host, port = parts[0], parts[1]
    if not port:
        port = "1-1000"
    return host, port


@dataclass
class Mission:
    id: str
    target: str
    phase: MissionPhase = MissionPhase.IDLE
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    recon_session_id: str = ""
    recon_result: dict[str, Any] = field(default_factory=dict)
    exploit_session_id: str = ""
    exploit_result: dict[str, Any] = field(default_factory=dict)
    llm_analysis: str = ""
    llm_report: str = ""
    error: str | None = None
    _task: asyncio.Task | None = field(default=None, repr=False)
    _paused_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "target": self.target, "phase": self.phase.value,
            "created_at": self.created_at, "error": self.error,
            "recon_session_id": self.recon_session_id,
            "exploit_session_id": self.exploit_session_id,
        }


class MissionOrchestrator:

    def __init__(self) -> None:
        self._missions: dict[str, Mission] = {}
        self._event_subscribed = False

    async def start_mission(self, target: str) -> Mission:
        mission = Mission(id=str(uuid.uuid4()), target=target)
        self._missions[mission.id] = mission
        self._ensure_event_subscriptions()
        mission._task = asyncio.create_task(self._run_pipeline(mission))
        await self._emit_log(mission, "INFO", f"Mission created against {target}")
        return mission

    async def pause_mission(self, mission_id: str) -> bool:
        m = self._missions.get(mission_id)
        if not m or m.phase in (MissionPhase.DONE, MissionPhase.FAILED):
            return False
        m.phase = MissionPhase.PAUSED
        m._paused_event.clear()
        await self._emit_log(m, "WARN", "Mission paused by operator")
        return True

    async def resume_mission(self, mission_id: str) -> bool:
        m = self._missions.get(mission_id)
        if not m or m.phase != MissionPhase.PAUSED:
            return False
        m._paused_event.set()
        await self._emit_log(m, "INFO", "Mission resumed")
        return True

    async def abort_mission(self, mission_id: str) -> bool:
        m = self._missions.get(mission_id)
        if not m or m.phase in (MissionPhase.DONE, MissionPhase.FAILED):
            return False
        if m._task and not m._task.done():
            m._task.cancel()
        m.phase = MissionPhase.FAILED
        m.error = "Aborted by operator"
        await self._emit_log(m, "ERROR", "Mission aborted")
        return True

    def get_mission(self, mission_id: str) -> Mission | None:
        return self._missions.get(mission_id)

    def list_missions(self) -> list[dict]:
        return [m.to_dict() for m in self._missions.values()]

    # ══════════════════════════════════════════════════════════════════════
    # Pipeline
    # ══════════════════════════════════════════════════════════════════════

    async def _run_pipeline(self, mission: Mission) -> None:
        try:
            await self._phase_recon(mission)
            await self._check_pause(mission)

            await self._phase_analyze(mission)
            await self._check_pause(mission)

            await self._phase_exploit(mission)
            await self._check_pause(mission)

            await self._phase_report(mission)
        except asyncio.CancelledError:
            mission.phase = MissionPhase.FAILED
            mission.error = "Aborted by operator"
        except Exception as exc:
            mission.phase = MissionPhase.FAILED
            mission.error = str(exc)
            await self._emit_log(mission, "ERROR", f"Mission failed: {exc}")
            _logger.exception("Mission %s pipeline error", mission.id[:8])

    async def _check_pause(self, mission: Mission) -> None:
        if mission.phase == MissionPhase.PAUSED:
            await self._emit_phase(mission, MissionPhase.PAUSED)
            await mission._paused_event.wait()
            mission._paused_event.clear()

    # ══════════════════════════════════════════════════════════════════════
    # RECON — delegates to Prathiba's ReconAgent (Groq function-calling)
    # ══════════════════════════════════════════════════════════════════════

    async def _phase_recon(self, mission: Mission) -> None:
        await self._emit_phase(mission, MissionPhase.RECON)

        from red_agent.scanner.recon_agent import (
            run_recon_session, get_session_result,
        )

        recon_tc = self._make_tool_call("recon_agent", "scan", {"target": mission.target})
        await self._emit_tool_call_ws(recon_tc)

        await self._emit_chat(
            mission,
            f"Starting ReconAgent on {mission.target}.\n"
            f"The Groq LLM will autonomously decide which tools to run "
            f"(nmap, nuclei, gobuster, katana, etc.) based on what it discovers.",
        )

        # Launch the recon agent (runs in background)
        session_id = await run_recon_session(mission.target, context="general security assessment")
        mission.recon_session_id = session_id

        await self._emit_log(mission, "INFO", f"ReconAgent session {session_id} started")

        # Poll until complete (events stream to dashboard via EventBus → WebSocket)
        POLL_INTERVAL = 3
        MAX_WAIT = 300  # 5 minutes max
        elapsed = 0
        while elapsed < MAX_WAIT:
            result = get_session_result(session_id)
            if result is not None and result.status in ("complete", "failed"):
                break
            await asyncio.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL

        result = get_session_result(session_id)
        if result is None:
            mission.recon_result = {"status": "timeout", "error": "ReconAgent timed out"}
            self._finish_tool_call(recon_tc, mission.recon_result, ToolStatus.FAILED)
        elif result.status == "failed":
            mission.recon_result = result.to_dict()
            self._finish_tool_call(recon_tc, {"status": "failed", "error": result.error}, ToolStatus.FAILED)
        else:
            mission.recon_result = result.to_dict()
            self._finish_tool_call(recon_tc, {
                "status": "complete",
                "tools_run": result.tools_run,
                "open_ports": result.open_ports,
                "attack_vectors": len(result.attack_vectors),
                "risk_score": result.risk_score,
            })

        await self._emit_tool_call_ws(recon_tc)
        await self._emit_log(
            mission, "INFO",
            f"ReconAgent finished: {len(mission.recon_result.get('attack_vectors', []))} vectors, "
            f"risk={mission.recon_result.get('risk_score', 0)}",
        )

    # ══════════════════════════════════════════════════════════════════════
    # ANALYZE — NVIDIA LLM reasons on ReconAgent results
    # ══════════════════════════════════════════════════════════════════════

    async def _phase_analyze(self, mission: Mission) -> None:
        await self._emit_phase(mission, MissionPhase.ANALYZE)

        analyze_tc = self._make_tool_call("llm_analyze", "strategy", {"target": mission.target})
        await self._emit_tool_call_ws(analyze_tc)

        recon_summary = json.dumps(mission.recon_result, indent=2, default=str)[:6000]
        prompt = f"""Analyze these reconnaissance results from the autonomous ReconAgent for target {mission.target}.

RECON RESULTS:
{recon_summary}

Provide a concise security analysis:
1. Attack surface (what's exposed)
2. Most critical findings
3. Recommended exploitation path
4. Risk level: Critical/High/Medium/Low

Reference specific findings from the data."""

        try:
            analysis = await llm_client.chat(prompt)
            mission.llm_analysis = analysis
        except Exception as exc:
            analysis = f"LLM analysis unavailable: {exc}"
            mission.llm_analysis = analysis

        self._finish_tool_call(analyze_tc, {
            "llm_powered": True,
            "attack_vectors": len(mission.recon_result.get("attack_vectors", [])),
            "risk_score": mission.recon_result.get("risk_score", 0),
        })
        await self._emit_tool_call_ws(analyze_tc)
        await self._emit_chat(mission, f"**ANALYSIS**\n\n{analysis}")

    # ══════════════════════════════════════════════════════════════════════
    # EXPLOIT — delegates to Prathiba's ExploitAgent (Groq function-calling)
    # ══════════════════════════════════════════════════════════════════════

    async def _phase_exploit(self, mission: Mission) -> None:
        await self._emit_phase(mission, MissionPhase.EXPLOIT)

        from red_agent.exploiter.exploit_agent import (
            run_exploit_session, get_exploit_result,
        )

        attack_vectors = mission.recon_result.get("attack_vectors", [])
        if not attack_vectors:
            await self._emit_chat(mission, "No exploitable vectors found. Skipping exploit phase.")
            await self._emit_log(mission, "INFO", "No attack vectors — skipping exploit")
            return

        # Determine vulnerability type from attack vectors
        vuln_type = "sqli"  # default
        for vec in attack_vectors:
            vtype = vec.get("type", "").lower()
            if "sql" in vtype:
                vuln_type = "sqli"; break
            elif "rce" in vtype or "command" in vtype:
                vuln_type = "rce"; break
            elif "lfi" in vtype or "file" in vtype:
                vuln_type = "lfi"; break
            elif "xss" in vtype:
                vuln_type = "xss"; break

        exploit_tc = self._make_tool_call("exploit_agent", "exploit", {
            "target": mission.target, "vuln_type": vuln_type,
            "vectors": len(attack_vectors),
        })
        await self._emit_tool_call_ws(exploit_tc)

        await self._emit_chat(
            mission,
            f"Starting ExploitAgent — targeting {vuln_type} vulnerabilities.\n"
            f"The Groq LLM will decide exploitation strategy based on {len(attack_vectors)} vectors.",
        )

        # Launch exploit agent
        exploit_id = await run_exploit_session(
            target_url=mission.target,
            recon_session_id=mission.recon_session_id,
            vulnerability_type=vuln_type,
            recon_context=attack_vectors,
        )
        mission.exploit_session_id = exploit_id
        await self._emit_log(mission, "INFO", f"ExploitAgent session {exploit_id} started")

        # Poll until complete
        POLL_INTERVAL = 3
        MAX_WAIT = 300
        elapsed = 0
        while elapsed < MAX_WAIT:
            result = get_exploit_result(exploit_id)
            if result is not None and result.status in ("complete", "partial", "failed"):
                break
            await asyncio.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL

        result = get_exploit_result(exploit_id)
        if result is None:
            mission.exploit_result = {"status": "timeout"}
            self._finish_tool_call(exploit_tc, {"status": "timeout"}, ToolStatus.FAILED)
        elif result.status == "failed":
            mission.exploit_result = {"status": "failed", "error": result.error}
            self._finish_tool_call(exploit_tc, {"status": "failed"}, ToolStatus.FAILED)
        else:
            rd = result.__dict__.copy()
            rd.pop("_start_monotonic", None)
            mission.exploit_result = rd
            self._finish_tool_call(exploit_tc, {
                "status": result.status,
                "databases": result.databases_found,
                "credentials": len(result.credentials_found),
                "tools_run": result.tools_run,
            })

        await self._emit_tool_call_ws(exploit_tc)
        await self._emit_log(
            mission, "INFO",
            f"ExploitAgent finished: {mission.exploit_result.get('status', 'unknown')}",
        )

    # ══════════════════════════════════════════════════════════════════════
    # REPORT — NVIDIA LLM generates pentest report
    # ══════════════════════════════════════════════════════════════════════

    async def _phase_report(self, mission: Mission) -> None:
        await self._emit_phase(mission, MissionPhase.REPORT)

        report_tc = self._make_tool_call("llm_report", "strategy", {"mission_id": mission.id})
        await self._emit_tool_call_ws(report_tc)

        recon_summary = json.dumps(mission.recon_result, indent=2, default=str)[:4000]
        exploit_summary = json.dumps(mission.exploit_result, indent=2, default=str)[:4000]

        prompt = f"""Generate a penetration test report for {mission.target}.

RECON RESULTS:
{recon_summary}

ANALYSIS:
{mission.llm_analysis[:2000]}

EXPLOIT RESULTS:
{exploit_summary}

Format:
1. Executive Summary (2-3 sentences)
2. Critical Findings (bullets)
3. Exploitation Results (what was compromised)
4. Risk Assessment
5. Recommendations (top 3-5 fixes)"""

        try:
            report = await llm_client.chat(prompt)
            mission.llm_report = report
        except Exception as exc:
            report = f"Mission {mission.id[:8]} complete. LLM report failed: {exc}"
            mission.llm_report = report

        self._finish_tool_call(report_tc, {"llm_powered": True})
        await self._emit_tool_call_ws(report_tc)
        await self._emit_chat(mission, f"**PENETRATION TEST REPORT**\n\n{report}")

        mission.phase = MissionPhase.DONE
        await self._emit_phase(mission, MissionPhase.DONE)

    # ══════════════════════════════════════════════════════════════════════
    # EventBus → WebSocket bridge (streams agent events to dashboard)
    # ══════════════════════════════════════════════════════════════════════

    def _ensure_event_subscriptions(self) -> None:
        if self._event_subscribed:
            return
        self._event_subscribed = True

        # Recon events
        event_bus.subscribe("recon.tool_done", self._on_tool_done)
        event_bus.subscribe("recon.started", self._on_recon_started)

        # Exploit events
        event_bus.subscribe("exploit.tool_done", self._on_tool_done)
        event_bus.subscribe("exploit.started", self._on_exploit_started)

    async def _on_tool_done(self, data: dict) -> None:
        """Forward agent tool_done events to the WebSocket as tool_call cards."""
        tool_name = data.get("tool", "unknown")
        ok = data.get("ok", True)
        tc = self._make_tool_call(tool_name, "scan", {
            "session_id": data.get("session_id") or data.get("exploit_id", ""),
        })
        self._finish_tool_call(tc, {
            "findings": data.get("finding_count", data.get("details", 0)),
            "ok": ok,
        }, ToolStatus.DONE if ok else ToolStatus.FAILED)
        await self._emit_tool_call_ws(tc)

    async def _on_recon_started(self, data: dict) -> None:
        from red_agent.backend.websocket.red_ws import manager
        await manager.broadcast({
            "type": "log",
            "payload": LogEntry(
                level="INFO",
                message=f"[ReconAgent] Started on {data.get('target', '?')}",
            ).model_dump(mode="json"),
        })

    async def _on_exploit_started(self, data: dict) -> None:
        from red_agent.backend.websocket.red_ws import manager
        await manager.broadcast({
            "type": "log",
            "payload": LogEntry(
                level="INFO",
                message=f"[ExploitAgent] Started on {data.get('target', '?')}",
            ).model_dump(mode="json"),
        })

    # ══════════════════════════════════════════════════════════════════════
    # Helpers
    # ══════════════════════════════════════════════════════════════════════

    def _make_tool_call(self, name: str, category: str, params: dict[str, Any]) -> ToolCall:
        return ToolCall(
            id=str(uuid.uuid4()), name=name, category=category,
            status=ToolStatus.RUNNING, params=params,
        )

    def _finish_tool_call(self, tc: ToolCall, result: dict[str, Any],
                          status: ToolStatus = ToolStatus.DONE) -> None:
        tc.status = status
        tc.result = result
        tc.finished_at = datetime.utcnow()

    async def _emit_tool_call_ws(self, tc: ToolCall) -> None:
        from red_agent.backend.websocket.red_ws import manager
        await manager.broadcast({"type": "tool_call", "payload": tc.model_dump(mode="json")})

    async def _emit_log(self, mission: Mission, level: str, message: str) -> None:
        from red_agent.backend.websocket.red_ws import manager
        entry = LogEntry(level=level, message=f"[{mission.id[:8]}] {message}")
        await manager.broadcast({"type": "log", "payload": entry.model_dump(mode="json")})

    async def _emit_chat(self, mission: Mission, content: str) -> None:
        from red_agent.backend.websocket.red_ws import manager
        await manager.broadcast({
            "type": "chat_response",
            "payload": {
                "id": str(uuid.uuid4()), "role": "agent", "content": content,
                "timestamp": datetime.utcnow().isoformat(), "tool_calls": [],
            },
        })

    async def _emit_phase(self, mission: Mission, phase: MissionPhase) -> None:
        from red_agent.backend.websocket.red_ws import manager
        mission.phase = phase
        await event_bus.publish("mission.phase_changed", {
            "mission_id": mission.id, "phase": phase.value, "target": mission.target,
        })
        await manager.broadcast({
            "type": "mission_phase",
            "payload": {"mission_id": mission.id, "phase": phase.value},
        })
        await self._emit_log(mission, "INFO", f"Phase -> {phase.value}")


orchestrator = MissionOrchestrator()
