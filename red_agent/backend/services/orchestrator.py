"""Mission orchestrator — runs a CrewAI Red Team crew.

Pipeline:
  1. CrewAI Crew (3 agents: Recon → Analyst → Exploit) runs autonomously
  2. Results stream to dashboard via WebSocket
  3. Final report delivered to chat
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from core.event_bus import event_bus
from red_agent.backend.schemas.red_schemas import (
    LogEntry,
    MissionPhase,
    ToolCall,
    ToolStatus,
)

_logger = logging.getLogger(__name__)


@dataclass
class Mission:
    id: str
    target: str
    phase: MissionPhase = MissionPhase.IDLE
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    recon_output: str = ""
    analysis_output: str = ""
    exploit_output: str = ""
    final_output: str = ""
    error: str | None = None
    _task: asyncio.Task | None = field(default=None, repr=False)
    _paused_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)

    # Keep old field names for compatibility with chat_routes
    recon_result: dict[str, Any] = field(default_factory=dict)
    exploit_result: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "target": self.target, "phase": self.phase.value,
            "created_at": self.created_at, "error": self.error,
        }


class MissionOrchestrator:

    def __init__(self) -> None:
        self._missions: dict[str, Mission] = {}

    async def start_mission(self, target: str) -> Mission:
        mission = Mission(id=str(uuid.uuid4()), target=target)
        self._missions[mission.id] = mission
        mission._task = asyncio.create_task(self._run_crew(mission))
        # Add done callback so errors aren't swallowed
        mission._task.add_done_callback(
            lambda t: _logger.error("Crew task failed: %s", t.exception()) if t.exception() else None
        )
        await self._emit_log(mission, "INFO", f"Mission created against {target}")
        return mission

    async def pause_mission(self, mission_id: str) -> bool:
        m = self._missions.get(mission_id)
        if not m or m.phase in (MissionPhase.DONE, MissionPhase.FAILED):
            return False
        m.phase = MissionPhase.PAUSED
        await self._emit_log(m, "WARN", "Mission paused")
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
    # CrewAI Pipeline
    # ══════════════════════════════════════════════════════════════════════

    async def _run_crew(self, mission: Mission) -> None:
        try:
            await self._emit_phase(mission, MissionPhase.RECON)
            await self._emit_chat(
                mission,
                f"Deploying Red Team Crew against {mission.target}.\n\n"
                f"3 agents activated:\n"
                f"  1. Recon Specialist — port scanning, directory discovery, vuln detection\n"
                f"  2. Security Analyst — risk assessment, attack planning\n"
                f"  3. Exploit Specialist — vulnerability exploitation, data extraction\n\n"
                f"The crew will work autonomously. Watch the Activity panel for tool calls.",
            )

            # Create tool call cards for each agent phase
            recon_tc = self._make_tool_call("crew_recon_agent", "scan", {"target": mission.target})
            await self._emit_tool_call_ws(recon_tc)

            # Run the CrewAI crew (sync operation in executor)
            from red_agent.agents.crew import run_crew_mission
            results = await run_crew_mission(mission.target)

            # Extract results
            mission.recon_output = results.get("recon_output", "")
            mission.analysis_output = results.get("analysis_output", "")
            mission.exploit_output = results.get("exploit_output", "")
            mission.final_output = results.get("final_output", "")

            # Update tool call
            self._finish_tool_call(recon_tc, {"status": "complete", "agents": 3})
            await self._emit_tool_call_ws(recon_tc)

            # Stream results to chat
            await self._emit_phase(mission, MissionPhase.ANALYZE)
            if mission.recon_output:
                await self._emit_chat(mission, f"**RECON RESULTS**\n\n{mission.recon_output[:2000]}")

            if mission.analysis_output:
                await self._emit_chat(mission, f"**SECURITY ANALYSIS**\n\n{mission.analysis_output[:2000]}")

            await self._emit_phase(mission, MissionPhase.EXPLOIT)
            if mission.exploit_output:
                await self._emit_chat(mission, f"**EXPLOITATION RESULTS**\n\n{mission.exploit_output[:2000]}")

            # Final report
            await self._emit_phase(mission, MissionPhase.REPORT)
            report_tc = self._make_tool_call("crew_final_report", "strategy", {"mission_id": mission.id})
            await self._emit_tool_call_ws(report_tc)

            if mission.final_output:
                await self._emit_chat(mission, f"**PENETRATION TEST REPORT**\n\n{mission.final_output[:3000]}")

            self._finish_tool_call(report_tc, {"status": "complete"})
            await self._emit_tool_call_ws(report_tc)

            mission.phase = MissionPhase.DONE
            await self._emit_phase(mission, MissionPhase.DONE)

        except asyncio.CancelledError:
            mission.phase = MissionPhase.FAILED
            mission.error = "Aborted by operator"
        except Exception as exc:
            mission.phase = MissionPhase.FAILED
            mission.error = str(exc)
            await self._emit_log(mission, "ERROR", f"Crew failed: {exc}")
            _logger.exception("Mission %s crew error", mission.id[:8])

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
