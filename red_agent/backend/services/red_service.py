"""Bridge between the HTTP/WS layer and the Red agent's domain modules.

This module is intentionally the *only* place the backend talks to the
underlying scanner/exploiter/strategy packages, so the agent core stays
decoupled from the FastAPI surface.
"""

from __future__ import annotations

import logging
import uuid
from collections import deque
from datetime import datetime
from typing import Any, Deque

from core.event_bus import event_bus
from red_agent.scanner.recon_agent import (
    ReconResult,
    get_session_result as _get_session_result,
    has_session as _has_session,
    list_sessions as _list_sessions,
    run_recon_session,
)

from red_agent.backend.schemas.red_schemas import (
    CVELookupRequest,
    CVELookupResult,
    ExploitRequest,
    ExploitResult,
    LogEntry,
    ScanRequest,
    ScanResult,
    StrategyPlan,
    StrategyRequest,
    ToolCall,
    ToolStatus,
)
from red_agent.exploiter.cve_exploiter import CVEExploiter
from red_agent.exploiter.exploit_engine import ExploitEngine
from red_agent.scanner.cloud_scanner import CloudScanner
from red_agent.scanner.network_scanner import NetworkScanner
from red_agent.scanner.system_scanner import SystemScanner
from red_agent.scanner.web_scanner import WebScanner
from red_agent.strategy.attack_evolver import AttackEvolver
from red_agent.strategy.attack_planner import AttackPlanner

_TOOL_HISTORY: Deque[ToolCall] = deque(maxlen=200)
_LOG_HISTORY: Deque[LogEntry] = deque(maxlen=500)

_network_scanner = NetworkScanner()
_web_scanner = WebScanner()
_system_scanner = SystemScanner()
_cloud_scanner = CloudScanner()
_exploit_engine = ExploitEngine()
_cve_exploiter = CVEExploiter()
_attack_planner = AttackPlanner()
_attack_evolver = AttackEvolver()


def _new_tool_call(name: str, category: str, params: dict[str, Any]) -> ToolCall:
    return ToolCall(
        id=str(uuid.uuid4()),
        name=name,
        category=category,
        status=ToolStatus.RUNNING,
        params=params,
    )


def _finish(call: ToolCall, result: dict[str, Any], status: ToolStatus = ToolStatus.DONE) -> ToolCall:
    call.status = status
    call.result = result
    call.finished_at = datetime.utcnow()
    _TOOL_HISTORY.append(call)
    _LOG_HISTORY.append(
        LogEntry(
            level="INFO" if status is ToolStatus.DONE else "ERROR",
            message=f"{call.name} -> {status.value}",
            tool_id=call.id,
        )
    )
    return call


async def run_network_scan(request: ScanRequest) -> ScanResult:
    call = _new_tool_call("nmap_scan", "scan", request.model_dump())
    # TODO: invoke _network_scanner against request.target
    open_ports = request.ports or [22, 80, 443]
    result = ScanResult(
        tool_call=_finish(call, {"open_ports": open_ports}),
        open_ports=open_ports,
        services={22: "ssh", 80: "http", 443: "https"},
        findings=[f"target {request.target} reachable"],
    )
    return result


async def run_web_scan(request: ScanRequest) -> ScanResult:
    call = _new_tool_call("web_scan", "scan", request.model_dump())
    return ScanResult(tool_call=_finish(call, {"target": request.target}))


async def run_system_scan(request: ScanRequest) -> ScanResult:
    call = _new_tool_call("system_scan", "scan", request.model_dump())
    return ScanResult(tool_call=_finish(call, {"target": request.target}))


async def run_cloud_scan(request: ScanRequest) -> ScanResult:
    call = _new_tool_call("cloud_scan", "scan", request.model_dump())
    return ScanResult(tool_call=_finish(call, {"target": request.target}))


async def lookup_cve(request: CVELookupRequest) -> CVELookupResult:
    call = _new_tool_call("lookup_cve", "exploit", request.model_dump())
    cve_ids: list[str] = []  # TODO: query CVE feed via core.cve_feed.CVEFeed
    return CVELookupResult(tool_call=_finish(call, {"cve_ids": cve_ids}), cve_ids=cve_ids)


async def run_exploit(request: ExploitRequest) -> ExploitResult:
    call = _new_tool_call("run_exploit", "exploit", request.model_dump())
    return ExploitResult(tool_call=_finish(call, {"success": False}))


async def run_cve_exploit(request: ExploitRequest) -> ExploitResult:
    call = _new_tool_call("cve_exploit", "exploit", request.model_dump())
    return ExploitResult(tool_call=_finish(call, {"cve": request.cve_id}))


async def plan_attack(request: StrategyRequest) -> StrategyPlan:
    call = _new_tool_call("plan_attack", "strategy", request.model_dump())
    steps = ["recon", "exploit", "persist"]
    return StrategyPlan(tool_call=_finish(call, {"steps": steps}), steps=steps)


async def evolve_strategy(request: StrategyRequest) -> StrategyPlan:
    call = _new_tool_call("evolve_strategy", "strategy", request.model_dump())
    return StrategyPlan(tool_call=_finish(call, {}), steps=[])


async def current_strategy() -> StrategyPlan:
    call = _new_tool_call("current_strategy", "strategy", {})
    return StrategyPlan(tool_call=_finish(call, {}), steps=[])


async def recent_tool_calls(category: str | None = None, limit: int = 20) -> list[ToolCall]:
    items = list(_TOOL_HISTORY)
    if category:
        items = [c for c in items if c.category == category]
    return items[-limit:]


async def recent_logs(limit: int = 100) -> list[LogEntry]:
    return list(_LOG_HISTORY)[-limit:]


# ---------- Autonomous CrewAI recon agent wiring --------------------------

_logger = logging.getLogger(__name__)
_recon_subscribed = False


async def start_recon(target: str, context: str | None = None) -> str:
    """Kick off a background recon session and return its id."""
    _ensure_recon_subscriptions()
    session_id = await run_recon_session(target=target, context=context)
    _LOG_HISTORY.append(
        LogEntry(level="INFO", message=f"recon started: {session_id} -> {target}")
    )
    return session_id


def get_recon_result(session_id: str) -> ReconResult | None:
    return _get_session_result(session_id)


def has_recon_session(session_id: str) -> bool:
    return _has_session(session_id)


def list_recon_sessions() -> list[dict]:
    return _list_sessions()


def _ensure_recon_subscriptions() -> None:
    global _recon_subscribed
    if _recon_subscribed:
        return
    event_bus.subscribe("recon.complete", _on_recon_complete)
    event_bus.subscribe("recon.failed", _on_recon_failed)
    _recon_subscribed = True


async def _on_recon_complete(data: dict) -> None:
    _logger.info(
        "[RedService] recon complete session=%s risk=%s vectors=%s",
        data.get("session_id"),
        data.get("risk_score"),
        len(data.get("attack_vectors") or []),
    )
    _LOG_HISTORY.append(
        LogEntry(
            level="INFO",
            message=(
                f"recon complete: {data.get('session_id')} "
                f"risk={data.get('risk_score')}"
            ),
        )
    )


async def _on_recon_failed(data: dict) -> None:
    _logger.warning(
        "[RedService] recon failed session=%s err=%s",
        data.get("session_id"),
        data.get("error"),
    )
    _LOG_HISTORY.append(
        LogEntry(
            level="ERROR",
            message=f"recon failed: {data.get('session_id')} {data.get('error')}",
        )
    )
