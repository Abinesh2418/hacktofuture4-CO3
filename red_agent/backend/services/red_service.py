"""Bridge between the HTTP/WS layer and the Red agent's domain modules.

This module is intentionally the *only* place the backend talks to the
underlying scanner/exploiter/strategy packages, so the agent core stays
decoupled from the FastAPI surface.

Recon scans (`run_network_scan`, `run_web_scan`, `run_system_scan`) call
the red_arsenal MCP server over SSE via `mcp_client`. Exploit and
strategy paths remain mocked until the exploit-tier MCP tools land.
"""

from __future__ import annotations

import uuid
from collections import deque
from datetime import datetime
from typing import Any, Deque

from loguru import logger

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
from red_agent.backend.services import mcp_client
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


async def _broadcast_tool_call(call: ToolCall) -> None:
    """Push a ToolCall snapshot to the /ws/red stream.

    Late-imported to avoid a circular import with the websocket module
    (red_ws.py imports red_service). Best-effort — a WS failure must
    never break a scan.
    """
    try:
        from red_agent.backend.websocket.red_ws import manager
        await manager.broadcast(
            {"type": "tool_call", "payload": call.model_dump(mode="json")}
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("ws broadcast skipped: {}", exc)


async def _broadcast_log(entry: LogEntry) -> None:
    try:
        from red_agent.backend.websocket.red_ws import manager
        await manager.broadcast(
            {"type": "log", "payload": entry.model_dump(mode="json")}
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("ws broadcast skipped: {}", exc)


def _summarize_nmap(raw: dict) -> tuple[list[int], dict[int, str], list[str]]:
    """Map a red_arsenal nmap result dict onto ScanResult fields."""
    findings = raw.get("findings") or []
    open_findings = [f for f in findings if (f.get("state") == "open")]
    open_ports = sorted({int(f["port"]) for f in open_findings if f.get("port")})
    services: dict[int, str] = {}
    notes: list[str] = []
    for f in open_findings:
        port = int(f["port"]) if f.get("port") else None
        if port is None:
            continue
        service = f.get("service") or "unknown"
        product = f.get("product")
        version = f.get("version")
        services[port] = service
        label = f"{port}/{service}"
        if product:
            label += f" ({product}{' ' + version if version else ''})"
        notes.append(label)
    return open_ports, services, notes


async def run_network_scan(request: ScanRequest) -> ScanResult:
    """Invoke red_arsenal `run_nmap` and shape the output into ScanResult."""
    call = _new_tool_call("nmap_scan", "scan", request.model_dump())
    await _broadcast_tool_call(call)

    ports = (
        ",".join(str(p) for p in request.ports)
        if request.ports
        else "22,80,443,445,3306,3389,5432,6379,8080,8443"
    )

    try:
        raw = await mcp_client.call_tool_and_wait(
            "run_nmap",
            {"target": request.target, "ports": ports},
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("run_nmap MCP call failed")
        _finish(call, {"error": str(exc)}, ToolStatus.FAILED)
        await _broadcast_tool_call(call)
        return ScanResult(tool_call=call, findings=[f"mcp error: {exc}"])

    ok = bool(raw.get("ok"))
    if not ok:
        _finish(call, raw, ToolStatus.FAILED)
        await _broadcast_tool_call(call)
        return ScanResult(
            tool_call=call,
            findings=[raw.get("error") or "nmap failed"],
        )

    open_ports, services, notes = _summarize_nmap(raw)
    _finish(call, raw, ToolStatus.DONE)
    await _broadcast_tool_call(call)
    return ScanResult(
        tool_call=call,
        open_ports=open_ports,
        services=services,
        findings=notes or [f"nmap completed against {request.target}, no open ports"],
    )


def _summarize_web_reconnaissance(raw: dict) -> list[str]:
    """Flatten a web_reconnaissance workflow result into human-readable lines."""
    notes: list[str] = []
    for step in raw.get("results") or []:
        tool = step.get("tool", "?")
        if not step.get("ok"):
            notes.append(f"{tool}: FAILED ({step.get('error') or 'unknown'})")
            continue
        n = len(step.get("findings") or [])
        notes.append(f"{tool}: {n} findings in {step.get('duration_s', 0):.1f}s")
    return notes


async def run_web_scan(request: ScanRequest) -> ScanResult:
    """Run the `web_reconnaissance` workflow in wait-mode and aggregate."""
    call = _new_tool_call("web_reconnaissance", "scan", request.model_dump())
    await _broadcast_tool_call(call)

    try:
        raw = await mcp_client.call_tool_and_wait(
            "web_reconnaissance",
            {"target": request.target, "wait": True},
            # Web workflow fans out 8 tools in parallel but some (gau,
            # nuclei) legitimately take minutes each.
            poll_timeout_s=1800.0,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("web_reconnaissance MCP call failed")
        _finish(call, {"error": str(exc)}, ToolStatus.FAILED)
        await _broadcast_tool_call(call)
        return ScanResult(tool_call=call, findings=[f"mcp error: {exc}"])

    notes = _summarize_web_reconnaissance(raw)
    _finish(call, raw, ToolStatus.DONE)
    await _broadcast_tool_call(call)
    return ScanResult(tool_call=call, findings=notes or ["web workflow returned no findings"])


async def run_system_scan(request: ScanRequest) -> ScanResult:
    """SMB enumeration via `run_smbmap` on the target host."""
    call = _new_tool_call("smbmap", "scan", request.model_dump())
    await _broadcast_tool_call(call)

    try:
        raw = await mcp_client.call_tool_and_wait(
            "run_smbmap",
            {"target": request.target},
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("run_smbmap MCP call failed")
        _finish(call, {"error": str(exc)}, ToolStatus.FAILED)
        await _broadcast_tool_call(call)
        return ScanResult(tool_call=call, findings=[f"mcp error: {exc}"])

    notes: list[str] = []
    for f in raw.get("findings") or []:
        line = f.get("line")
        if line:
            notes.append(line)
    if not raw.get("ok") and not notes:
        notes.append(raw.get("error") or "smbmap reported no shares")

    status = ToolStatus.DONE if raw.get("ok") else ToolStatus.FAILED
    _finish(call, raw, status)
    await _broadcast_tool_call(call)
    return ScanResult(tool_call=call, findings=notes or [f"no SMB shares on {request.target}"])


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
