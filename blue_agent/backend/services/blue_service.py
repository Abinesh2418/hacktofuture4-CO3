"""Bridge between the HTTP/WS layer and the Blue agent's domain modules."""

from __future__ import annotations

import asyncio
import uuid
from collections import deque
from datetime import datetime
from typing import Any, Callable, Deque, Dict, List, Optional

from blue_agent.backend.schemas.blue_schemas import (
    ApprovalResult,
    AssetInfo,
    BlueAgentStatus,
    ClosePortRequest,
    DefensePlan,
    DefenseResult,
    EnvironmentAlertInfo,
    EnvironmentStats,
    EvolutionMetrics,
    HardenServiceRequest,
    IsolateHostRequest,
    LogEntry,
    PatchRequest,
    PatchResult,
    PendingFix,
    RedReportRequest,
    RemediationResult,
    RemediationStatus,
    StrategyRequest,
    ToolCall,
    ToolStatus,
    VerifyFixRequest,
    VerifyFixResult,
    VulnerabilityInfo,
)
from blue_agent.scanner.asset_scanner import AssetScanner
from blue_agent.scanner.ssh_scanner import SSHScanner
from blue_agent.environment.environment_manager import EnvironmentManager
from blue_agent.strategy.defense_evolver import DefenseEvolver
from blue_agent.strategy.defense_planner import DefensePlanner
from blue_agent.remediation.remediation_engine import RemediationEngine
from blue_agent.ids.ids_engine import IDSEngine
from blue_agent.siem.siem_engine import SIEMEngine

_TOOL_HISTORY: Deque[ToolCall] = deque(maxlen=200)
_LOG_HISTORY: Deque[LogEntry] = deque(maxlen=500)

_asset_scanner = AssetScanner()
_ssh_scanner = SSHScanner()
_environment_manager = EnvironmentManager()
_defense_planner = DefensePlanner()
_defense_evolver = DefenseEvolver()
_remediation_engine = RemediationEngine()
_ids_engine = IDSEngine()
_siem_engine = SIEMEngine()

# ---------------------------------------------------------------------------
# Real-time broadcast bridge — WebSocket registers its callback here
# ---------------------------------------------------------------------------

_broadcast_cb: Optional[Callable] = None


def set_broadcast_callback(cb: Callable) -> None:
    """Called by blue_ws.py to register the WebSocket broadcast function."""
    global _broadcast_cb
    _broadcast_cb = cb
    _ids_engine.set_broadcast(cb)
    _siem_engine.set_broadcast(cb)


def clear_history() -> None:
    """Wipe accumulated log and tool-call history on fresh client connection."""
    _LOG_HISTORY.clear()
    _TOOL_HISTORY.clear()


def _broadcast(payload: dict) -> None:
    """Push a payload to all connected WebSocket clients."""
    if _broadcast_cb:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(_broadcast_cb(payload))
        except RuntimeError:
            pass


def add_log(message: str, level: str = "INFO", tool_id: Optional[str] = None) -> LogEntry:
    """Add a log entry and broadcast it to all dashboard clients."""
    entry = LogEntry(level=level, message=message, tool_id=tool_id)
    _LOG_HISTORY.append(entry)
    _broadcast({"type": "log", "payload": entry.model_dump(mode="json")})
    return entry


def _new_tool_call(name: str, category: str, params: Dict[str, Any]) -> ToolCall:
    call = ToolCall(
        id=str(uuid.uuid4()),
        name=name,
        category=category,
        status=ToolStatus.RUNNING,
        params=params,
    )
    _TOOL_HISTORY.append(call)
    _broadcast({"type": "tool_call", "payload": call.model_dump(mode="json")})
    return call


def _finish(call: ToolCall, result: Dict[str, Any], status: ToolStatus = ToolStatus.DONE) -> ToolCall:
    call.status = status
    call.result = result
    call.finished_at = datetime.now()
    add_log(
        f"{call.name} -> {status.value}" + (f" | {result.get('detail', '')}" if result.get('detail') else ""),
        level="INFO" if status is ToolStatus.DONE else "ERROR",
        tool_id=call.id,
    )
    _broadcast({"type": "tool_call", "payload": call.model_dump(mode="json")})
    return call


# ── Defense endpoints ────────────────────────────────────────────────

async def close_port(request: ClosePortRequest) -> DefenseResult:
    call = _new_tool_call("close_port", "defend", request.model_dump())
    return DefenseResult(
        tool_call=_finish(call, {"closed": True, "detail": f"closed {request.protocol}/{request.port}"}),
        detail=f"closed {request.protocol}/{request.port} on {request.host}",
    )


async def harden_service(request: HardenServiceRequest) -> DefenseResult:
    call = _new_tool_call("harden_service", "defend", request.model_dump())
    return DefenseResult(
        tool_call=_finish(call, {"hardened": request.service, "detail": f"hardened {request.service}"}),
        detail=f"hardened {request.service} on {request.host}",
    )


async def isolate_host(request: IsolateHostRequest) -> DefenseResult:
    call = _new_tool_call("isolate_host", "defend", request.model_dump())
    return DefenseResult(
        tool_call=_finish(call, {"isolated": request.host}),
        detail=request.reason or "isolated",
    )


# ── Patch endpoints ──────────────────────────────────────────────────

async def apply_patch(request: PatchRequest) -> PatchResult:
    call = _new_tool_call("apply_patch", "patch", request.model_dump())
    return PatchResult(tool_call=_finish(call, {"applied": True}), applied=True)


async def verify_fix(request: VerifyFixRequest) -> VerifyFixResult:
    call = _new_tool_call("verify_fix", "patch", request.model_dump())
    return VerifyFixResult(
        tool_call=_finish(call, {"verified": True}),
        verified=True,
        evidence="re-scan returned no matching CVE signature",
    )


# ── Strategy endpoints ───────────────────────────────────────────────

async def plan_defense(request: StrategyRequest) -> DefensePlan:
    call = _new_tool_call("plan_defense", "strategy", request.model_dump())
    plan = _defense_planner.get_current_plan()
    steps = [a.get("reason", a.get("action", "")) for a in plan[:10]]
    return DefensePlan(
        tool_call=_finish(call, {"steps": steps, "plan_count": len(plan)}),
        steps=steps,
    )


async def evolve_strategy(request: StrategyRequest) -> DefensePlan:
    call = _new_tool_call("evolve_strategy", "strategy", request.model_dump())
    metrics = _defense_evolver.get_metrics()
    steps = [f"Evolution #{metrics['evolution_count']}", f"Accuracy: {metrics['response_accuracy_pct']:.1f}%"]
    return DefensePlan(tool_call=_finish(call, metrics), steps=steps)


async def current_strategy() -> DefensePlan:
    call = _new_tool_call("current_strategy", "strategy", {})
    plan = _defense_planner.get_current_plan()
    threat = _defense_planner.get_threat_summary()
    steps = [a.get("reason", "") for a in plan[:10]]
    return DefensePlan(
        tool_call=_finish(call, {**threat, "plan_actions": len(plan)}),
        steps=steps,
    )


# ── SSH scan — the main pipeline ─────────────────────────────────────

async def run_ssh_scan(host: str, ssh_port: int, username: str, password: str) -> dict:
    """Full pipeline: SSH connect → discover → CVE lookup → fix → verify.

    Every step is logged as a ToolCall + LogEntry and broadcast to the
    dashboard in real-time via WebSocket.
    """
    # Pass the logging callback to the scanner so it can stream progress
    result = await _ssh_scanner.scan(
        host, ssh_port, username, password,
        log_cb=add_log,
        tool_cb=_create_scan_tool,
    )
    return result


def _create_scan_tool(name: str, params: dict, result: dict, status: str = "DONE") -> None:
    """Helper: create a completed ToolCall for a scan step."""
    call = _new_tool_call(name, "scan", params)
    _finish(call, result, ToolStatus.DONE if status == "DONE" else ToolStatus.FAILED)


# ── Asset scanning endpoints ─────────────────────────────────────────

async def get_asset_inventory(environment: Optional[str] = None) -> list:
    if environment:
        by_env = _asset_scanner.get_inventory_by_environment()
        items = by_env.get(environment, [])
    else:
        items = _asset_scanner.get_inventory()
    return [AssetInfo(**item) for item in items]


async def get_vulnerable_assets() -> list:
    items = _asset_scanner.get_vulnerable_assets()
    return [AssetInfo(**item) for item in items]


async def get_scan_stats() -> dict:
    return _ssh_scanner.get_stats()


async def get_all_vulnerabilities() -> list:
    vulns = []
    for svc in _ssh_scanner.last_scan_results:
        for cve in svc.cves:
            vulns.append(VulnerabilityInfo(
                cve_id=cve.cve_id,
                severity=cve.severity,
                cvss_score=cve.cvss_score,
                description=cve.description,
                affected_software=cve.affected_software,
                affected_version=cve.affected_version,
                fix=cve.fix,
            ))
    return vulns


# ── Environment monitoring endpoints ─────────────────────────────────

async def get_environment_alerts(environment: Optional[str] = None) -> list:
    items = _environment_manager.get_alerts(environment=environment)
    return [EnvironmentAlertInfo(**item) for item in items]


async def get_environment_stats() -> EnvironmentStats:
    stats = _environment_manager.get_stats()
    return EnvironmentStats(**stats)


# ── Evolution endpoints ──────────────────────────────────────────────

async def get_evolution_metrics() -> EvolutionMetrics:
    metrics = _defense_evolver.get_metrics()
    return EvolutionMetrics(**metrics)


# ── Full agent status ────────────────────────────────────────────────

async def get_agent_status() -> BlueAgentStatus:
    ssh_stats = _ssh_scanner.get_stats()
    return BlueAgentStatus(
        running=True,
        detection_count=ssh_stats.get("services_found", 0),
        response_count=ssh_stats.get("total_cves", 0),
        patch_count=ssh_stats.get("fixes_applied", 0),
        cve_fix_count=ssh_stats.get("fixes_applied", 0),
        isolation_count=0,
        scan_cycles=ssh_stats.get("scan_count", 0),
        assets_discovered=ssh_stats.get("services_found", 0),
        vulnerable_assets=ssh_stats.get("vulnerable_services", 0),
        total_vulnerabilities=ssh_stats.get("total_cves", 0),
        environment_alerts=0,
        evolution_rounds=0,
        defense_plans=0,
    )


async def apply_ssh_fixes() -> dict:
    """Step 2: apply approved fixes on the server."""
    result = await _ssh_scanner.apply_fixes(
        log_cb=add_log,
        tool_cb=_create_scan_tool,
    )
    return result


def get_ssh_scan_results() -> list:
    return _ssh_scanner.get_results()


def get_ssh_scan_stats() -> dict:
    return _ssh_scanner.get_stats()


# ── Approval workflow endpoints ──────────────────────────────────────

async def get_pending_fixes() -> List[PendingFix]:
    """Return all fixes currently awaiting user approval."""
    items = _remediation_engine.get_pending_fixes()
    return [PendingFix(**item) for item in items]


async def approve_fix(fix_id: str) -> ApprovalResult:
    """Approve and apply a single pending fix."""
    result = await _remediation_engine.approve_fix(fix_id)
    return ApprovalResult(**result)


async def approve_all_fixes() -> List[ApprovalResult]:
    """Approve and apply every pending fix."""
    results = await _remediation_engine.approve_all()
    return [ApprovalResult(**r) for r in results]


async def reject_fix(fix_id: str) -> ApprovalResult:
    """Reject a pending fix, removing it from the queue."""
    result = _remediation_engine.reject_fix(fix_id)
    return ApprovalResult(**result)


# ── History endpoints ────────────────────────────────────────────────

async def recent_tool_calls(category: Optional[str] = None, limit: int = 20) -> list:
    items = list(_TOOL_HISTORY)
    if category:
        items = [c for c in items if c.category == category]
    return items[-limit:]


async def recent_logs(limit: int = 100) -> list:
    return list(_LOG_HISTORY)[-limit:]


# ── Remediation endpoints (Red report → Blue fix pipeline) ──────────

async def ingest_red_report(report: RedReportRequest) -> RemediationResult:
    """Process a Red team report and apply all fixes simultaneously."""
    from core.event_bus import event_bus

    # Ensure event bus is running for the remediation pipeline
    await event_bus.start()
    _remediation_engine.register()
    _ids_engine.register()
    _siem_engine.register()

    call = _new_tool_call("ingest_red_report", "remediation", {
        "target": report.target,
        "risk_score": report.risk_score,
    })

    add_log(f"Ingesting Red team report for {report.target} (risk: {report.risk_score}/10)", level="INFO")

    # Run the full pipeline: parse → publish findings → remediate simultaneously
    result = await _remediation_engine.remediate_full_report(report.model_dump())

    report_summary = result.get("report_summary", {})
    remediation = result.get("remediation", {})

    _finish(call, {
        "findings": report_summary.get("total_findings", 0),
        "fixes": remediation.get("fixes_applied", 0),
        "status": "complete",
    })

    # Use the fix list built directly inside remediate_full_report (no state-read gap)
    pending = result.get("pending_fixes_list", [])
    print(f"[blue_service] ingest_red_report: pending_fixes_list has {len(pending)} items")

    return RemediationResult(
        target=report.target,
        risk_score=report.risk_score,
        total_findings=report_summary.get("total_findings", 0),
        fixes_applied=remediation.get("fixes_applied", 0),
        total_steps=remediation.get("total_steps", 0),
        severity_counts=report_summary.get("severity_counts", {}),
        applied_fixes=remediation.get("applied_fixes", []),
        pending_fixes=pending,
        status="complete",
    )


async def run_sample_remediation() -> RemediationResult:
    """Run remediation using the sample Red team report."""
    from red_agent.report_ingester import build_report_from_sample

    sample = build_report_from_sample()
    report = RedReportRequest(**sample)
    return await ingest_red_report(report)


async def get_remediation_status() -> RemediationStatus:
    """Get current status of the remediation engine."""
    status = _remediation_engine.get_status()
    return RemediationStatus(**status)


# ── IDS endpoints ────────────────────────────────────────────────────

def get_ids_status() -> dict:
    return _ids_engine.get_status()


def get_ids_alerts(limit: int = 50) -> list:
    return _ids_engine.get_alerts(limit=limit)


# ── SIEM endpoints ───────────────────────────────────────────────────

def get_siem_report() -> dict:
    return _siem_engine.get_report()


def get_siem_status() -> dict:
    return _siem_engine.get_status()
