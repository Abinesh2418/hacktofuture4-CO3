"""Remediation endpoints — Red report ingestion, fix pipeline, and approval workflow."""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, HTTPException

from blue_agent.backend.schemas.blue_schemas import (
    ApprovalResult,
    PendingFix,
    RedReportRequest,
    RemediationResult,
    RemediationStatus,
    ToolCall,
)
from blue_agent.backend.services import blue_service

router = APIRouter()


@router.post("/ingest-report", response_model=RemediationResult)
async def ingest_red_report(report: RedReportRequest) -> RemediationResult:
    """Receive a Red team pen-test report and trigger simultaneous remediation.

    The Blue Agent will parse each finding and apply fixes in real-time
    while the report is being processed.
    """
    return await blue_service.ingest_red_report(report)


@router.post("/run-sample", response_model=RemediationResult)
async def run_sample_remediation() -> RemediationResult:
    """Run the full remediation pipeline using the sample Red team report.

    Triggers the complete Red → Blue pipeline with the known findings
    from the 172.25.8.172:5000 pen-test.
    """
    return await blue_service.run_sample_remediation()


@router.get("/status", response_model=RemediationStatus)
async def remediation_status() -> RemediationStatus:
    """Get current remediation engine status."""
    return await blue_service.get_remediation_status()


@router.get("/recent", response_model=List[ToolCall])
async def recent_remediation_actions(limit: int = 20) -> List[ToolCall]:
    return await blue_service.recent_tool_calls(category="remediation", limit=limit)


# ── Approval workflow endpoints ─────────────────────────────────────


@router.get("/pending", response_model=List[PendingFix])
async def pending_fixes() -> List[PendingFix]:
    """Return all fixes currently awaiting user approval."""
    return await blue_service.get_pending_fixes()


@router.post("/approve/{fix_id}", response_model=ApprovalResult)
async def approve_fix(fix_id: str) -> ApprovalResult:
    """Approve and apply a single pending fix."""
    try:
        return await blue_service.approve_fix(fix_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/approve-all", response_model=List[ApprovalResult])
async def approve_all_fixes() -> List[ApprovalResult]:
    """Approve and apply all pending fixes at once."""
    return await blue_service.approve_all_fixes()


@router.post("/reject/{fix_id}", response_model=ApprovalResult)
async def reject_fix(fix_id: str) -> ApprovalResult:
    """Reject a pending fix, removing it from the queue."""
    try:
        return await blue_service.reject_fix(fix_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
