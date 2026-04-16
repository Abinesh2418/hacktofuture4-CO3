from __future__ import annotations
"""Scan endpoints for the Red Agent."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from red_agent.backend.schemas.red_schemas import (
    ScanRequest,
    ScanResult,
    ToolCall,
)
from red_agent.backend.services import red_service

router = APIRouter()


class ReconRequest(BaseModel):
    target: str
    context: str | None = None


class ReconStartResponse(BaseModel):
    session_id: str
    status: str
    message: str


@router.post("/network", response_model=ScanResult)
async def scan_network(request: ScanRequest) -> ScanResult:
    try:
        return await red_service.run_network_scan(request)
    except Exception as exc:  # pragma: no cover - bubble to HTTP layer
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/web", response_model=ScanResult)
async def scan_web(request: ScanRequest) -> ScanResult:
    return await red_service.run_web_scan(request)


@router.post("/system", response_model=ScanResult)
async def scan_system(request: ScanRequest) -> ScanResult:
    return await red_service.run_system_scan(request)


@router.post("/cloud", response_model=ScanResult)
async def scan_cloud(request: ScanRequest) -> ScanResult:
    return await red_service.run_cloud_scan(request)


@router.get("/recent", response_model=list[ToolCall])
async def recent_scans(limit: int = 20) -> list[ToolCall]:
    return await red_service.recent_tool_calls(category="scan", limit=limit)


# ---------- Autonomous CrewAI recon agent ---------------------------------

@router.post("/recon", response_model=ReconStartResponse)
async def start_recon(request: ReconRequest) -> ReconStartResponse:
    """Kick off the autonomous CrewAI recon agent in the background."""
    session_id = await red_service.start_recon(
        target=request.target, context=request.context
    )
    return ReconStartResponse(
        session_id=session_id,
        status="started",
        message=(
            f"Recon started on {request.target}. "
            f"Poll /scan/recon/{session_id} for results."
        ),
    )


@router.get("/recon/sessions/all")
async def get_all_recon_sessions() -> dict:
    """Dashboard view over every recon session this process has seen."""
    return {"sessions": red_service.list_recon_sessions()}


@router.get("/recon/{session_id}")
async def get_recon_result(session_id: str) -> dict:
    """Poll for the result of a recon session."""
    if not red_service.has_recon_session(session_id):
        raise HTTPException(
            status_code=404, detail=f"Session {session_id} not found"
        )
    result = red_service.get_recon_result(session_id)
    if result is None:
        return {
            "session_id": session_id,
            "status": "running",
            "message": "Recon in progress...",
        }
    return result.to_dict()


@router.get("/recon/{session_id}/attack-vectors")
async def get_attack_vectors(session_id: str) -> dict:
    """Return only the attack vectors — used by the exploit agent."""
    result = red_service.get_recon_result(session_id)
    if result is None:
        return {"status": "running", "attack_vectors": []}
    return {
        "session_id": session_id,
        "status": result.status,
        "attack_vectors": result.attack_vectors,
        "risk_score": result.risk_score,
        "recommended_exploits": result.recommended_exploits,
    }
