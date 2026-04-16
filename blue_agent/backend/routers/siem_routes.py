"""SIEM endpoints — correlated security report and event status."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter

from blue_agent.backend.services import blue_service

router = APIRouter()


@router.get("/report")
async def siem_report() -> Dict[str, Any]:
    """Full correlated SIEM report with attack timeline and risk score."""
    return blue_service.get_siem_report()


@router.get("/status")
async def siem_status() -> Dict[str, Any]:
    """Current SIEM engine status."""
    return blue_service.get_siem_status()
