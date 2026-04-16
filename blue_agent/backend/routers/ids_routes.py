"""IDS endpoints — intrusion alert status and alert history."""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter

from blue_agent.backend.services import blue_service

router = APIRouter()


@router.get("/status")
async def ids_status() -> Dict[str, Any]:
    """Current IDS engine status and alert summary."""
    return blue_service.get_ids_status()


@router.get("/alerts")
async def ids_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    """Recent IDS alerts (most recent first)."""
    alerts = blue_service.get_ids_alerts(limit=limit)
    return list(reversed(alerts))
