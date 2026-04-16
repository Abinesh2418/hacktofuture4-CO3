from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()


@router.get("/current")
async def current_strategy():
    return {"strategy": "autonomous", "status": "active"}
