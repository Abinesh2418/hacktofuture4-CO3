"""Score tracking routes – award points and view leaderboard."""

from __future__ import annotations

import datetime
from collections import deque
from typing import Deque, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()

# ---------------------------------------------------------------------------
# In-memory score store
# ---------------------------------------------------------------------------
red_score: int = 0
blue_score: int = 0
history: Deque[dict] = deque(maxlen=100)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AwardRequest(BaseModel):
    team: str  # "red" or "blue"
    points: int
    reason: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scores/award")
async def award_points(body: AwardRequest) -> dict:
    global red_score, blue_score

    team = body.team.lower()
    if team not in ("red", "blue"):
        raise HTTPException(status_code=400, detail="team must be 'red' or 'blue'")
    if body.points <= 0:
        raise HTTPException(status_code=400, detail="points must be positive")

    if team == "red":
        red_score += body.points
    else:
        blue_score += body.points

    entry = {
        "team": team,
        "points": body.points,
        "reason": body.reason,
        "timestamp": datetime.datetime.now().isoformat(),
    }
    history.appendleft(entry)

    return {
        "red_score": red_score,
        "blue_score": blue_score,
        "awarded": entry,
    }


@router.get("/scores")
async def get_scores() -> dict:
    return {
        "red_score": red_score,
        "blue_score": blue_score,
        "history": list(history),
    }


@router.get("/scores/leaderboard")
async def leaderboard() -> List[dict]:
    teams = [
        {"team": "red", "score": red_score},
        {"team": "blue", "score": blue_score},
    ]
    teams.sort(key=lambda t: t["score"], reverse=True)
    result: List[dict] = []
    for rank, t in enumerate(teams, start=1):
        result.append({"team": t["team"], "score": t["score"], "rank": rank})
    return result
