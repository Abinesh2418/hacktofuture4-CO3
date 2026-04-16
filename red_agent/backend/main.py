"""FastAPI entry point for the Red Agent backend.

Runs on port 8001. Exposes REST routes for scan / exploit / strategy
operations plus a WebSocket channel that streams live tool-call logs to
the Red Team dashboard.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from red_agent.backend.routers import (
    chat_routes,
    exploit_routes,
    scan_routes,
    strategy_routes,
)
from red_agent.backend.routers import report_routes
from red_agent.backend.routers import cve_routes
from red_agent.backend.websocket import red_ws

RED_API_PORT = 8001


@asynccontextmanager
async def lifespan(app: FastAPI):
    import asyncio
    from red_agent.backend.websocket.red_ws import manager
    # Let the WS manager schedule broadcasts from CrewAI worker threads
    # onto the main loop (avoids "Lock bound to a different event loop").
    manager.bind_loop(asyncio.get_running_loop())
    yield


app = FastAPI(
    title="HTF Red Agent API",
    description="Backend for the Red (attacker) AI agent in the HTF simulation.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3001", "http://localhost:3002",
        "http://localhost:5173", "http://localhost:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(chat_routes.router, tags=["chat"])
app.include_router(scan_routes.router, prefix="/scan", tags=["scan"])
app.include_router(exploit_routes.router, prefix="/exploit", tags=["exploit"])
app.include_router(report_routes.router, prefix="/report", tags=["report"])
app.include_router(cve_routes.router)  # /cve/lookup — NVD proxy
app.include_router(strategy_routes.router, prefix="/strategy", tags=["strategy"])
app.include_router(red_ws.router, tags=["websocket"])


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    return {"status": "ok", "agent": "red"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "red_agent.backend.main:app",
        host="0.0.0.0",
        port=RED_API_PORT,
        reload=True,
    )
