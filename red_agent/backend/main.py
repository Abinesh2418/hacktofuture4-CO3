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
from red_agent.backend.websocket import red_ws

RED_API_PORT = 8001


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: place to wire up the RedController, event bus, CVE feed, etc.
    yield
    # Shutdown: close any open resources here.


app = FastAPI(
    title="HTF Red Agent API",
    description="Backend for the Red (attacker) AI agent in the HTF simulation.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(chat_routes.router, tags=["chat"])
app.include_router(scan_routes.router, prefix="/scan", tags=["scan"])
app.include_router(exploit_routes.router, prefix="/exploit", tags=["exploit"])
app.include_router(report_routes.router, prefix="/report", tags=["report"])
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
