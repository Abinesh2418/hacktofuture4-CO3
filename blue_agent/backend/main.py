"""FastAPI entry point for the Blue Agent backend.

Runs on port 8002. Exposes REST routes for defense / patch / strategy /
scan / environment operations plus a WebSocket channel that streams live
tool-call logs to the Blue Team dashboard.
"""

from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root so CVE_API_KEY etc. are available
_env_path = Path(__file__).resolve().parents[2] / ".env"
load_dotenv(_env_path)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from blue_agent.backend.routers import (
    defense_routes,
    environment_routes,
    ids_routes,
    patch_routes,
    remediation_routes,
    scan_routes,
    siem_routes,
    strategy_routes,
)
from blue_agent.backend.websocket import blue_ws

BLUE_API_PORT = 8002


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: place to wire up the BlueController, event bus, log monitors, etc.
    yield
    # Shutdown: close any open resources here.


app = FastAPI(
    title="HTF Blue Agent API",
    description="Backend for the Blue (defender) AI agent in the HTF simulation.",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3002", "http://localhost:5173", "http://localhost:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(defense_routes.router, prefix="/defend", tags=["defend"])
app.include_router(patch_routes.router, prefix="/patch", tags=["patch"])
app.include_router(strategy_routes.router, prefix="/strategy", tags=["strategy"])
app.include_router(scan_routes.router, prefix="/scan", tags=["scan"])
app.include_router(environment_routes.router, prefix="/environment", tags=["environment"])
app.include_router(remediation_routes.router, prefix="/remediate", tags=["remediation"])
app.include_router(ids_routes.router, prefix="/ids", tags=["ids"])
app.include_router(siem_routes.router, prefix="/siem", tags=["siem"])
app.include_router(blue_ws.router, tags=["websocket"])


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    return {"status": "ok", "agent": "blue"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "blue_agent.backend.main:app",
        host="0.0.0.0",
        port=BLUE_API_PORT,
        reload=True,
    )
