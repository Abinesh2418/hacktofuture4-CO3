"""Auth service – FastAPI app on port 8003.

Provides authentication, MFA, and score tracking for HTF Arena.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from auth_service.routes.auth_routes import router as auth_router
from auth_service.routes.score_routes import router as score_router

AUTH_API_PORT = 8003

app = FastAPI(title="HTF Arena Auth Service", version="1.0.0")

# CORS – allow the frontend dev servers
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:3001",
        "http://localhost:3002",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(score_router, tags=["scores"])


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "auth", "port": AUTH_API_PORT}
