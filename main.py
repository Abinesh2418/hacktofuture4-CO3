"""HTF root entry point.

Launches Red (8001), Blue (8002), and Auth (8003) FastAPI backends in parallel.
Frontends are started independently via npm run dev.
"""

from __future__ import annotations

import asyncio

import uvicorn

from auth_service.main import AUTH_API_PORT, app as auth_app
from blue_agent.backend.main import BLUE_API_PORT, app as blue_app
from red_agent.backend.main import RED_API_PORT, app as red_app


async def _serve(app, port: int) -> None:
    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()


async def main() -> None:
    await asyncio.gather(
        _serve(red_app, RED_API_PORT),
        _serve(blue_app, BLUE_API_PORT),
        _serve(auth_app, AUTH_API_PORT),
    )


if __name__ == "__main__":
    asyncio.run(main())
