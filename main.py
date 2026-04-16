"""HTF root entry point.

Launches the Blue (8002) FastAPI backend.
The Blue frontend is started independently from its own folder
via `npm run dev` (Blue on 5174).
"""

from __future__ import annotations

import asyncio

import uvicorn

from blue_agent.backend.main import BLUE_API_PORT, app as blue_app


async def _serve(app, port: int) -> None:
    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()


async def main() -> None:
    await _serve(blue_app, BLUE_API_PORT)


if __name__ == "__main__":
    asyncio.run(main())
