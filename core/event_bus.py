"""Async pub/sub event bus connecting agents and subsystems.

Red agent publishes events (recon.started, recon.complete, …). Blue agent,
internal services, and websocket broadcasters subscribe. Handlers never
break the publisher — any exception is caught and logged.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventBus:
    """Async pub/sub bus.

    Published events:
        recon.started     {session_id, target, timestamp}
        recon.cve_fetched {session_id, cve_count, cves}
        recon.tool_done   {session_id, tool, finding_count}
        recon.complete    {session_id, ...ReconResult}
        recon.failed      {session_id, error}
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callable[[dict], Any]]] = defaultdict(list)
        self._history: list[dict] = []

    async def publish(self, event_type: str, data: dict) -> None:
        event = {"type": event_type, "data": data, "timestamp": _utc_now()}
        self._history.append(event)
        logger.info("[EventBus] %s published", event_type)

        for handler in list(self._subscribers.get(event_type, [])):
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(data)
                else:
                    handler(data)
            except Exception as exc:  # noqa: BLE001
                logger.error("[EventBus] handler error for %s: %s", event_type, exc)

    def subscribe(self, event_type: str, handler: Callable[[dict], Any]) -> None:
        self._subscribers[event_type].append(handler)
        logger.info("[EventBus] subscribed to %s", event_type)

    def unsubscribe(self, event_type: str, handler: Callable[[dict], Any]) -> None:
        if handler in self._subscribers.get(event_type, []):
            self._subscribers[event_type].remove(handler)

    def get_history(self) -> list[dict]:
        return list(self._history)

    def clear_history(self) -> None:
        self._history.clear()


event_bus = EventBus()
