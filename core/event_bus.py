"""Pub/sub event bus — central nervous system connecting all Blue Agent subsystems.

Event delivery order is guaranteed: detect → respond → patch.
Uses asyncio.Queue internally to buffer bursts without dropping events.
Supports multiple subscribers per event type.
"""

import asyncio
import logging
from collections import defaultdict
from typing import Any, Callable, Dict, List

logger = logging.getLogger(__name__)

VALID_EVENT_TYPES = {
    "port_scanned",
    "port_probed",
    "exploit_attempted",
    "cve_detected",
    "anomaly_detected",
    "misconfig_found",
    "response_complete",
    "patch_complete",
    "isolation_complete",
    "blue_ready",
    # Web application attack events (Flask/Werkzeug target)
    "webapp_attack_detected",
    "sql_injection_attempted",
    "credential_attack_detected",
    "directory_traversal_attempted",
    "idor_attempted",
}


class EventBus:
    """Fully async pub/sub event bus with ordered delivery guarantee.

    All emit() calls are non-blocking — events are queued and dispatched
    sequentially by a single worker task, preserving detect → respond → patch
    ordering while never dropping events under high Red-agent load.
    """

    def __init__(self) -> None:
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._queue: asyncio.Queue = asyncio.Queue()
        self._running: bool = False
        self._worker_task: "asyncio.Task | None" = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def subscribe(self, event_type: str, handler: Callable) -> None:
        """Register an async handler for a specific event type.

        Multiple handlers per event type are fully supported.
        Handlers are called in registration order.
        """
        self._subscribers[event_type].append(handler)
        logger.debug(
            f"EventBus: subscribed '{handler.__qualname__}' to '{event_type}'"
        )

    async def emit(self, event_type: str, data: "Dict[str, Any] | None" = None) -> None:
        """Queue an event for ordered delivery.

        Never blocks the caller — the event is placed in the internal Queue
        and dispatched asynchronously by the worker.
        """
        if data is None:
            data = {}
        await self._queue.put((event_type, data))

    async def start(self) -> None:
        """Start the background event-processing worker."""
        if self._running:
            return
        self._running = True
        self._worker_task = asyncio.create_task(
            self._process_events(), name="event_bus_worker"
        )
        logger.info("EventBus: worker started")

    async def stop(self) -> None:
        """Drain the queue and stop the worker gracefully."""
        self._running = False
        try:
            await asyncio.wait_for(self._queue.join(), timeout=2.0)
        except asyncio.TimeoutError:
            pass
        if self._worker_task and not self._worker_task.done():
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info("EventBus: worker stopped")

    # ------------------------------------------------------------------
    # Internal worker
    # ------------------------------------------------------------------

    async def _process_events(self) -> None:
        """Worker loop: dequeue and dispatch events in FIFO order.

        Each event's handlers are awaited sequentially so that the
        detect → respond → patch chain is never interleaved.
        """
        while self._running:
            try:
                event_type, data = await asyncio.wait_for(
                    self._queue.get(), timeout=0.1
                )
                handlers = self._subscribers.get(event_type, [])
                for handler in handlers:
                    try:
                        await handler(event_type, data)
                    except Exception as exc:
                        logger.error(
                            f"EventBus: handler '{handler.__qualname__}' "
                            f"raised on '{event_type}': {exc}"
                        )
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(f"EventBus: worker error: {exc}")


# ---------------------------------------------------------------------------
# Module-level singleton — import this everywhere
# ---------------------------------------------------------------------------
event_bus = EventBus()
