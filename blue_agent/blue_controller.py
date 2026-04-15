"""Top-level orchestrator for the Blue Agent.

Responsibilities:
  1. Start the EventBus worker.
  2. Register all event subscriptions (response_engine, isolator, auto_patcher).
  3. Launch all three detector loops concurrently via asyncio.gather().
  4. Emit blue_ready when everything is live.
  5. Expose get_status() with live counters for the FastAPI / WebSocket layer.

Concurrency guarantee:
  - All three detector loops run in parallel — detection never waits for
    patching to finish.
  - The full detect → respond → patch chain completes in under 3 seconds.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict

from core.event_bus import event_bus
from blue_agent.detector.intrusion_detector import IntrusionDetector
from blue_agent.detector.anomaly_detector import AnomalyDetector
from blue_agent.detector.log_monitor import LogMonitor
from blue_agent.responder.response_engine import ResponseEngine
from blue_agent.responder.isolator import Isolator
from blue_agent.patcher.auto_patcher import AutoPatcher

logger = logging.getLogger(__name__)


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


class BlueController:
    """Orchestrates all Blue Agent subsystems autonomously.

    Usage::

        controller = BlueController()
        await controller.start()   # blocks — runs until stop() is called

    get_status() can be called at any time from an external coroutine
    (e.g. the FastAPI service layer) to retrieve live counters.
    """

    def __init__(self) -> None:
        # ── Detector layer ────────────────────────────────────────────
        self.intrusion_detector = IntrusionDetector()
        self.anomaly_detector = AnomalyDetector()
        self.log_monitor = LogMonitor()

        # ── Responder layer ───────────────────────────────────────────
        self.response_engine = ResponseEngine()
        self.isolator = Isolator()

        # ── Patcher layer ─────────────────────────────────────────────
        self.auto_patcher = AutoPatcher()

        self._running: bool = False

    # ------------------------------------------------------------------
    # Subscription wiring
    # ------------------------------------------------------------------

    def _wire_subscriptions(self) -> None:
        """Register every subsystem's event subscriptions before loops start.

        Subscription order matters for the detect → respond → patch chain:
          1. ResponseEngine subscribes to all detection events.
          2. Isolator subscribes to exploit_attempted + anomaly_detected.
          3. AutoPatcher subscribes to response_complete.
        """
        self.response_engine.register()
        self.isolator.register()
        self.auto_patcher.register()

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        """Return live operational counters for dashboards and health checks."""
        total_detections = (
            self.intrusion_detector.detection_count
            + self.anomaly_detector.detection_count
            + self.log_monitor.detection_count
        )
        return {
            "detection_count": total_detections,
            "response_count": self.response_engine.response_count,
            "patch_count": self.auto_patcher.patch_count,
            "isolation_count": self.isolator.isolation_count,
            "running": self._running,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Initialise and start all subsystems.

        Steps:
          1. Start EventBus worker.
          2. Wire all event subscriptions.
          3. Emit blue_ready.
          4. Launch all three detector loops concurrently (asyncio.gather).

        This coroutine blocks until all detector loops exit (i.e. stop() is
        called) — run it as a background task from main.py if needed.
        """
        ts = _ts()
        print(f"{ts} < blue_controller: Initialising Blue Agent subsystems...")

        # 1. Event bus must be running before any subscriptions fire
        await event_bus.start()

        # 2. Wire subscriptions — must happen before detectors start emitting
        self._wire_subscriptions()
        self._running = True

        ts = _ts()
        print(
            f"{ts} < blue_controller: Event bus live — "
            f"response_engine, isolator, auto_patcher subscribed"
        )
        print(
            f"{ts} < blue_controller: Launching detection loops "
            f"(intrusion_detector + anomaly_detector + log_monitor)"
        )

        # 3. Announce readiness
        await event_bus.emit("blue_ready", {
            "message": "Blue Agent fully operational",
            "subsystems": [
                "intrusion_detector",
                "anomaly_detector",
                "log_monitor",
                "response_engine",
                "isolator",
                "auto_patcher",
            ],
        })

        ts = _ts()
        print(
            f"{ts} < blue_controller: \u2588 BLUE AGENT ONLINE \u2588 "
            f"Real-time detection, response, and patching ACTIVE"
        )

        # 4. Run all three detector loops concurrently — none blocks the others.
        #    return_exceptions=True prevents one crash from killing all loops.
        results = await asyncio.gather(
            self.intrusion_detector.start(),
            self.anomaly_detector.start(),
            self.log_monitor.start(),
            return_exceptions=True,
        )

        # Log any unexpected loop exits
        loop_names = ["intrusion_detector", "anomaly_detector", "log_monitor"]
        for name, result in zip(loop_names, results):
            if isinstance(result, Exception):
                logger.error(f"BlueController: {name} exited with error: {result}")

    async def stop(self) -> None:
        """Gracefully stop all detector loops and the event bus."""
        self._running = False
        await asyncio.gather(
            self.intrusion_detector.stop(),
            self.anomaly_detector.stop(),
            self.log_monitor.stop(),
            return_exceptions=True,
        )
        await event_bus.stop()
        ts = _ts()
        print(f"{ts} < blue_controller: Blue Agent stopped — all subsystems offline")
