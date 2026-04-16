"""Top-level orchestrator for the Blue Agent.

Responsibilities:
  1. Start the EventBus worker.
  2. Register all event subscriptions (response_engine, isolator, auto_patcher,
     defense_planner, defense_evolver).
  3. Launch all subsystem loops concurrently via asyncio.gather():
       - 3 detector loops (intrusion, anomaly, log monitor)
       - Asset scanner (continuous version + CVE scanning)
       - Environment manager (cloud + onprem + hybrid monitoring)
       - Defense evolver (continuous learning loop)
  4. Emit blue_ready when everything is live.
  5. Expose get_status() with live counters for the FastAPI / WebSocket layer.

Concurrency guarantee:
  - All loops run in parallel — detection never waits for scanning or patching.
  - The full detect → respond → patch chain completes in under 3 seconds.
  - Asset scanning and environment monitoring run independently.
  - The evolver adapts parameters across all subsystems continuously.

Coverage:
  - Cloud, On-Premise, and Hybrid environments monitored simultaneously.
  - Web servers, databases, applications, frontends, system services scanned.

Continuous operation:
  - No periodic scheduling — all loops run continuously until stop().
  - Scan intervals tighten automatically under active threat (via evolver).
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
from blue_agent.scanner.asset_scanner import AssetScanner
from blue_agent.environment.environment_manager import EnvironmentManager
from blue_agent.strategy.defense_planner import DefensePlanner
from blue_agent.strategy.defense_evolver import DefenseEvolver

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

        # ── Scanner layer (NEW) ───────────────────────────────────────
        self.asset_scanner = AssetScanner()

        # ── Environment monitoring (NEW) ──────────────────────────────
        self.environment_manager = EnvironmentManager()

        # ── Strategy layer (NEW — fully implemented) ──────────────────
        self.defense_planner = DefensePlanner()
        self.defense_evolver = DefenseEvolver()

        self._running: bool = False

    # ------------------------------------------------------------------
    # Subscription wiring
    # ------------------------------------------------------------------

    def _wire_subscriptions(self) -> None:
        """Register every subsystem's event subscriptions before loops start.

        Subscription order matters for the detect → respond → patch chain:
          1. ResponseEngine subscribes to all detection events.
          2. Isolator subscribes to exploit_attempted + anomaly_detected.
          3. AutoPatcher subscribes to response_complete + vulnerability_found.
          4. DefensePlanner subscribes to vulnerability_found + environment_alert.
          5. DefenseEvolver subscribes to all terminal events for learning.
        """
        self.response_engine.register()
        self.isolator.register()
        self.auto_patcher.register()
        self.defense_planner.register()
        self.defense_evolver.register()

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
            "running": self._running,
            # Detection
            "detection_count": total_detections,
            "response_count": self.response_engine.response_count,
            "patch_count": self.auto_patcher.patch_count,
            "cve_fix_count": self.auto_patcher.cve_fix_count,
            "isolation_count": self.isolator.isolation_count,
            # Scanning
            "scan_cycles": self.asset_scanner.scan_count,
            "assets_discovered": self.asset_scanner.asset_count,
            "vulnerable_assets": self.asset_scanner.vulnerable_count,
            "total_vulnerabilities": self.asset_scanner.total_vulnerabilities,
            # Environment monitoring
            "environment_alerts": self.environment_manager.alert_count,
            # Evolution
            "evolution_rounds": self.defense_evolver.evolution_count,
            "defense_plans": self.defense_planner.plans_generated,
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
          4. Launch ALL loops concurrently (asyncio.gather):
             - 3 detector loops
             - Asset scanner (continuous)
             - Environment manager (cloud + onprem + hybrid)
             - Defense evolver (continuous learning)

        This coroutine blocks until all loops exit (i.e. stop() is called).
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
            f"{ts} < blue_controller: Event bus live \u2014 "
            f"response_engine, isolator, auto_patcher, planner, evolver subscribed"
        )
        print(
            f"{ts} < blue_controller: Launching continuous loops: "
            f"detection(3) + asset_scanner + env_manager(3) + evolver"
        )

        # 3. Announce readiness
        await event_bus.emit("blue_ready", {
            "message": "Blue Agent fully operational \u2014 continuous defense active (target: 172.25.8.172:5000)",
            "subsystems": [
                "intrusion_detector",
                "anomaly_detector",
                "log_monitor",
                "response_engine",
                "isolator",
                "auto_patcher",
                "asset_scanner",
                "environment_manager",
                "defense_planner",
                "defense_evolver",
            ],
            "environments": ["cloud", "onprem", "hybrid"],
            "primary_target": {
                "ip": "172.25.8.172",
                "port": 5000,
                "service": "Flask/Werkzeug 3.1.8",
                "endpoints": ["/login", "/search", "/profile"],
                "attack_vectors": [
                    "credential_bruteforce",
                    "sql_injection",
                    "directory_traversal",
                    "idor",
                ],
            },
        })

        ts = _ts()
        print(
            f"{ts} < blue_controller: \u2588 BLUE AGENT ONLINE \u2588 "
            f"Real-time detection, scanning, response, patching, and evolution ACTIVE"
        )
        print(
            f"{ts} < blue_controller: Monitoring: Cloud + On-Premise + Hybrid environments"
        )
        print(
            f"{ts} < blue_controller: Primary target: Flask/Werkzeug 3.1.8 @ 172.25.8.172:5000"
        )
        print(
            f"{ts} < blue_controller: Defending endpoints: /login /search /profile "
            f"(SQLi, brute-force, IDOR, traversal)"
        )

        # 4. Run ALL loops concurrently — none blocks the others.
        results = await asyncio.gather(
            # Detection loops
            self.intrusion_detector.start(),
            self.anomaly_detector.start(),
            self.log_monitor.start(),
            # Asset scanning (continuous version + CVE scanning)
            self.asset_scanner.start(),
            # Environment monitoring (cloud + onprem + hybrid)
            self.environment_manager.start(),
            # Defensive evolution (continuous learning)
            self.defense_evolver.start(),
            return_exceptions=True,
        )

        # Log any unexpected loop exits
        loop_names = [
            "intrusion_detector", "anomaly_detector", "log_monitor",
            "asset_scanner", "environment_manager", "defense_evolver",
        ]
        for name, result in zip(loop_names, results):
            if isinstance(result, Exception):
                logger.error(f"BlueController: {name} exited with error: {result}")

    async def stop(self) -> None:
        """Gracefully stop all loops and the event bus."""
        self._running = False
        await asyncio.gather(
            self.intrusion_detector.stop(),
            self.anomaly_detector.stop(),
            self.log_monitor.stop(),
            self.asset_scanner.stop(),
            self.environment_manager.stop(),
            self.defense_evolver.stop(),
            return_exceptions=True,
        )
        await event_bus.stop()
        ts = _ts()
        print(f"{ts} < blue_controller: Blue Agent stopped \u2014 all subsystems offline")
