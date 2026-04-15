"""Real-Time Detection (Feature 1) — Port scans and active probes.

Runs a continuous asyncio polling loop every 1 second watching the target
system for new port probes. Emits port_probed (and port_scanned for
sensitive ports) events via the event bus the moment a probe is detected.

Never blocks — the detection loop is a standalone coroutine that runs
concurrently alongside anomaly_detector and log_monitor.
"""

import asyncio
import logging
import random
from datetime import datetime
from typing import Set

from core.event_bus import event_bus

logger = logging.getLogger(__name__)

TARGET_IP = "192.168.1.100"

# Ports exposed by the simulated target system
TARGET_PORTS = [21, 22, 23, 80, 443, 3306, 8080, 8443, 3389, 5432]

# Sensitive ports that also trigger a port_scanned event (nmap-style sweep)
SENSITIVE_PORTS = {21, 22, 23, 3306, 5432}

# Chance Red probes a port on any given tick (70 %)
PROBE_PROBABILITY = 0.70


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


class IntrusionDetector:
    """Continuously polls for new port probes on the target system.

    Emits:
        port_probed  — for every detected probe
        port_scanned — additionally for sensitive ports (21, 22, 23, 3306, 5432)
    """

    def __init__(self) -> None:
        self._running: bool = False
        self.detection_count: int = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _simulate_probe(self) -> "tuple[int, str] | None":
        """Simulate Red agent probing the target.

        Returns (port, protocol) with PROBE_PROBABILITY, else None.
        """
        if random.random() < PROBE_PROBABILITY:
            port = random.choice(TARGET_PORTS)
            protocol = "udp" if port == 53 else "tcp"
            return port, protocol
        return None

    # ------------------------------------------------------------------
    # Detection loop
    # ------------------------------------------------------------------

    async def _detection_loop(self) -> None:
        """Main loop — ticks every 1 second. Never blocks other loops."""
        while self._running:
            try:
                result = self._simulate_probe()
                if result is not None:
                    port, protocol = result
                    source_ip = f"10.0.0.{random.randint(2, 254)}"
                    ts = _ts()

                    # Log detection
                    print(f"{ts} < intrusion_detector: Port {port} probe detected")
                    print(
                        f'{ts} > event_bus.emit("port_probed", '
                        f'{{"port": {port}, "protocol": "{protocol}"}})'
                    )

                    self.detection_count += 1
                    await event_bus.emit("port_probed", {
                        "port": port,
                        "protocol": protocol,
                        "source_ip": source_ip,
                        "target": TARGET_IP,
                    })

                    # Sensitive ports also fire port_scanned (nmap sweep behaviour)
                    if port in SENSITIVE_PORTS:
                        ts = _ts()
                        print(
                            f"{ts} < intrusion_detector: "
                            f"Port {port} is sensitive — escalating to port_scanned"
                        )
                        print(
                            f'{ts} > event_bus.emit("port_scanned", '
                            f'{{"port": {port}, "protocol": "{protocol}"}})'
                        )
                        await event_bus.emit("port_scanned", {
                            "port": port,
                            "protocol": protocol,
                            "source_ip": source_ip,
                            "target": TARGET_IP,
                        })

            except Exception as exc:
                logger.error(f"IntrusionDetector error: {exc}")

            await asyncio.sleep(1)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the detection loop (runs until stop() is called)."""
        self._running = True
        ts = _ts()
        print(
            f"{ts} < intrusion_detector: Detection loop started "
            f"— watching {TARGET_IP}"
        )
        await self._detection_loop()

    async def stop(self) -> None:
        """Signal the detection loop to exit on the next tick."""
        self._running = False
