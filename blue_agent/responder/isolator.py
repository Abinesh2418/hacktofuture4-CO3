"""Real-Time Response (Feature 2) — Isolate services or network segments under attack.

Subscribes to exploit_attempted and anomaly_detected events.
On trigger, immediately isolates the affected service or IP:
  - exploit_attempted → drop all inbound traffic to the service port
  - anomaly_detected  → drop all traffic from the offending source IP

Guaranteed to complete isolation in under 1 second of receiving the event.
Emits isolation_complete after each successful action.

All state is in-memory — no real OS or iptables changes.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, Set

from core.event_bus import event_bus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Simulated isolation state
# ---------------------------------------------------------------------------
_isolated_ports: Set[int] = set()
_isolated_ips: Set[str] = set()


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


class Isolator:
    """Isolates services and source IPs under active attack.

    Call register() once during system initialisation to wire subscriptions.
    All actions complete in < 1 second (simulated latency is 30 ms).
    Idempotent — isolating the same port or IP twice is a no-op.

    Emits:
        isolation_complete — after each successful isolation action
    """

    def __init__(self) -> None:
        self.isolation_count: int = 0

    # ------------------------------------------------------------------
    # Subscription wiring
    # ------------------------------------------------------------------

    def register(self) -> None:
        """Wire subscriptions to exploitation, anomaly, and web app attack events."""
        event_bus.subscribe("exploit_attempted", self._on_exploit_attempted)
        event_bus.subscribe("anomaly_detected", self._on_anomaly_detected)
        # Web application attacks also trigger isolation
        event_bus.subscribe("sql_injection_attempted", self._on_exploit_attempted)
        event_bus.subscribe("credential_attack_detected", self._on_anomaly_detected)
        event_bus.subscribe("directory_traversal_attempted", self._on_exploit_attempted)

    # ------------------------------------------------------------------
    # Internal simulation actions
    # ------------------------------------------------------------------

    async def _drop_inbound(self, port: int, protocol: str = "tcp") -> bool:
        """Simulate dropping all inbound traffic to a port (< 1 s)."""
        ts = _ts()
        params = {"port": port, "protocol": protocol}
        print(f"{ts} > isolator.drop_inbound({json.dumps(params)})")
        await asyncio.sleep(0.03)       # well under 1 second
        _isolated_ports.add(port)
        print(
            f"{ts} < isolator: Port {port}/{protocol} "
            f"\u2014 all inbound traffic DROPPED"
        )
        return True

    async def _drop_ip(self, source_ip: str) -> bool:
        """Simulate blocking all traffic from a source IP (< 1 s)."""
        ts = _ts()
        params = {"source_ip": source_ip}
        print(f"{ts} > isolator.drop_ip({json.dumps(params)})")
        await asyncio.sleep(0.03)
        _isolated_ips.add(source_ip)
        print(f"{ts} < isolator: {source_ip} \u2014 ISOLATED, all traffic blocked")
        return True

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    async def _on_exploit_attempted(
        self, event_type: str, data: Dict[str, Any]
    ) -> None:
        """exploit_attempted → drop inbound traffic to the attacked port."""
        port = data.get("port")
        service = data.get("service", "unknown")
        protocol = data.get("protocol", "tcp")

        if port is None:
            return
        if port in _isolated_ports:
            return  # already isolated — idempotent

        success = await self._drop_inbound(port, protocol)
        if success:
            self.isolation_count += 1
            ts = _ts()
            print(
                f"{ts} < isolator: Service '{service}' on port {port} "
                f"ISOLATED \u2713"
            )
            await event_bus.emit("isolation_complete", {
                "service": service,
                "port": port,
                "protocol": protocol,
                "action": "drop_inbound",
                "status": "ISOLATED",
            })

    async def _on_anomaly_detected(
        self, event_type: str, data: Dict[str, Any]
    ) -> None:
        """anomaly_detected → drop all traffic from the offending source IP."""
        source_ip = data.get("source_ip")
        anomaly_type = data.get("type", "unknown")

        if not source_ip:
            return
        if source_ip in _isolated_ips:
            return  # already isolated — idempotent

        success = await self._drop_ip(source_ip)
        if success:
            self.isolation_count += 1
            ts = _ts()
            print(
                f"{ts} < isolator: IP {source_ip} ISOLATED "
                f"(anomaly: {anomaly_type}) \u2713"
            )
            await event_bus.emit("isolation_complete", {
                "source_ip": source_ip,
                "anomaly_type": anomaly_type,
                "action": "drop_ip",
                "status": "ISOLATED",
            })
