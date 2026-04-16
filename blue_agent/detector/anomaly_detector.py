"""Real-Time Detection (Feature 1) — Unusual traffic patterns and service behaviour.

Runs a continuous asyncio polling loop every 1 second.
Flags anomalies when:
  - More than 5 port scans per second are observed
  - Unexpected access occurs on sensitive ports (3306, 21, 23, 22)
  - A sudden traffic spike hits any single port

Emits anomaly_detected events via the event bus the instant a threshold
is crossed. Runs concurrently alongside intrusion_detector and log_monitor
and never blocks either of them.
"""

import asyncio
import logging
import random
from collections import deque
from datetime import datetime
from typing import Deque, Dict

from core.event_bus import event_bus

logger = logging.getLogger(__name__)

TARGET_IP = "172.25.8.172"
SENSITIVE_PORTS: set = {3306, 21, 23, 22, 5000}
SCAN_RATE_THRESHOLD = 5        # scans/second that trigger anomaly_detected
SPIKE_THRESHOLD = 8            # per-port hits/second that trigger a spike alert
SENSITIVE_ACCESS_CHANCE = 0.35  # probability per tick that a sensitive port is hit

# Web app anomaly thresholds (Flask @ port 5000)
LOGIN_ATTEMPT_THRESHOLD = 5     # failed logins/sec triggers credential_attack_detected
SQLI_PATTERN_CHANCE = 0.30      # probability of SQLi pattern per tick
PARAM_FUZZ_THRESHOLD = 10       # parameter variations/sec triggers anomaly


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


class AnomalyDetector:
    """Monitors simulated traffic metrics for behavioural anomalies.

    Emits:
        anomaly_detected — with type "scan_rate", "sensitive_port", or "traffic_spike"
    """

    def __init__(self) -> None:
        # Rolling window of scan timestamps for rate calculation
        self._scan_window: Deque[float] = deque(maxlen=200)
        # Per-port hit counters for the current second
        self._port_hits: Dict[int, int] = {}
        self._running: bool = False
        self.detection_count: int = 0
        # Web app anomaly tracking
        self._login_attempts: Deque[float] = deque(maxlen=100)
        self._param_variations: Deque[float] = deque(maxlen=200)

    # ------------------------------------------------------------------
    # Simulation helpers
    # ------------------------------------------------------------------

    def _simulate_tick(self, now: float) -> Dict:
        """Produce simulated traffic metrics for a single 1-second tick."""
        scans_this_tick = random.randint(0, 12)

        # Record each scan in the rolling window
        for _ in range(scans_this_tick):
            self._scan_window.append(now)

        # Count scans that occurred within the last 1 second
        scans_per_second = sum(1 for t in self._scan_window if now - t <= 1.0)

        # Pick a random port that Red is probing this tick
        probed_port = random.choice(
            [21, 22, 23, 80, 443, 3306, 5432, 8080]
        )
        source_ip = f"10.0.0.{random.randint(2, 254)}"

        # Increment per-port hit counter
        self._port_hits[probed_port] = self._port_hits.get(probed_port, 0) + scans_this_tick

        return {
            "scans_per_second": scans_per_second,
            "probed_port": probed_port,
            "source_ip": source_ip,
            "port_hits": self._port_hits.copy(),
        }

    # ------------------------------------------------------------------
    # Detection loop
    # ------------------------------------------------------------------

    async def _detection_loop(self) -> None:
        """Main loop — ticks every 1 second. Non-blocking."""
        while self._running:
            try:
                now = asyncio.get_event_loop().time()
                metrics = self._simulate_tick(now)
                ts = _ts()

                # ── Rule 1: Scan rate threshold ──────────────────────────
                if metrics["scans_per_second"] > SCAN_RATE_THRESHOLD:
                    rate = metrics["scans_per_second"]
                    src = metrics["source_ip"]
                    print(
                        f"{ts} < anomaly_detector: Scan rate {rate}/s exceeds "
                        f"threshold ({SCAN_RATE_THRESHOLD}/s) from {src}"
                    )
                    print(
                        f'{ts} > event_bus.emit("anomaly_detected", '
                        f'{{"type": "scan_rate", "rate": {rate}, '
                        f'"source_ip": "{src}"}})'
                    )
                    self.detection_count += 1
                    await event_bus.emit("anomaly_detected", {
                        "type": "scan_rate",
                        "rate": rate,
                        "source_ip": src,
                        "target": TARGET_IP,
                    })

                # ── Rule 2: Unexpected access on sensitive port ───────────
                port = metrics["probed_port"]
                if port in SENSITIVE_PORTS and random.random() < SENSITIVE_ACCESS_CHANCE:
                    src = metrics["source_ip"]
                    ts = _ts()
                    print(
                        f"{ts} < anomaly_detector: Unexpected access on "
                        f"sensitive port {port} from {src}"
                    )
                    print(
                        f'{ts} > event_bus.emit("anomaly_detected", '
                        f'{{"type": "sensitive_port", "port": {port}, '
                        f'"source_ip": "{src}"}})'
                    )
                    self.detection_count += 1
                    await event_bus.emit("anomaly_detected", {
                        "type": "sensitive_port",
                        "port": port,
                        "source_ip": src,
                        "target": TARGET_IP,
                    })

                # ── Rule 3: Per-port traffic spike ───────────────────────
                for p, hits in metrics["port_hits"].items():
                    if hits > SPIKE_THRESHOLD:
                        src = metrics["source_ip"]
                        ts = _ts()
                        print(
                            f"{ts} < anomaly_detector: Traffic spike on port {p} "
                            f"— {hits} hits detected"
                        )
                        print(
                            f'{ts} > event_bus.emit("anomaly_detected", '
                            f'{{"type": "traffic_spike", "port": {p}, '
                            f'"hits": {hits}, "source_ip": "{src}"}})'
                        )
                        self.detection_count += 1
                        await event_bus.emit("anomaly_detected", {
                            "type": "traffic_spike",
                            "port": p,
                            "hits": hits,
                            "source_ip": src,
                            "target": TARGET_IP,
                        })
                        # Reset after alerting so we don't spam the same spike
                        self._port_hits[p] = 0

                # ── Rule 4: Login brute-force on Flask /login ────────────
                login_burst = random.randint(0, 8)
                for _ in range(login_burst):
                    self._login_attempts.append(now)
                logins_per_sec = sum(1 for t in self._login_attempts if now - t <= 1.0)
                if logins_per_sec > LOGIN_ATTEMPT_THRESHOLD:
                    src = metrics["source_ip"]
                    ts = _ts()
                    print(
                        f"{ts} < anomaly_detector: Credential brute-force detected "
                        f"— {logins_per_sec} login attempts/s on /login from {src}"
                    )
                    self.detection_count += 1
                    await event_bus.emit("credential_attack_detected", {
                        "type": "login_bruteforce",
                        "endpoint": "/login",
                        "attempts_per_sec": logins_per_sec,
                        "port": 5000,
                        "service": "flask",
                        "source_ip": src,
                        "target": TARGET_IP,
                    })

                # ── Rule 5: SQL injection pattern on Flask /search ───────
                if random.random() < SQLI_PATTERN_CHANCE:
                    src = metrics["source_ip"]
                    sqli_payloads = [
                        "' OR 1=1--", "'; DROP TABLE users;--",
                        "' UNION SELECT * FROM users--", "1' AND '1'='1",
                        "admin'--", "' OR ''='",
                    ]
                    payload = random.choice(sqli_payloads)
                    ts = _ts()
                    print(
                        f"{ts} < anomaly_detector: SQLi pattern detected "
                        f"on /search?q={payload} from {src}"
                    )
                    self.detection_count += 1
                    await event_bus.emit("sql_injection_attempted", {
                        "type": "sqli_pattern",
                        "endpoint": "/search",
                        "payload": payload,
                        "port": 5000,
                        "service": "flask",
                        "source_ip": src,
                        "target": TARGET_IP,
                    })

                # ── Rule 6: IDOR / Directory traversal on /profile ───────
                if random.random() < 0.25:
                    src = metrics["source_ip"]
                    traversal_payloads = [
                        "../../etc/passwd", "../../../etc/shadow",
                        "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
                    ]
                    idor_ids = ["-1", "0", "999999", "1 OR 1=1"]
                    if random.random() < 0.5:
                        payload = random.choice(traversal_payloads)
                        ts = _ts()
                        print(
                            f"{ts} < anomaly_detector: Directory traversal attempt "
                            f"on /profile?id={payload} from {src}"
                        )
                        self.detection_count += 1
                        await event_bus.emit("directory_traversal_attempted", {
                            "type": "path_traversal",
                            "endpoint": "/profile",
                            "payload": payload,
                            "port": 5000,
                            "service": "flask",
                            "source_ip": src,
                            "target": TARGET_IP,
                        })
                    else:
                        idor_id = random.choice(idor_ids)
                        ts = _ts()
                        print(
                            f"{ts} < anomaly_detector: IDOR attempt "
                            f"on /profile?id={idor_id} from {src}"
                        )
                        self.detection_count += 1
                        await event_bus.emit("idor_attempted", {
                            "type": "idor",
                            "endpoint": "/profile",
                            "payload": idor_id,
                            "port": 5000,
                            "service": "flask",
                            "source_ip": src,
                            "target": TARGET_IP,
                        })

            except Exception as exc:
                logger.error(f"AnomalyDetector error: {exc}")

            await asyncio.sleep(1)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the anomaly detection loop (runs until stop() is called)."""
        self._running = True
        ts = _ts()
        print(
            f"{ts} < anomaly_detector: Anomaly detection loop started "
            f"— threshold {SCAN_RATE_THRESHOLD} scans/s, "
            f"sensitive ports {sorted(SENSITIVE_PORTS)}"
        )
        await self._detection_loop()

    async def stop(self) -> None:
        """Signal the detection loop to exit on the next tick."""
        self._running = False
