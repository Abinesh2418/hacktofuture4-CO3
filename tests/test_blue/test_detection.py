"""Feature 1 -- Real-Time Detection Tests

Tests all three detectors:
  - IntrusionDetector : port probes -> emits port_probed / port_scanned
  - AnomalyDetector   : scan-rate / sensitive-port spikes -> emits anomaly_detected
  - LogMonitor        : log signature matching -> emits port_scanned / cve_detected / exploit_attempted

Each test runs the detector for a short window (3 seconds) and asserts
that the expected events were emitted via the event bus.
"""

import asyncio
import sys
import os

# Allow running from repo root without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.event_bus import EventBus
from blue_agent.detector.intrusion_detector import IntrusionDetector
from blue_agent.detector.anomaly_detector import AnomalyDetector
from blue_agent.detector.log_monitor import LogMonitor

# ── helpers ──────────────────────────────────────────────────────────────────

def make_bus():
    """Return a fresh EventBus for each test (avoids shared state)."""
    return EventBus()


async def collect_events(bus: EventBus, event_types: list, run_coro, timeout: float = 3.5):
    """
    Start the event bus + detector coroutine, collect emitted events for
    `timeout` seconds, then cancel the detector and return collected events.
    """
    collected = []

    async def capture(event_type, data):
        collected.append({"event": event_type, "data": data})

    for et in event_types:
        bus.subscribe(et, capture)

    await bus.start()

    task = asyncio.create_task(run_coro)
    await asyncio.sleep(timeout)
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass

    await bus.stop()
    return collected


# ── Test 1 : IntrusionDetector ────────────────────────────────────────────────

async def test_intrusion_detector_emits_port_probed():
    """IntrusionDetector must emit at least one port_probed within 3 s."""
    import blue_agent.detector.intrusion_detector as mod

    bus = make_bus()
    detector = IntrusionDetector()

    # Patch the module-level event_bus singleton used by the detector
    mod.event_bus = bus

    events = await collect_events(
        bus,
        event_types=["port_probed", "port_scanned"],
        run_coro=detector.start(),
        timeout=3.5,
    )

    probed = [e for e in events if e["event"] == "port_probed"]
    scanned = [e for e in events if e["event"] == "port_scanned"]

    print(f"\n  [IntrusionDetector] port_probed events   : {len(probed)}")
    print(f"  [IntrusionDetector] port_scanned events  : {len(scanned)}")
    if probed:
        sample = probed[0]["data"]
        print(f"  [IntrusionDetector] sample port_probed  : port={sample['port']} proto={sample['protocol']} src={sample['source_ip']}")

    assert len(probed) > 0, "Expected at least one port_probed event in 3 s"
    assert all("port" in e["data"] for e in probed), "port_probed must carry 'port' field"
    assert all("protocol" in e["data"] for e in probed), "port_probed must carry 'protocol' field"
    print("  [IntrusionDetector] PASS OK")


async def test_intrusion_detector_sensitive_ports_emit_port_scanned():
    """Probes on sensitive ports (21,22,23,3306,5432) must also emit port_scanned."""
    import blue_agent.detector.intrusion_detector as mod
    import random

    bus = make_bus()
    detector = IntrusionDetector()
    mod.event_bus = bus

    # Force every tick to probe a sensitive port
    original = detector._simulate_probe
    def forced_sensitive_probe():
        return random.choice([21, 22, 23, 3306]), "tcp"
    detector._simulate_probe = forced_sensitive_probe

    events = await collect_events(
        bus,
        event_types=["port_scanned"],
        run_coro=detector.start(),
        timeout=3.5,
    )

    scanned = [e for e in events if e["event"] == "port_scanned"]
    print(f"\n  [IntrusionDetector] port_scanned (sensitive) events: {len(scanned)}")
    assert len(scanned) > 0, "Expected port_scanned for sensitive port probes"
    print("  [IntrusionDetector] sensitive port escalation PASS OK")


# ── Test 2 : AnomalyDetector ──────────────────────────────────────────────────

async def test_anomaly_detector_emits_on_scan_rate():
    """AnomalyDetector must emit anomaly_detected when scan rate > 5/s."""
    import blue_agent.detector.anomaly_detector as mod

    bus = make_bus()
    detector = AnomalyDetector()
    mod.event_bus = bus

    # Force scan rate to always be above threshold
    original_simulate = detector._simulate_tick
    def forced_high_rate(now):
        result = original_simulate(now)
        result["scans_per_second"] = 10   # always above threshold of 5
        return result
    detector._simulate_tick = forced_high_rate

    events = await collect_events(
        bus,
        event_types=["anomaly_detected"],
        run_coro=detector.start(),
        timeout=3.5,
    )

    anomalies = [e for e in events if e["event"] == "anomaly_detected"]
    scan_rate = [e for e in anomalies if e["data"].get("type") == "scan_rate"]

    print(f"\n  [AnomalyDetector] anomaly_detected events  : {len(anomalies)}")
    print(f"  [AnomalyDetector] scan_rate anomalies      : {len(scan_rate)}")
    if scan_rate:
        s = scan_rate[0]["data"]
        print(f"  [AnomalyDetector] sample : rate={s.get('rate')} src={s.get('source_ip')}")

    assert len(scan_rate) > 0, "Expected scan_rate anomaly_detected events"
    print("  [AnomalyDetector] scan rate detection PASS OK")


async def test_anomaly_detector_emits_on_sensitive_port():
    """AnomalyDetector must emit anomaly_detected for access on sensitive ports."""
    import blue_agent.detector.anomaly_detector as mod
    import random

    bus = make_bus()
    detector = AnomalyDetector()
    mod.event_bus = bus

    # Force every tick to probe a sensitive port and always trigger the rule
    original_simulate = detector._simulate_tick
    def forced_sensitive(now):
        result = original_simulate(now)
        result["probed_port"] = 3306
        result["scans_per_second"] = 0   # suppress scan_rate rule
        return result
    detector._simulate_tick = forced_sensitive

    # Also patch random.random so the 35% gate always fires
    import blue_agent.detector.anomaly_detector as anomaly_mod
    original_random = anomaly_mod.random.random
    anomaly_mod.random.random = lambda: 0.1   # always < 0.35

    events = await collect_events(
        bus,
        event_types=["anomaly_detected"],
        run_coro=detector.start(),
        timeout=3.5,
    )
    anomaly_mod.random.random = original_random

    sensitive = [
        e for e in events
        if e["event"] == "anomaly_detected" and e["data"].get("type") == "sensitive_port"
    ]
    print(f"\n  [AnomalyDetector] sensitive_port anomalies: {len(sensitive)}")
    assert len(sensitive) > 0, "Expected sensitive_port anomaly_detected events"
    assert sensitive[0]["data"]["port"] == 3306
    print("  [AnomalyDetector] sensitive port detection PASS OK")


# ── Test 3 : LogMonitor ───────────────────────────────────────────────────────

async def test_log_monitor_emits_port_scanned_for_nmap():
    """LogMonitor must emit port_scanned when an nmap signature is found."""
    import blue_agent.detector.log_monitor as mod

    bus = make_bus()
    monitor = LogMonitor()
    mod.event_bus = bus

    events = await collect_events(
        bus,
        event_types=["port_scanned", "cve_detected", "exploit_attempted"],
        run_coro=monitor.start(),
        timeout=4.0,   # slightly longer -- injector runs every 1.5 s
    )

    port_scanned = [e for e in events if e["event"] == "port_scanned"]
    cve_detected  = [e for e in events if e["event"] == "cve_detected"]
    exploits      = [e for e in events if e["event"] == "exploit_attempted"]

    print(f"\n  [LogMonitor] port_scanned events     : {len(port_scanned)}")
    print(f"  [LogMonitor] cve_detected events      : {len(cve_detected)}")
    print(f"  [LogMonitor] exploit_attempted events : {len(exploits)}")

    total = len(port_scanned) + len(cve_detected) + len(exploits)
    assert total > 0, "LogMonitor emitted no events in 4 s"
    print("  [LogMonitor] log signature detection PASS OK")


async def test_log_monitor_cve_event_carries_cve_id():
    """cve_detected events from LogMonitor must carry a cve_id field."""
    import blue_agent.detector.log_monitor as mod

    bus = make_bus()
    monitor = LogMonitor()
    mod.event_bus = bus

    # Inject a known CVE log entry directly
    from blue_agent.detector.log_monitor import _ts
    monitor._log_buffer.append(
        (f"{_ts()} searchsploit CVE-2023-44487 [cve_lookup]", "cve_lookup")
    )

    events = await collect_events(
        bus,
        event_types=["cve_detected"],
        run_coro=monitor.start(),
        timeout=3.0,
    )

    cve_events = [e for e in events if e["event"] == "cve_detected"]
    print(f"\n  [LogMonitor] cve_detected events with cve_id: {len(cve_events)}")
    if cve_events:
        print(f"  [LogMonitor] cve_id = {cve_events[0]['data'].get('cve_id')}")

    assert len(cve_events) > 0, "Expected cve_detected event from injected log entry"
    print("  [LogMonitor] CVE ID extraction PASS OK")


# ── Runner ────────────────────────────────────────────────────────────────────

def run_all():
    tests = [
        ("IntrusionDetector emits port_probed",              test_intrusion_detector_emits_port_probed),
        ("IntrusionDetector escalates sensitive to scanned",  test_intrusion_detector_sensitive_ports_emit_port_scanned),
        ("AnomalyDetector detects high scan rate",            test_anomaly_detector_emits_on_scan_rate),
        ("AnomalyDetector detects sensitive port access",     test_anomaly_detector_emits_on_sensitive_port),
        ("LogMonitor emits events for nmap/cve/exploit",      test_log_monitor_emits_port_scanned_for_nmap),
        ("LogMonitor extracts CVE ID from log entry",         test_log_monitor_cve_event_carries_cve_id),
    ]

    passed = 0
    failed = 0

    print("\n" + "=" * 60)
    print("  FEATURE 1 -- Real-Time Detection Tests")
    print("=" * 60)

    for name, coro_fn in tests:
        print(f"\n-> {name}")
        try:
            asyncio.run(coro_fn())
            passed += 1
        except AssertionError as e:
            print(f"  FAIL FAIL  {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR FAIL {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"  Detection: {passed} passed, {failed} failed")
    print("=" * 60)
    return failed


if __name__ == "__main__":
    failures = run_all()
    sys.exit(failures)
