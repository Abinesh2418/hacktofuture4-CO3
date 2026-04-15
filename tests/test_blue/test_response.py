"""Feature 2 -- Real-Time Response Tests

Tests the responder layer:
  - ResponseEngine : maps detection events -> close_port / isolate_service /
                     harden_service / block_ip, then emits response_complete
  - Isolator       : maps exploit_attempted / anomaly_detected ->
                     drop_inbound / drop_ip, then emits isolation_complete

Each test emits a detection event directly into a fresh EventBus and asserts
that the correct response event is produced within 2 seconds.
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.event_bus import EventBus


def make_bus():
    return EventBus()


async def emit_and_collect(bus: EventBus, trigger_event: str, trigger_data: dict,
                            listen_for: str, timeout: float = 2.0):
    """
    Start the bus, emit one trigger event, wait up to `timeout` seconds for
    a `listen_for` event, return all collected listen_for events.
    """
    collected = []

    async def capture(event_type, data):
        collected.append({"event": event_type, "data": data})

    bus.subscribe(listen_for, capture)
    await bus.start()

    await bus.emit(trigger_event, trigger_data)
    await asyncio.sleep(timeout)
    await bus.stop()
    return collected


# ── ResponseEngine tests ──────────────────────────────────────────────────────

async def test_response_engine_blocks_port_on_port_probed():
    """port_probed -> ResponseEngine must emit response_complete with status=BLOCKED."""
    import blue_agent.responder.response_engine as mod
    # Reset shared state for isolation
    mod._blocked_ports.clear()

    bus = make_bus()
    mod.event_bus = bus
    mod.TARGET_IP = "192.168.1.100"

    from blue_agent.responder.response_engine import ResponseEngine
    engine = ResponseEngine()
    engine.register()

    events = await emit_and_collect(
        bus,
        trigger_event="port_probed",
        trigger_data={"port": 3306, "protocol": "tcp", "source_ip": "10.0.0.5", "target": "192.168.1.100"},
        listen_for="response_complete",
        timeout=2.0,
    )

    print(f"\n  [ResponseEngine] response_complete events : {len(events)}")
    assert len(events) > 0, "Expected response_complete after port_probed"

    r = events[0]["data"]
    print(f"  [ResponseEngine] action={r['action']}  status={r['status']}  port={r.get('port')}")
    assert r["action"] == "close_port"
    assert r["status"] == "BLOCKED"
    assert r["port"] == 3306
    assert 3306 in mod._blocked_ports, "Port 3306 should be in blocked set"
    print("  [ResponseEngine] port block PASS OK")


async def test_response_engine_idempotent_on_same_port():
    """Emitting port_probed twice for the same port must only respond once."""
    import blue_agent.responder.response_engine as mod
    mod._blocked_ports.clear()

    bus = make_bus()
    mod.event_bus = bus

    from blue_agent.responder.response_engine import ResponseEngine
    engine = ResponseEngine()
    engine.register()

    await bus.start()
    await bus.emit("port_probed", {"port": 22, "protocol": "tcp", "source_ip": "10.0.0.1", "target": "192.168.1.100"})
    await bus.emit("port_probed", {"port": 22, "protocol": "tcp", "source_ip": "10.0.0.2", "target": "192.168.1.100"})
    await asyncio.sleep(2.0)
    await bus.stop()

    print(f"\n  [ResponseEngine] response_count after 2 identical events: {engine.response_count}")
    assert engine.response_count == 1, "Same port must only be responded to once (idempotent)"
    print("  [ResponseEngine] idempotency PASS OK")


async def test_response_engine_isolates_on_exploit_attempted():
    """exploit_attempted -> ResponseEngine must emit response_complete with status=ISOLATED."""
    import blue_agent.responder.response_engine as mod
    mod._isolated_services.clear()

    bus = make_bus()
    mod.event_bus = bus

    from blue_agent.responder.response_engine import ResponseEngine
    engine = ResponseEngine()
    engine.register()

    events = await emit_and_collect(
        bus,
        trigger_event="exploit_attempted",
        trigger_data={"service": "ftp", "port": 21, "source_ip": "10.0.0.7"},
        listen_for="response_complete",
        timeout=2.0,
    )

    print(f"\n  [ResponseEngine] response_complete (exploit) events: {len(events)}")
    assert len(events) > 0, "Expected response_complete after exploit_attempted"

    r = events[0]["data"]
    print(f"  [ResponseEngine] action={r['action']}  status={r['status']}  service={r.get('service')}")
    assert r["action"] == "isolate_service"
    assert r["status"] == "ISOLATED"
    print("  [ResponseEngine] exploit isolation PASS OK")


async def test_response_engine_hardens_on_cve_detected():
    """cve_detected -> ResponseEngine must emit response_complete with status=HARDENED."""
    import blue_agent.responder.response_engine as mod
    mod._hardened_services.clear()

    bus = make_bus()
    mod.event_bus = bus

    from blue_agent.responder.response_engine import ResponseEngine
    engine = ResponseEngine()
    engine.register()

    events = await emit_and_collect(
        bus,
        trigger_event="cve_detected",
        trigger_data={"service_name": "apache httpd", "port": 80, "cve_id": "CVE-2023-44487"},
        listen_for="response_complete",
        timeout=2.0,
    )

    print(f"\n  [ResponseEngine] response_complete (CVE) events: {len(events)}")
    assert len(events) > 0, "Expected response_complete after cve_detected"

    r = events[0]["data"]
    print(f"  [ResponseEngine] action={r['action']}  status={r['status']}  service={r.get('service')}")
    assert r["action"] == "harden_service"
    assert r["status"] == "HARDENED"
    print("  [ResponseEngine] CVE hardening PASS OK")


async def test_response_engine_blocks_ip_on_anomaly():
    """anomaly_detected -> ResponseEngine must emit response_complete with status=BLOCKED."""
    import blue_agent.responder.response_engine as mod
    mod._blocked_ips.clear()

    bus = make_bus()
    mod.event_bus = bus

    from blue_agent.responder.response_engine import ResponseEngine
    engine = ResponseEngine()
    engine.register()

    events = await emit_and_collect(
        bus,
        trigger_event="anomaly_detected",
        trigger_data={"type": "scan_rate", "rate": 9, "source_ip": "10.0.0.99"},
        listen_for="response_complete",
        timeout=2.0,
    )

    print(f"\n  [ResponseEngine] response_complete (anomaly) events: {len(events)}")
    assert len(events) > 0, "Expected response_complete after anomaly_detected"

    r = events[0]["data"]
    print(f"  [ResponseEngine] action={r['action']}  status={r['status']}  ip={r.get('source_ip')}")
    assert r["action"] == "block_ip"
    assert r["status"] == "BLOCKED"
    assert r["source_ip"] == "10.0.0.99"
    assert "10.0.0.99" in mod._blocked_ips
    print("  [ResponseEngine] IP block PASS OK")


# ── Isolator tests ────────────────────────────────────────────────────────────

async def test_isolator_drops_inbound_on_exploit():
    """exploit_attempted -> Isolator must emit isolation_complete with action=drop_inbound."""
    import blue_agent.responder.isolator as mod
    mod._isolated_ports.clear()
    mod._isolated_ips.clear()

    bus = make_bus()
    mod.event_bus = bus

    from blue_agent.responder.isolator import Isolator
    isolator = Isolator()
    isolator.register()

    events = await emit_and_collect(
        bus,
        trigger_event="exploit_attempted",
        trigger_data={"service": "mysql", "port": 3306, "protocol": "tcp"},
        listen_for="isolation_complete",
        timeout=2.0,
    )

    print(f"\n  [Isolator] isolation_complete events (exploit): {len(events)}")
    assert len(events) > 0, "Expected isolation_complete after exploit_attempted"

    r = events[0]["data"]
    print(f"  [Isolator] action={r['action']}  status={r['status']}  port={r.get('port')}")
    assert r["action"] == "drop_inbound"
    assert r["status"] == "ISOLATED"
    assert r["port"] == 3306
    assert 3306 in mod._isolated_ports
    print("  [Isolator] inbound drop PASS OK")


async def test_isolator_drops_ip_on_anomaly():
    """anomaly_detected -> Isolator must emit isolation_complete with action=drop_ip."""
    import blue_agent.responder.isolator as mod
    mod._isolated_ports.clear()
    mod._isolated_ips.clear()

    bus = make_bus()
    mod.event_bus = bus

    from blue_agent.responder.isolator import Isolator
    isolator = Isolator()
    isolator.register()

    events = await emit_and_collect(
        bus,
        trigger_event="anomaly_detected",
        trigger_data={"type": "traffic_spike", "source_ip": "10.0.0.55"},
        listen_for="isolation_complete",
        timeout=2.0,
    )

    print(f"\n  [Isolator] isolation_complete events (anomaly): {len(events)}")
    assert len(events) > 0, "Expected isolation_complete after anomaly_detected"

    r = events[0]["data"]
    print(f"  [Isolator] action={r['action']}  status={r['status']}  ip={r.get('source_ip')}")
    assert r["action"] == "drop_ip"
    assert r["status"] == "ISOLATED"
    assert r["source_ip"] == "10.0.0.55"
    assert "10.0.0.55" in mod._isolated_ips
    print("  [Isolator] IP isolation PASS OK")


async def test_isolator_completes_under_one_second():
    """Isolator must complete isolation in under 1 second."""
    import time
    import blue_agent.responder.isolator as mod
    mod._isolated_ports.clear()
    mod._isolated_ips.clear()

    bus = make_bus()
    mod.event_bus = bus

    from blue_agent.responder.isolator import Isolator
    isolator = Isolator()
    isolator.register()

    completed = []

    async def capture(event_type, data):
        completed.append(asyncio.get_event_loop().time())

    bus.subscribe("isolation_complete", capture)
    await bus.start()

    start = asyncio.get_event_loop().time()
    await bus.emit("exploit_attempted", {"service": "telnet", "port": 23, "protocol": "tcp"})
    await asyncio.sleep(1.5)
    await bus.stop()

    assert len(completed) > 0, "isolation_complete was never emitted"
    elapsed = completed[0] - start
    print(f"\n  [Isolator] isolation completed in {elapsed:.3f}s (must be < 1.0s)")
    assert elapsed < 1.0, f"Isolation took {elapsed:.3f}s -- must be under 1 second"
    print("  [Isolator] sub-1-second isolation PASS OK")


# ── Runner ────────────────────────────────────────────────────────────────────

def run_all():
    tests = [
        ("ResponseEngine blocks port on port_probed",         test_response_engine_blocks_port_on_port_probed),
        ("ResponseEngine is idempotent for same port",        test_response_engine_idempotent_on_same_port),
        ("ResponseEngine isolates service on exploit",        test_response_engine_isolates_on_exploit_attempted),
        ("ResponseEngine hardens service on CVE",             test_response_engine_hardens_on_cve_detected),
        ("ResponseEngine blocks IP on anomaly",               test_response_engine_blocks_ip_on_anomaly),
        ("Isolator drops inbound on exploit_attempted",       test_isolator_drops_inbound_on_exploit),
        ("Isolator drops IP on anomaly_detected",             test_isolator_drops_ip_on_anomaly),
        ("Isolator completes isolation in < 1 second",        test_isolator_completes_under_one_second),
    ]

    passed = 0
    failed = 0

    print("\n" + "=" * 60)
    print("  FEATURE 2 -- Real-Time Response Tests")
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
    print(f"  Response: {passed} passed, {failed} failed")
    print("=" * 60)
    return failed


if __name__ == "__main__":
    failures = run_all()
    sys.exit(failures)
