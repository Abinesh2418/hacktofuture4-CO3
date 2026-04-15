"""Feature 3 -- Real-Time Patching Tests

Tests the AutoPatcher:
  - Subscribes to response_complete events
  - Applies the correct patch per service (apache, mysql, ftp, telnet, ssh, postgresql)
  - Emits patch_complete after each patch
  - Is fully idempotent -- same service:port is never patched twice
  - Resolves service by name, port, or partial match
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
    collected = []

    async def capture(event_type, data):
        collected.append({"event": event_type, "data": data})

    bus.subscribe(listen_for, capture)
    await bus.start()
    await bus.emit(trigger_event, trigger_data)
    await asyncio.sleep(timeout)
    await bus.stop()
    return collected


def reset_patcher_state():
    """Clear module-level patch tracking between tests."""
    import blue_agent.patcher.auto_patcher as mod
    mod._applied_patches.clear()


# ── Patch catalogue tests ─────────────────────────────────────────────────────

async def test_patcher_patches_apache_on_port_80():
    """response_complete for apache httpd -> patch_complete with action=patch."""
    import blue_agent.patcher.auto_patcher as mod
    reset_patcher_state()
    bus = make_bus()
    mod.event_bus = bus

    from blue_agent.patcher.auto_patcher import AutoPatcher
    patcher = AutoPatcher()
    patcher.register()

    events = await emit_and_collect(
        bus,
        trigger_event="response_complete",
        trigger_data={"action": "close_port", "service": "apache httpd", "port": 80, "status": "BLOCKED"},
        listen_for="patch_complete",
        timeout=2.0,
    )

    print(f"\n  [AutoPatcher] patch_complete events (apache): {len(events)}")
    assert len(events) > 0, "Expected patch_complete for apache httpd"

    r = events[0]["data"]
    print(f"  [AutoPatcher] service={r['service']}  action={r['action']}  status={r['status']}")
    print(f"  [AutoPatcher] steps applied: {len(r['steps_applied'])}")
    for step in r["steps_applied"]:
        print(f"    • {step}")

    assert r["service"] == "apache httpd"
    assert r["action"] == "patch"
    assert r["status"] == "PATCHED"
    assert len(r["steps_applied"]) > 0
    print("  [AutoPatcher] apache httpd patch PASS OK")


async def test_patcher_patches_mysql_on_port_3306():
    """response_complete for mysql / port 3306 -> patch_complete with action=bind_local."""
    import blue_agent.patcher.auto_patcher as mod
    reset_patcher_state()
    bus = make_bus()
    mod.event_bus = bus

    from blue_agent.patcher.auto_patcher import AutoPatcher
    patcher = AutoPatcher()
    patcher.register()

    events = await emit_and_collect(
        bus,
        trigger_event="response_complete",
        trigger_data={"action": "close_port", "service": "mysql", "port": 3306, "status": "BLOCKED"},
        listen_for="patch_complete",
        timeout=2.0,
    )

    print(f"\n  [AutoPatcher] patch_complete events (mysql): {len(events)}")
    assert len(events) > 0, "Expected patch_complete for mysql"

    r = events[0]["data"]
    print(f"  [AutoPatcher] service={r['service']}  action={r['action']}  status={r['status']}")
    for step in r["steps_applied"]:
        print(f"    • {step}")

    assert r["service"] == "mysql"
    assert r["action"] == "bind_local"
    assert r["status"] == "PATCHED"
    print("  [AutoPatcher] mysql patch PASS OK")


async def test_patcher_removes_telnet_on_port_23():
    """response_complete for telnet / port 23 -> patch_complete with action=remove_service."""
    import blue_agent.patcher.auto_patcher as mod
    reset_patcher_state()
    bus = make_bus()
    mod.event_bus = bus

    from blue_agent.patcher.auto_patcher import AutoPatcher
    patcher = AutoPatcher()
    patcher.register()

    events = await emit_and_collect(
        bus,
        trigger_event="response_complete",
        trigger_data={"action": "close_port", "service": "telnet", "port": 23, "status": "BLOCKED"},
        listen_for="patch_complete",
        timeout=2.0,
    )

    print(f"\n  [AutoPatcher] patch_complete events (telnet): {len(events)}")
    assert len(events) > 0, "Expected patch_complete for telnet"

    r = events[0]["data"]
    print(f"  [AutoPatcher] service={r['service']}  action={r['action']}  status={r['status']}")
    for step in r["steps_applied"]:
        print(f"    • {step}")

    assert r["service"] == "telnet"
    assert r["action"] == "remove_service"
    assert r["status"] == "PATCHED"
    print("  [AutoPatcher] telnet removal PASS OK")


async def test_patcher_disables_anon_ftp_on_port_21():
    """response_complete for ftp / port 21 -> patch_complete with action=disable_anon."""
    import blue_agent.patcher.auto_patcher as mod
    reset_patcher_state()
    bus = make_bus()
    mod.event_bus = bus

    from blue_agent.patcher.auto_patcher import AutoPatcher
    patcher = AutoPatcher()
    patcher.register()

    events = await emit_and_collect(
        bus,
        trigger_event="response_complete",
        trigger_data={"action": "close_port", "service": "ftp", "port": 21, "status": "BLOCKED"},
        listen_for="patch_complete",
        timeout=2.0,
    )

    print(f"\n  [AutoPatcher] patch_complete events (ftp): {len(events)}")
    assert len(events) > 0, "Expected patch_complete for ftp"

    r = events[0]["data"]
    print(f"  [AutoPatcher] service={r['service']}  action={r['action']}  status={r['status']}")
    for step in r["steps_applied"]:
        print(f"    • {step}")

    assert r["service"] == "ftp"
    assert r["action"] == "disable_anon"
    assert r["status"] == "PATCHED"
    print("  [AutoPatcher] ftp anonymous disable PASS OK")


async def test_patcher_hardens_ssh_on_port_22():
    """response_complete for ssh / port 22 -> patch_complete with action=harden."""
    import blue_agent.patcher.auto_patcher as mod
    reset_patcher_state()
    bus = make_bus()
    mod.event_bus = bus

    from blue_agent.patcher.auto_patcher import AutoPatcher
    patcher = AutoPatcher()
    patcher.register()

    events = await emit_and_collect(
        bus,
        trigger_event="response_complete",
        trigger_data={"action": "close_port", "service": "ssh", "port": 22, "status": "BLOCKED"},
        listen_for="patch_complete",
        timeout=2.0,
    )

    print(f"\n  [AutoPatcher] patch_complete events (ssh): {len(events)}")
    assert len(events) > 0, "Expected patch_complete for ssh"

    r = events[0]["data"]
    print(f"  [AutoPatcher] service={r['service']}  action={r['action']}  status={r['status']}")
    for step in r["steps_applied"]:
        print(f"    • {step}")

    assert r["service"] == "ssh"
    assert r["action"] == "harden"
    print("  [AutoPatcher] ssh harden PASS OK")


# ── Idempotency test ──────────────────────────────────────────────────────────

async def test_patcher_is_idempotent():
    """Sending response_complete twice for the same service:port patches only once."""
    import blue_agent.patcher.auto_patcher as mod
    reset_patcher_state()
    bus = make_bus()
    mod.event_bus = bus

    from blue_agent.patcher.auto_patcher import AutoPatcher
    patcher = AutoPatcher()
    patcher.register()

    collected = []

    async def capture(event_type, data):
        collected.append(data)

    bus.subscribe("patch_complete", capture)
    await bus.start()

    # Emit the same response_complete twice
    payload = {"action": "close_port", "service": "mysql", "port": 3306, "status": "BLOCKED"}
    await bus.emit("response_complete", payload)
    await asyncio.sleep(1.0)
    await bus.emit("response_complete", payload)
    await asyncio.sleep(1.5)
    await bus.stop()

    print(f"\n  [AutoPatcher] patch_complete events after 2 identical triggers: {len(collected)}")
    assert len(collected) == 1, f"Expected 1 patch but got {len(collected)} -- idempotency broken"
    assert patcher.patch_count == 1
    print("  [AutoPatcher] idempotency PASS OK")


# ── Port-based resolution test ────────────────────────────────────────────────

async def test_patcher_resolves_service_from_port():
    """AutoPatcher must resolve service from port when service name is missing."""
    import blue_agent.patcher.auto_patcher as mod
    reset_patcher_state()
    bus = make_bus()
    mod.event_bus = bus

    from blue_agent.patcher.auto_patcher import AutoPatcher
    patcher = AutoPatcher()
    patcher.register()

    # No service name -- only port 23 (should resolve to telnet)
    events = await emit_and_collect(
        bus,
        trigger_event="response_complete",
        trigger_data={"action": "close_port", "port": 23, "status": "BLOCKED"},
        listen_for="patch_complete",
        timeout=2.0,
    )

    print(f"\n  [AutoPatcher] port-only resolution (port 23): {len(events)} event(s)")
    assert len(events) > 0, "Expected patch_complete when service resolved from port 23"

    r = events[0]["data"]
    print(f"  [AutoPatcher] resolved service={r['service']}  action={r['action']}")
    assert r["service"] == "telnet"
    print("  [AutoPatcher] port-based service resolution PASS OK")


# ── Full chain test ───────────────────────────────────────────────────────────

async def test_full_detect_respond_patch_chain():
    """End-to-end: port_probed -> response_complete -> patch_complete in < 3 s."""
    import blue_agent.responder.response_engine as re_mod
    import blue_agent.patcher.auto_patcher as ap_mod

    re_mod._blocked_ports.clear()
    re_mod._isolated_services.clear()
    re_mod._hardened_services.clear()
    re_mod._blocked_ips.clear()
    ap_mod._applied_patches.clear()

    bus = make_bus()
    re_mod.event_bus = bus
    ap_mod.event_bus = bus

    from blue_agent.responder.response_engine import ResponseEngine
    from blue_agent.patcher.auto_patcher import AutoPatcher

    engine = ResponseEngine()
    patcher = AutoPatcher()
    engine.register()
    patcher.register()

    patch_events = []
    timestamps = {}

    async def on_patch(event_type, data):
        patch_events.append(data)
        timestamps["patch"] = asyncio.get_event_loop().time()

    bus.subscribe("patch_complete", on_patch)
    await bus.start()

    timestamps["start"] = asyncio.get_event_loop().time()
    await bus.emit("port_probed", {
        "port": 21,
        "protocol": "tcp",
        "source_ip": "10.0.0.77",
        "target": "192.168.1.100",
    })

    await asyncio.sleep(3.5)
    await bus.stop()

    print(f"\n  [Full Chain] patch_complete events received: {len(patch_events)}")
    assert len(patch_events) > 0, "patch_complete never emitted -- chain is broken"

    elapsed = timestamps["patch"] - timestamps["start"]
    print(f"  [Full Chain] detect -> respond -> patch completed in {elapsed:.3f}s")
    assert elapsed < 3.0, f"Full chain took {elapsed:.3f}s -- must be under 3 seconds"

    r = patch_events[0]
    print(f"  [Full Chain] service={r['service']}  action={r['action']}  status={r['status']}")
    print("  [Full Chain] end-to-end chain PASS OK")


# ── Runner ────────────────────────────────────────────────────────────────────

def run_all():
    tests = [
        ("AutoPatcher patches apache httpd (port 80)",        test_patcher_patches_apache_on_port_80),
        ("AutoPatcher patches mysql (port 3306)",             test_patcher_patches_mysql_on_port_3306),
        ("AutoPatcher removes telnet (port 23)",              test_patcher_removes_telnet_on_port_23),
        ("AutoPatcher disables anonymous FTP (port 21)",      test_patcher_disables_anon_ftp_on_port_21),
        ("AutoPatcher hardens SSH (port 22)",                 test_patcher_hardens_ssh_on_port_22),
        ("AutoPatcher is idempotent (same patch twice)",      test_patcher_is_idempotent),
        ("AutoPatcher resolves service from port number",     test_patcher_resolves_service_from_port),
        ("Full chain: detect -> respond -> patch in < 3s",     test_full_detect_respond_patch_chain),
    ]

    passed = 0
    failed = 0

    print("\n" + "=" * 60)
    print("  FEATURE 3 -- Real-Time Patching Tests")
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
    print(f"  Patching: {passed} passed, {failed} failed")
    print("=" * 60)
    return failed


if __name__ == "__main__":
    failures = run_all()
    sys.exit(failures)
