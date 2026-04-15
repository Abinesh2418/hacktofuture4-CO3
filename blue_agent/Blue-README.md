# Blue Agent — Implementation Reference

HTF (Hack The Flag) · Red Team vs Blue Team AI Simulation  
Target system: `192.168.1.100`

---

## What Was Implemented

This document describes every file that was **created or modified** to bring the Blue Agent from empty stubs to a fully autonomous, real-time defend-respond-patch system.

---

## Files Changed

### `core/event_bus.py` — Modified (full rewrite)

**Role:** Central nervous system. Every Red action flows through here to trigger Blue's detection → response → patching chain.

**Key changes:**
- Fully `async def` — all `emit()` and handler calls are coroutines
- `asyncio.Queue` internal buffer — events are never dropped under burst load
- Multiple subscribers per event type — registration order is preserved
- Single background worker task processes events in FIFO order, guaranteeing `detect → respond → patch` delivery sequence
- Graceful `stop()` drains the queue before cancelling the worker

**Supported event types:**

| Event | Emitted by | Handled by |
|---|---|---|
| `port_probed` | IntrusionDetector | ResponseEngine |
| `port_scanned` | IntrusionDetector, LogMonitor | ResponseEngine |
| `exploit_attempted` | LogMonitor | ResponseEngine, Isolator |
| `cve_detected` | LogMonitor | ResponseEngine |
| `anomaly_detected` | AnomalyDetector | ResponseEngine, Isolator |
| `misconfig_found` | (reserved) | — |
| `response_complete` | ResponseEngine | AutoPatcher |
| `isolation_complete` | Isolator | (terminal) |
| `patch_complete` | AutoPatcher | (terminal) |
| `blue_ready` | BlueController | (broadcast) |

---

### `blue_agent/detector/intrusion_detector.py` — Implemented

**Role:** Feature 1 — Real-Time Detection of port scans and active probes.

**Behaviour:**
- Continuous `asyncio` polling loop, ticks every **1 second**
- Simulates Red agent probing with 70 % probability per tick
- Emits `port_probed` for every detected probe
- Emits `port_scanned` additionally for sensitive ports (21, 22, 23, 3306, 5432)
- Non-blocking — never pauses anomaly or log detection
- Tracks `detection_count` for live status reporting

**Sample output:**
```
19:28:19 < intrusion_detector: Port 23 probe detected
19:28:19 > event_bus.emit("port_probed", {"port": 23, "protocol": "tcp"})
```

---

### `blue_agent/detector/anomaly_detector.py` — Implemented

**Role:** Feature 1 — Real-Time Detection of unusual traffic patterns.

**Detection rules (all emit `anomaly_detected`):**

| Rule | Condition | Anomaly type |
|---|---|---|
| Scan rate | > 5 scans/second | `scan_rate` |
| Sensitive port | Access on port 21/22/23/3306 | `sensitive_port` |
| Traffic spike | > 8 hits/second on a single port | `traffic_spike` |

**Behaviour:**
- Continuous `asyncio` loop, ticks every **1 second**
- Maintains rolling scan window and per-port hit counters
- Runs concurrently alongside intrusion_detector and log_monitor — zero blocking
- Resets per-port counter after emitting a spike alert to avoid spam

**Sample output:**
```
19:28:20 < anomaly_detector: Scan rate 7/s exceeds threshold (5/s) from 10.0.0.42
19:28:20 > event_bus.emit("anomaly_detected", {"type": "scan_rate", "rate": 7, "source_ip": "10.0.0.42"})
```

---

### `blue_agent/detector/log_monitor.py` — Implemented

**Role:** Feature 1 — Real-Time Detection by tailing system logs for Red signatures.

**Behaviour:**
- Maintains an internal rotating log buffer (max 500 lines) simulating `/var/log/syslog`
- **Injection task** — adds 1–3 realistic Red-agent log entries every 1.5 seconds
- **Tail loop** — processes new buffer lines every 1 second, pattern-matches signatures

**Signature → event mapping:**

| Signature | Example log pattern | Event emitted |
|---|---|---|
| `nmap` | `nmap -sV -p 3306 192.168.1.100` | `port_scanned` |
| `cve_lookup` | `searchsploit CVE-2023-44487` | `cve_detected` |
| `exploit` | `python3 exploit_ftp.py --target ...` | `exploit_attempted` |

**Sample output:**
```
19:28:21 < log_monitor: CVE lookup pattern found in logs → emitting cve_detected
19:28:21 > event_bus.emit("cve_detected", {"cve_id": "CVE-2023-44487", "service": "mysql", ...})
```

---

### `blue_agent/responder/response_engine.py` — Implemented

**Role:** Feature 2 — Real-Time Response. Reacts to every detection event immediately.

**Event → action mapping:**

| Event | Action | Status logged |
|---|---|---|
| `port_probed` / `port_scanned` | `close_port(port)` → iptables DROP (simulated) | `BLOCKED` |
| `exploit_attempted` | `isolate_service(service)` | `ISOLATED` |
| `cve_detected` | `harden_service(service, cve_id)` | `HARDENED` |
| `anomaly_detected` | `block_ip(source_ip)` | `BLOCKED` |

**Behaviour:**
- All actions are idempotent — same port/IP/service is only acted on once
- After each action, `verify_fix()` confirms the block is in the simulated state
- Emits `response_complete` after every verified response (triggers AutoPatcher)

**Sample output:**
```
19:28:37 > close_port({"port": 3306, "protocol": "tcp"})
19:28:38 < close_port: Port 3306/tcp blocked via iptables DROP rule
19:28:38 > verify_fix({"target": "192.168.1.100", "port": 3306})
19:28:38 < verify_fix: Port 3306 is BLOCKED ✓
```

---

### `blue_agent/responder/isolator.py` — Implemented

**Role:** Feature 2 — Real-Time Response. Isolates services or source IPs under active attack.

**Subscriptions:**
- `exploit_attempted` → `drop_inbound(port)` — drops all inbound traffic to the service port
- `anomaly_detected` → `drop_ip(source_ip)` — drops all traffic from the offending IP

**Behaviour:**
- Completes isolation in **< 1 second** (30 ms simulated latency)
- Idempotent — isolating the same port/IP twice is a no-op
- Emits `isolation_complete` after each successful action

**Sample output:**
```
19:28:39 > isolator.drop_inbound({"port": 21, "protocol": "tcp"})
19:28:39 < isolator: Port 21/tcp — all inbound traffic DROPPED
19:28:39 < isolator: Service 'ftp' on port 21 ISOLATED ✓
```

---

### `blue_agent/patcher/auto_patcher.py` — Implemented

**Role:** Feature 3 — Real-Time Patching. Fixes the root cause after every response.

**Patch catalogue:**

| Service | Ports | Action | What it does |
|---|---|---|---|
| `apache httpd` | 80, 443, 8080, 8443 | `patch` | Disable DIR-LISTING, apply security headers, harden server config |
| `mysql` | 3306 | `bind_local` | Enforce `bind-address=127.0.0.1`, block external access |
| `ftp` | 21 | `disable_anon` | Disable anonymous login, enforce auth, enable TLS |
| `telnet` | 23 | `remove_service` | Stop daemon, disable on boot, remove package |
| `ssh` | 22 | `harden` | Disable root login, enforce key-based auth, set MaxAuthTries 3 |
| `postgresql` | 5432 | `harden` | Restrict pg_hba.conf to local connections |

**Behaviour:**
- Subscribes to `response_complete`
- Resolves service by name → port → partial match
- **Idempotent** — `service:port` patch key tracked; same patch is never applied twice
- Emits `patch_complete` after each patch

**Sample output:**
```
19:28:39 > harden_service({"service_name": "apache httpd", "port": 80, "action": "patch"})
19:28:39 < harden_service: DIR-LISTING disabled, security headers applied ✓
```

---

### `blue_agent/blue_controller.py` — Modified (full rewrite)

**Role:** Main orchestrator — starts and connects all three features.

**Startup sequence:**
1. Start EventBus worker
2. Register all subscriptions (response_engine, isolator, auto_patcher)
3. Emit `blue_ready` event
4. Launch all three detector loops **concurrently** via `asyncio.gather()`

**`get_status()` returns:**
```json
{
  "detection_count": 42,
  "response_count": 18,
  "patch_count": 11,
  "isolation_count": 7,
  "running": true
}
```

**Concurrency guarantee:** `asyncio.gather()` with `return_exceptions=True` — a single detector crash cannot bring down the other two loops.

---

## System Architecture

```
Red Agent Action
      │
      ▼
 EventBus (asyncio.Queue — FIFO, never drops)
      │
      ├──► IntrusionDetector  ─┐
      │    [1s loop]           │  port_probed
      │                        │  port_scanned
      ├──► AnomalyDetector   ──┤  anomaly_detected
      │    [1s loop]           │
      │                        │
      └──► LogMonitor        ──┘  port_scanned
           [1s loop]              cve_detected
                                  exploit_attempted
                                       │
                          ┌────────────┴───────────┐
                          ▼                        ▼
                  ResponseEngine              Isolator
                  (close_port /         (drop_inbound /
                   isolate /             drop_ip)
                   harden /                  │
                   block_ip)          isolation_complete
                          │
                   response_complete
                          │
                          ▼
                     AutoPatcher
                  (service-specific,
                   idempotent patches)
                          │
                    patch_complete
```

## Concurrency Model

All three detector loops run in parallel inside a single `asyncio.gather()` call.
No loop ever waits for another — detection continues even while patching is in progress.

```
Time →   1s          2s          3s
         ┌──────┐    ┌──────┐    ┌──────┐
ID       │detect│    │detect│    │detect│   IntrusionDetector (1s tick)
         └──────┘    └──────┘    └──────┘
         ┌──────┐    ┌──────┐    ┌──────┐
AD       │detect│    │detect│    │detect│   AnomalyDetector   (1s tick)
         └──────┘    └──────┘    └──────┘
         ┌──────┐    ┌──────┐    ┌──────┐
LM       │detect│    │detect│    │detect│   LogMonitor        (1s tick)
         └──────┘    └──────┘    └──────┘
                ┌─┐               ┌─┐
RE              │R│               │R│        ResponseEngine   (event-driven)
                └─┘               └─┘
                  ┌──┐              ┌──┐
AP                │P │              │P │     AutoPatcher      (event-driven)
                  └──┘              └──┘
```

## Log Format

Every action across all files follows this exact format:

```
{HH:MM:SS} < {component}: {result_message}
{HH:MM:SS} > {tool_name}({json_params})
```

Example end-to-end chain:
```
19:28:19 < intrusion_detector: Port 23 probe detected
19:28:19 > event_bus.emit("port_probed", {"port": 23, "protocol": "tcp"})
19:28:19 > close_port({"port": 23, "protocol": "tcp"})
19:28:19 < close_port: Port 23/tcp blocked via iptables DROP rule
19:28:19 > verify_fix({"target": "192.168.1.100", "port": 23})
19:28:19 < verify_fix: Port 23 is BLOCKED ✓
19:28:19 > harden_service({"service_name": "telnet", "port": 23, "action": "remove_service"})
19:28:19 < harden_service: Telnet service removed entirely ✓
```

## Simulation Notes

All defence actions are **fully simulated in-memory**:
- No real `iptables` rules are created
- No real services are restarted or removed
- No real filesystem changes are made
- Safe to run on any OS (Windows, Linux, macOS) without root

Blocked ports, isolated services, and applied patches are tracked in module-level Python sets. The simulation is deterministic enough to demonstrate the full detect → respond → patch chain in a live demo.
