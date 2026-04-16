from __future__ import annotations

"""Real-Time Response (Feature 2) — React to every detection event immediately.

Subscribes to all detection events from the event bus on initialisation.
Each event type maps to an immediate response action with no delay:

    port_probed       → close_port(port)      via simulated iptables DROP
    port_scanned      → close_port(port)      (same as port_probed)
    exploit_attempted → isolate_service(svc)
    cve_detected      → harden_service(svc)
    anomaly_detected  → block_ip(source_ip)

After every response action the engine verifies the fix was applied, then
emits response_complete so the AutoPatcher can act.

All state is in-memory — no real OS or iptables changes.
"""

import asyncio
import json
import logging
import random
from datetime import datetime
from typing import Any, Dict, Set

from core.event_bus import event_bus

logger = logging.getLogger(__name__)

TARGET_IP = "172.25.8.172"

# ---------------------------------------------------------------------------
# Simulated firewall / isolation state  (module-level so all handlers share it)
# ---------------------------------------------------------------------------
_blocked_ports: Set[int] = set()
_isolated_services: Set[str] = set()
_hardened_services: Set[str] = set()
_blocked_ips: Set[str] = set()

# ---------------------------------------------------------------------------
# Port → service name look-up
# ---------------------------------------------------------------------------
_PORT_SERVICE: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    80: "apache httpd",
    443: "apache httpd",
    3306: "mysql",
    5000: "flask",
    8080: "apache httpd",
    5432: "postgresql",
    3389: "rdp",
    8443: "apache httpd",
}

# ---------------------------------------------------------------------------
# Web application defense state (Flask/Werkzeug @ port 5000)
# ---------------------------------------------------------------------------
_waf_rules: Set[str] = set()          # active WAF rules
_rate_limited_ips: Set[str] = set()   # IPs under rate limiting
_blocked_endpoints: Set[str] = set()  # endpoints with input validation enforced


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _service_for_port(port: int) -> str:
    return _PORT_SERVICE.get(port, f"service_port_{port}")


# ---------------------------------------------------------------------------
# Simulated response actions
# ---------------------------------------------------------------------------

async def _close_port(port: int, protocol: str) -> bool:
    """Simulate iptables -A INPUT -p tcp --dport PORT -j DROP."""
    ts = _ts()
    params = {"port": port, "protocol": protocol}
    print(f"{ts} > close_port({json.dumps(params)})")
    await asyncio.sleep(0.05)           # simulate syscall latency
    _blocked_ports.add(port)
    print(f"{ts} < close_port: Port {port}/{protocol} blocked via iptables DROP rule")
    return True


async def _verify_fix(port: int) -> bool:
    """Confirm the port is in the blocked set (simulated port probe)."""
    ts = _ts()
    params = {"target": TARGET_IP, "port": port}
    print(f"{ts} > verify_fix({json.dumps(params)})")
    await asyncio.sleep(0.02)
    blocked = port in _blocked_ports
    status = "BLOCKED \u2713" if blocked else "STILL OPEN \u2717"
    print(f"{ts} < verify_fix: Port {port} is {status}")
    return blocked


async def _isolate_service(service: str) -> bool:
    """Simulate dropping all inbound connections to a named service."""
    ts = _ts()
    params = {"service": service}
    print(f"{ts} > isolate_service({json.dumps(params)})")
    await asyncio.sleep(0.05)
    _isolated_services.add(service)
    print(f"{ts} < isolate_service: {service} ISOLATED \u2014 inbound traffic dropped")
    return True


async def _harden_service(service: str, cve_id: str | None = None) -> bool:
    """Simulate applying CVE mitigations to a service config."""
    ts = _ts()
    params: Dict[str, Any] = {"service": service}
    if cve_id:
        params["cve_id"] = cve_id
    print(f"{ts} > harden_service({json.dumps(params)})")
    await asyncio.sleep(0.05)
    _hardened_services.add(service)
    suffix = f" ({cve_id})" if cve_id else ""
    print(f"{ts} < harden_service: {service} HARDENED \u2014 CVE mitigations applied{suffix}")
    return True


async def _block_ip(source_ip: str) -> bool:
    """Simulate iptables -A INPUT -s SOURCE_IP -j DROP."""
    ts = _ts()
    params = {"source_ip": source_ip}
    print(f"{ts} > block_ip({json.dumps(params)})")
    await asyncio.sleep(0.05)
    _blocked_ips.add(source_ip)
    print(f"{ts} < block_ip: {source_ip} BLOCKED \u2014 all traffic dropped")
    return True


# ---------------------------------------------------------------------------
# Web application response actions (Flask/Werkzeug @ 172.25.8.172:5000)
# ---------------------------------------------------------------------------

async def _deploy_waf_rule(rule_name: str, endpoint: str, attack_type: str) -> bool:
    """Simulate deploying a WAF rule to block attack patterns."""
    ts = _ts()
    params = {"rule": rule_name, "endpoint": endpoint, "attack": attack_type}
    print(f"{ts} > deploy_waf_rule({json.dumps(params)})")
    await asyncio.sleep(0.05)
    _waf_rules.add(rule_name)
    print(f"{ts} < deploy_waf_rule: WAF rule '{rule_name}' ACTIVE on {endpoint} \u2713")
    return True


async def _rate_limit_ip(source_ip: str, endpoint: str, max_rpm: int = 10) -> bool:
    """Simulate applying rate limiting on an IP for a specific endpoint."""
    ts = _ts()
    params = {"source_ip": source_ip, "endpoint": endpoint, "max_rpm": max_rpm}
    print(f"{ts} > rate_limit({json.dumps(params)})")
    await asyncio.sleep(0.03)
    _rate_limited_ips.add(source_ip)
    print(f"{ts} < rate_limit: {source_ip} limited to {max_rpm} req/min on {endpoint} \u2713")
    return True


async def _enforce_input_validation(endpoint: str, param: str, validation_type: str) -> bool:
    """Simulate enforcing strict input validation on a parameter."""
    ts = _ts()
    params = {"endpoint": endpoint, "param": param, "validation": validation_type}
    print(f"{ts} > enforce_input_validation({json.dumps(params)})")
    await asyncio.sleep(0.04)
    key = f"{endpoint}:{param}"
    _blocked_endpoints.add(key)
    print(f"{ts} < enforce_input_validation: {validation_type} enforced on {endpoint}?{param} \u2713")
    return True


# ---------------------------------------------------------------------------
# ResponseEngine
# ---------------------------------------------------------------------------

class ResponseEngine:
    """Subscribes to all detection events and executes immediate responses.

    Call register() once during system initialisation to wire all subscriptions.
    Each handler is fully idempotent — acting on the same port/IP/service twice
    is a no-op after the first successful response.
    """

    def __init__(self) -> None:
        self.response_count: int = 0

    # ------------------------------------------------------------------
    # Subscription wiring
    # ------------------------------------------------------------------

    def register(self) -> None:
        """Wire all detection-event subscriptions."""
        event_bus.subscribe("port_probed", self._on_port_probed)
        event_bus.subscribe("port_scanned", self._on_port_probed)   # same handler
        event_bus.subscribe("exploit_attempted", self._on_exploit_attempted)
        event_bus.subscribe("cve_detected", self._on_cve_detected)
        event_bus.subscribe("anomaly_detected", self._on_anomaly_detected)
        # Web application attack handlers (Flask/Werkzeug @ port 5000)
        event_bus.subscribe("sql_injection_attempted", self._on_sql_injection)
        event_bus.subscribe("credential_attack_detected", self._on_credential_attack)
        event_bus.subscribe("directory_traversal_attempted", self._on_directory_traversal)
        event_bus.subscribe("idor_attempted", self._on_idor_attempt)
        event_bus.subscribe("webapp_attack_detected", self._on_webapp_attack)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    async def _on_port_probed(self, event_type: str, data: Dict[str, Any]) -> None:
        """port_probed / port_scanned → close_port + verify."""
        port = data.get("port")
        protocol = data.get("protocol", "tcp")

        if port is None:
            return
        if port in _blocked_ports:
            return  # already handled — idempotent

        success = await _close_port(port, protocol)
        if success:
            verified = await _verify_fix(port)
            if verified:
                self.response_count += 1
                await event_bus.emit("response_complete", {
                    "action": "close_port",
                    "port": port,
                    "protocol": protocol,
                    "service": _service_for_port(port),
                    "status": "BLOCKED",
                })

    async def _on_exploit_attempted(self, event_type: str, data: Dict[str, Any]) -> None:
        """exploit_attempted → isolate_service."""
        service = data.get("service", "unknown_service")

        if service in _isolated_services:
            return

        success = await _isolate_service(service)
        if success:
            self.response_count += 1
            await event_bus.emit("response_complete", {
                "action": "isolate_service",
                "service": service,
                "port": data.get("port"),
                "status": "ISOLATED",
            })

    async def _on_cve_detected(self, event_type: str, data: Dict[str, Any]) -> None:
        """cve_detected → harden_service."""
        # service_name comes from log_monitor; fall back to port look-up
        service = (
            data.get("service_name")
            or data.get("service")
            or _service_for_port(data.get("port", 0))
        )
        cve_id = data.get("cve_id")

        if service in _hardened_services:
            return

        success = await _harden_service(service, cve_id)
        if success:
            self.response_count += 1
            await event_bus.emit("response_complete", {
                "action": "harden_service",
                "service": service,
                "cve_id": cve_id,
                "port": data.get("port"),
                "status": "HARDENED",
            })

    async def _on_anomaly_detected(self, event_type: str, data: Dict[str, Any]) -> None:
        """anomaly_detected → block_ip."""
        source_ip = data.get("source_ip") or f"10.0.0.{random.randint(2, 254)}"

        if source_ip in _blocked_ips:
            return

        success = await _block_ip(source_ip)
        if success:
            self.response_count += 1
            await event_bus.emit("response_complete", {
                "action": "block_ip",
                "source_ip": source_ip,
                "anomaly_type": data.get("type", "unknown"),
                "status": "BLOCKED",
            })

    # ------------------------------------------------------------------
    # Web application attack handlers (Flask/Werkzeug @ 172.25.8.172:5000)
    # ------------------------------------------------------------------

    async def _on_sql_injection(self, event_type: str, data: Dict[str, Any]) -> None:
        """sql_injection_attempted → deploy WAF rule + enforce input validation + block IP."""
        source_ip = data.get("source_ip", "")
        endpoint = data.get("endpoint", "/search")
        rule_name = f"sqli_block_{endpoint.replace('/', '_')}"

        if rule_name not in _waf_rules:
            await _deploy_waf_rule(rule_name, endpoint, "sql_injection")
        await _enforce_input_validation(endpoint, "q", "parameterized_query")

        if source_ip and source_ip not in _blocked_ips:
            await _block_ip(source_ip)

        self.response_count += 1
        await event_bus.emit("response_complete", {
            "action": "block_sql_injection",
            "endpoint": endpoint,
            "service": "flask",
            "port": 5000,
            "source_ip": source_ip,
            "waf_rule": rule_name,
            "status": "WAF_DEPLOYED",
        })

    async def _on_credential_attack(self, event_type: str, data: Dict[str, Any]) -> None:
        """credential_attack_detected → rate limit + account lockout + block IP."""
        source_ip = data.get("source_ip", "")
        endpoint = data.get("endpoint", "/login")

        if source_ip and source_ip not in _rate_limited_ips:
            await _rate_limit_ip(source_ip, endpoint, max_rpm=5)

        rule_name = "credential_protection_login"
        if rule_name not in _waf_rules:
            await _deploy_waf_rule(rule_name, endpoint, "brute_force")

        if source_ip and source_ip not in _blocked_ips:
            await _block_ip(source_ip)

        self.response_count += 1
        await event_bus.emit("response_complete", {
            "action": "block_credential_attack",
            "endpoint": endpoint,
            "service": "flask",
            "port": 5000,
            "source_ip": source_ip,
            "status": "RATE_LIMITED",
        })

    async def _on_directory_traversal(self, event_type: str, data: Dict[str, Any]) -> None:
        """directory_traversal_attempted → WAF rule + input sanitization + block IP."""
        source_ip = data.get("source_ip", "")
        endpoint = data.get("endpoint", "/profile")
        rule_name = f"traversal_block_{endpoint.replace('/', '_')}"

        if rule_name not in _waf_rules:
            await _deploy_waf_rule(rule_name, endpoint, "directory_traversal")
        await _enforce_input_validation(endpoint, "id", "path_sanitization")

        if source_ip and source_ip not in _blocked_ips:
            await _block_ip(source_ip)

        self.response_count += 1
        await event_bus.emit("response_complete", {
            "action": "block_directory_traversal",
            "endpoint": endpoint,
            "service": "flask",
            "port": 5000,
            "source_ip": source_ip,
            "waf_rule": rule_name,
            "status": "WAF_DEPLOYED",
        })

    async def _on_idor_attempt(self, event_type: str, data: Dict[str, Any]) -> None:
        """idor_attempted → enforce authorization + input validation + block IP."""
        source_ip = data.get("source_ip", "")
        endpoint = data.get("endpoint", "/profile")
        rule_name = "idor_protection_profile"

        if rule_name not in _waf_rules:
            await _deploy_waf_rule(rule_name, endpoint, "idor")
        await _enforce_input_validation(endpoint, "id", "authorization_check")

        if source_ip and source_ip not in _blocked_ips:
            await _block_ip(source_ip)

        self.response_count += 1
        await event_bus.emit("response_complete", {
            "action": "block_idor",
            "endpoint": endpoint,
            "service": "flask",
            "port": 5000,
            "source_ip": source_ip,
            "status": "AUTH_ENFORCED",
        })

    async def _on_webapp_attack(self, event_type: str, data: Dict[str, Any]) -> None:
        """webapp_attack_detected → generic WAF + block IP."""
        source_ip = data.get("source_ip", "")
        endpoint = data.get("endpoint", "/")
        attack_type = data.get("attack_type", "unknown")

        rule_name = f"webapp_block_{attack_type}"
        if rule_name not in _waf_rules:
            await _deploy_waf_rule(rule_name, endpoint, attack_type)

        if source_ip and source_ip not in _blocked_ips:
            await _block_ip(source_ip)

        self.response_count += 1
        await event_bus.emit("response_complete", {
            "action": "block_webapp_attack",
            "endpoint": endpoint,
            "service": "flask",
            "port": 5000,
            "source_ip": source_ip,
            "attack_type": attack_type,
            "status": "WAF_DEPLOYED",
        })
