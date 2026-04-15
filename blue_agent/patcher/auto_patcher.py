"""Real-Time Patching (Feature 3) — Fix root cause after every response.

Subscribes to response_complete events from the event bus.
Applies the correct service-specific patch based on what triggered the response.

Patch catalogue:
    apache httpd / ports 80, 443, 8080
        → disable DIR-LISTING, apply security headers, harden server config
          (cannot be shut down — essential service)
    mysql / port 3306
        → enforce local-only binding, block external access
    ftp / port 21
        → disable anonymous login, enforce authentication, enable TLS
    telnet / port 23
        → remove service entirely
    ssh / port 22
        → disable root login, enforce key-based auth
    postgresql / port 5432
        → restrict pg_hba.conf to local connections

Patching is idempotent — applying the same patch twice is a no-op.
Emits patch_complete after each successful patch.

All changes are simulated in-memory — no real OS modifications.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Set

from core.event_bus import event_bus

logger = logging.getLogger(__name__)


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


# ---------------------------------------------------------------------------
# Patch catalogue
# ---------------------------------------------------------------------------

_PATCH_CATALOG: Dict[str, Dict[str, Any]] = {
    "apache httpd": {
        "action": "patch",
        "ports": [80, 443, 8080, 8443],
        "steps": [
            "Disable DIR-LISTING (Options -Indexes)",
            "Apply security headers: X-Frame-Options, X-Content-Type-Options, HSTS",
            "Harden config: ServerTokens Prod, ServerSignature Off",
            "Enable mod_security rule set",
        ],
        "result": "DIR-LISTING disabled, security headers applied \u2713",
    },
    "mysql": {
        "action": "bind_local",
        "ports": [3306],
        "steps": [
            "Set bind-address = 127.0.0.1 in my.cnf",
            "Block external access on port 3306 (iptables DROP)",
            "Revoke remote root login privileges",
            "Flush privileges",
        ],
        "result": "MySQL bound to localhost only, external access blocked \u2713",
    },
    "ftp": {
        "action": "disable_anon",
        "ports": [21],
        "steps": [
            "Set anonymous_enable=NO in vsftpd.conf",
            "Set local_enable=YES — enforce authenticated access",
            "Enable TLS: ssl_enable=YES, force_local_data_ssl=YES",
            "Restart vsftpd service",
        ],
        "result": "Anonymous FTP disabled, authentication enforced \u2713",
    },
    "telnet": {
        "action": "remove_service",
        "ports": [23],
        "steps": [
            "Stop telnet daemon (systemctl stop telnet)",
            "Disable telnet on boot (systemctl disable telnet)",
            "Remove telnet package (apt-get remove telnetd -y)",
            "Block port 23 (iptables -A INPUT -p tcp --dport 23 -j DROP)",
        ],
        "result": "Telnet service removed entirely \u2713",
    },
    "ssh": {
        "action": "harden",
        "ports": [22],
        "steps": [
            "Set PermitRootLogin no in sshd_config",
            "Set PasswordAuthentication no (key-based auth only)",
            "Set MaxAuthTries 3",
            "Restart sshd",
        ],
        "result": "SSH hardened \u2014 root login and password auth disabled \u2713",
    },
    "postgresql": {
        "action": "harden",
        "ports": [5432],
        "steps": [
            "Restrict pg_hba.conf: allow only local connections",
            "Disable remote superuser login",
            "Reload PostgreSQL configuration",
        ],
        "result": "PostgreSQL access restricted to local connections \u2713",
    },
    "http": {
        "action": "patch",
        "ports": [80, 8080],
        "steps": [
            "Apply HTTP security headers",
            "Disable directory listing",
        ],
        "result": "HTTP service hardened \u2713",
    },
    "rdp": {
        "action": "harden",
        "ports": [3389],
        "steps": [
            "Enforce NLA (Network Level Authentication)",
            "Restrict RDP to VPN subnet only",
            "Enable RDP session timeout",
        ],
        "result": "RDP hardened \u2014 NLA enforced, access restricted \u2713",
    },
}

# Port → canonical service name for fast lookup
_PORT_TO_SERVICE: Dict[int, str] = {}
for _svc, _meta in _PATCH_CATALOG.items():
    for _p in _meta["ports"]:
        _PORT_TO_SERVICE[_p] = _svc

# Idempotency tracker: set of patch keys already applied
_applied_patches: Set[str] = set()


def _resolve_service(data: Dict[str, Any]) -> "str | None":
    """Determine which catalog entry to use from response_complete data."""
    raw = (data.get("service") or "").lower().strip()
    port = data.get("port")

    # 1. Exact match in catalog
    if raw in _PATCH_CATALOG:
        return raw

    # 2. Port-based look-up
    if port and port in _PORT_TO_SERVICE:
        return _PORT_TO_SERVICE[port]

    # 3. Partial / substring match (e.g. "apache" matches "apache httpd")
    for name in _PATCH_CATALOG:
        if raw and (raw in name or name in raw):
            return name

    return None


# ---------------------------------------------------------------------------
# AutoPatcher
# ---------------------------------------------------------------------------

class AutoPatcher:
    """Applies root-cause patches after every confirmed response.

    Call register() once during system initialisation to wire the subscription.
    Patching is idempotent — the same service:port pair is only patched once.

    Emits:
        patch_complete — after each successful patch application
    """

    def __init__(self) -> None:
        self.patch_count: int = 0

    # ------------------------------------------------------------------
    # Subscription wiring
    # ------------------------------------------------------------------

    def register(self) -> None:
        """Subscribe to response_complete events."""
        event_bus.subscribe("response_complete", self._on_response_complete)

    # ------------------------------------------------------------------
    # Event handler
    # ------------------------------------------------------------------

    async def _on_response_complete(
        self, event_type: str, data: Dict[str, Any]
    ) -> None:
        """response_complete → apply the correct patch for the service."""
        service_name = _resolve_service(data)
        if not service_name:
            logger.debug(f"AutoPatcher: no catalog entry for data={data}")
            return

        port = data.get("port") or _PATCH_CATALOG[service_name]["ports"][0]
        patch_key = f"{service_name}:{port}"

        # Idempotency guard
        if patch_key in _applied_patches:
            ts = _ts()
            print(
                f"{ts} < auto_patcher: Patch for {service_name}:{port} "
                f"already applied \u2014 skipping (idempotent)"
            )
            return

        patch = _PATCH_CATALOG[service_name]
        ts = _ts()
        print(
            f"{ts} > harden_service({json.dumps({'service_name': service_name, 'port': port, 'action': patch['action']})})"
        )

        # Simulate applying each patch step
        for step in patch["steps"]:
            await asyncio.sleep(0.05)   # simulate config write / reload
            logger.debug(f"AutoPatcher [{service_name}]: {step}")

        _applied_patches.add(patch_key)
        self.patch_count += 1

        ts = _ts()
        print(f"{ts} < harden_service: {patch['result']}")

        await event_bus.emit("patch_complete", {
            "service": service_name,
            "port": port,
            "action": patch["action"],
            "steps_applied": patch["steps"],
            "status": "PATCHED",
        })
