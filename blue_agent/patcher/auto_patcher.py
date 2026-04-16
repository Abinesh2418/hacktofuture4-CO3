from __future__ import annotations

"""Real-Time Patching (Feature 3) — Fix root cause after every response.

Subscribes to response_complete and vulnerability_found events.
Applies the correct service-specific patch based on what triggered the response.

Two patching modes:
  1. Service patches — from the built-in catalogue (triggered by response_complete)
  2. CVE-specific patches — targeted fixes for discovered CVEs (triggered by
     vulnerability_found from the asset scanner + CVE lookup pipeline)

Patch catalogue:
    apache httpd / ports 80, 443, 8080
        → disable DIR-LISTING, apply security headers, harden server config
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

CVE fix catalogue:
    Maps specific CVE IDs to targeted remediation steps (upgrade commands,
    config changes, module disabling, etc.)

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
    "nginx": {
        "action": "harden",
        "ports": [80, 443, 8080],
        "steps": [
            "Hide server version: server_tokens off",
            "Add security headers: X-Frame-Options, X-Content-Type-Options, CSP",
            "Disable autoindex: autoindex off",
            "Restrict HTTP methods: allow GET, POST, HEAD only",
        ],
        "result": "Nginx hardened \u2014 version hidden, security headers applied \u2713",
    },
    "mongodb": {
        "action": "harden",
        "ports": [27017],
        "steps": [
            "Enable authentication: security.authorization=enabled",
            "Bind to localhost: net.bindIp=127.0.0.1",
            "Disable scripting: security.javascriptEnabled=false",
        ],
        "result": "MongoDB hardened \u2014 auth enabled, bound to localhost \u2713",
    },
    "redis": {
        "action": "harden",
        "ports": [6379],
        "steps": [
            "Set requirepass in redis.conf",
            "Bind to 127.0.0.1",
            "Disable dangerous commands: rename-command FLUSHALL, CONFIG",
            "Enable protected-mode yes",
        ],
        "result": "Redis hardened \u2014 password set, dangerous commands disabled \u2713",
    },
    "elasticsearch": {
        "action": "harden",
        "ports": [9200, 9300],
        "steps": [
            "Enable X-Pack security authentication",
            "Bind to localhost: network.host=127.0.0.1",
            "Enable TLS for transport and HTTP layers",
            "Disable dynamic scripting",
        ],
        "result": "Elasticsearch hardened \u2014 auth enabled, TLS configured \u2713",
    },
    "tomcat": {
        "action": "harden",
        "ports": [8080, 8443],
        "steps": [
            "Remove default webapps (manager, host-manager, examples, docs)",
            "Disable directory listing in web.xml",
            "Set shutdown port to -1",
            "Remove server version from error pages",
        ],
        "result": "Tomcat hardened \u2014 defaults removed, directory listing disabled \u2713",
    },
    "wordpress": {
        "action": "patch",
        "ports": [80, 443],
        "steps": [
            "Update WordPress core to latest version",
            "Disable XML-RPC: add deny rule to .htaccess",
            "Disable file editing: define('DISALLOW_FILE_EDIT', true)",
            "Set proper file permissions (644 for files, 755 for directories)",
        ],
        "result": "WordPress patched \u2014 core updated, XML-RPC disabled \u2713",
    },
    "docker": {
        "action": "harden",
        "ports": [2376, 2375],
        "steps": [
            "Enable TLS authentication on Docker daemon",
            "Drop all capabilities and add only required ones",
            "Set no-new-privileges security option",
            "Enable user namespace remapping",
        ],
        "result": "Docker hardened \u2014 TLS enabled, capabilities restricted \u2713",
    },
    "kubernetes": {
        "action": "harden",
        "ports": [443, 6443, 8443],
        "steps": [
            "Enable RBAC authorization mode",
            "Enforce Pod Security Standards (restricted)",
            "Enable audit logging",
            "Disable anonymous authentication",
        ],
        "result": "Kubernetes hardened \u2014 RBAC enabled, PSS enforced \u2713",
    },
    "flask": {
        "action": "harden",
        "ports": [5000],
        "steps": [
            "Disable debug mode: set FLASK_DEBUG=0, app.debug=False",
            "Disable Werkzeug interactive debugger in production",
            "Set SECRET_KEY to cryptographically random value (os.urandom(32))",
            "Enable CSRF protection via Flask-WTF CSRFProtect",
            "Enforce parameterized queries on /search endpoint (prevent SQLi)",
            "Add input validation/sanitization on all query parameters (q, id)",
            "Implement rate limiting on /login endpoint (Flask-Limiter: 5/min)",
            "Add account lockout after 5 failed login attempts",
            "Enforce authorization checks on /profile?id= (prevent IDOR)",
            "Set secure HTTP headers: X-Frame-Options, X-Content-Type-Options, CSP",
            "Disable directory listing and path traversal via safe path joins",
            "Set SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True",
            "Bind Werkzeug to 127.0.0.1 in production (use reverse proxy)",
            "Remove server version from Werkzeug response headers",
        ],
        "result": "Flask/Werkzeug hardened \u2014 debug off, SQLi blocked, auth enforced, rate-limited \u2713",
    },
    "werkzeug": {
        "action": "harden",
        "ports": [5000],
        "steps": [
            "Upgrade Werkzeug to latest stable (3.1.x+)",
            "Disable interactive debugger: use_debugger=False",
            "Disable reloader in production: use_reloader=False",
            "Remove server version header: hide Werkzeug/3.1.8 banner",
            "Set strict Content-Security-Policy headers",
        ],
        "result": "Werkzeug hardened \u2014 debugger disabled, version hidden \u2713",
    },
}

# ---------------------------------------------------------------------------
# CVE-specific fix catalogue
# ---------------------------------------------------------------------------

_CVE_FIX_CATALOG: Dict[str, Dict[str, Any]] = {
    "CVE-2021-41773": {
        "service": "apache",
        "steps": ["Upgrade Apache to 2.4.51+", "Set 'Require all denied' on filesystem root", "Verify: path traversal returns 403"],
        "result": "CVE-2021-41773 fixed \u2014 Apache upgraded, path traversal blocked \u2713",
    },
    "CVE-2021-42013": {
        "service": "apache",
        "steps": ["Upgrade Apache to 2.4.51+", "Disable CGI modules if unused: a2dismod cgi cgid"],
        "result": "CVE-2021-42013 fixed \u2014 Apache upgraded, CGI hardened \u2713",
    },
    "CVE-2022-22720": {
        "service": "apache",
        "steps": ["Upgrade Apache to 2.4.53+", "Enable mod_reqtimeout"],
        "result": "CVE-2022-22720 fixed \u2014 request smuggling mitigated \u2713",
    },
    "CVE-2020-11984": {
        "service": "apache",
        "steps": ["Upgrade Apache to 2.4.44+", "Disable mod_proxy_uwsgi if unused"],
        "result": "CVE-2020-11984 fixed \u2014 buffer overflow patched \u2713",
    },
    "CVE-2021-23017": {
        "service": "nginx",
        "steps": ["Upgrade nginx to 1.20.1+", "Avoid using nginx as DNS resolver"],
        "result": "CVE-2021-23017 fixed \u2014 DNS resolver vulnerability patched \u2713",
    },
    "CVE-2020-14812": {
        "service": "mysql",
        "steps": ["Upgrade MySQL to 5.7.32+", "Apply Oracle CPU patch"],
        "result": "CVE-2020-14812 fixed \u2014 MySQL locking vulnerability patched \u2713",
    },
    "CVE-2020-14769": {
        "service": "mysql",
        "steps": ["Upgrade MySQL to 5.7.32+", "Optimize complex queries"],
        "result": "CVE-2020-14769 fixed \u2014 MySQL optimizer patched \u2713",
    },
    "CVE-2021-2307": {
        "service": "mysql",
        "steps": ["Upgrade MySQL to 8.0.26+"],
        "result": "CVE-2021-2307 fixed \u2014 MySQL packaging vulnerability patched \u2713",
    },
    "CVE-2021-32027": {
        "service": "postgresql",
        "steps": ["Upgrade PostgreSQL to 13.3+", "Restrict array dimension sizes"],
        "result": "CVE-2021-32027 fixed \u2014 buffer overrun patched \u2713",
    },
    "CVE-2022-2625": {
        "service": "postgresql",
        "steps": ["Upgrade PostgreSQL to 14.6+", "Audit installed extensions"],
        "result": "CVE-2022-2625 fixed \u2014 extension vulnerability patched \u2713",
    },
    "CVE-2021-32761": {
        "service": "redis",
        "steps": ["Upgrade Redis to 6.0.15+", "Migrate to 64-bit if on 32-bit"],
        "result": "CVE-2021-32761 fixed \u2014 BITFIELD overflow patched \u2713",
    },
    "CVE-2021-32625": {
        "service": "redis",
        "steps": ["Upgrade Redis to 6.0.14+", "Disable STRALGO if unused"],
        "result": "CVE-2021-32625 fixed \u2014 STRALGO overflow patched \u2713",
    },
    "CVE-2020-15778": {
        "service": "openssh",
        "steps": ["Upgrade OpenSSH to 8.4+", "Use sftp instead of scp"],
        "result": "CVE-2020-15778 fixed \u2014 scp injection patched \u2713",
    },
    "CVE-2021-41617": {
        "service": "openssh",
        "steps": ["Upgrade OpenSSH to 8.8+", "Review AuthorizedKeysCommand config"],
        "result": "CVE-2021-41617 fixed \u2014 privilege escalation patched \u2713",
    },
    "CVE-2021-3618": {
        "service": "vsftpd",
        "steps": ["Upgrade vsftpd to 3.0.5+", "Configure strict TLS SNI", "Disable SSLv3/TLSv1.0"],
        "result": "CVE-2021-3618 fixed \u2014 ALPACA TLS attack mitigated \u2713",
    },
    "CVE-2021-21702": {
        "service": "php",
        "steps": ["Upgrade PHP to 7.4.18+", "Disable SOAP extension if unused"],
        "result": "CVE-2021-21702 fixed \u2014 SOAP null pointer patched \u2713",
    },
    "CVE-2021-21703": {
        "service": "php",
        "steps": ["Upgrade PHP to 7.4.26+", "Run PHP-FPM as non-root"],
        "result": "CVE-2021-21703 fixed \u2014 FPM privilege escalation patched \u2713",
    },
    "CVE-2021-22931": {
        "service": "nodejs",
        "steps": ["Upgrade Node.js to 14.17.5+", "Validate DNS resolution results"],
        "result": "CVE-2021-22931 fixed \u2014 DNS rebinding patched \u2713",
    },
    "CVE-2022-21824": {
        "service": "nodejs",
        "steps": ["Upgrade Node.js to 16.13.2+", "Freeze Object.prototype at startup"],
        "result": "CVE-2022-21824 fixed \u2014 prototype pollution patched \u2713",
    },
    "CVE-2021-29447": {
        "service": "wordpress",
        "steps": ["Upgrade WordPress to 5.7.1+", "Disable XML entity processing", "Restrict media upload types"],
        "result": "CVE-2021-29447 fixed \u2014 XXE vulnerability patched \u2713",
    },
    "CVE-2022-21661": {
        "service": "wordpress",
        "steps": ["Upgrade WordPress to 5.9.4+", "Use parameterized queries in plugins"],
        "result": "CVE-2022-21661 fixed \u2014 SQL injection patched \u2713",
    },
    "CVE-2021-42340": {
        "service": "tomcat",
        "steps": ["Upgrade Tomcat to 9.0.54+", "Configure WebSocket connection limits"],
        "result": "CVE-2021-42340 fixed \u2014 WebSocket memory leak patched \u2713",
    },
    "CVE-2021-32040": {
        "service": "mongodb",
        "steps": ["Upgrade MongoDB to 4.4.15+", "Enable message size validation"],
        "result": "CVE-2021-32040 fixed \u2014 BSON DoS patched \u2713",
    },
    "CVE-2022-23708": {
        "service": "elasticsearch",
        "steps": ["Upgrade Elasticsearch to 7.17.1+", "Review search API access controls"],
        "result": "CVE-2022-23708 fixed \u2014 document access patched \u2713",
    },
    "CVE-2022-24769": {
        "service": "docker",
        "steps": ["Upgrade Docker to 20.10.14+", "Drop inheritable capabilities"],
        "result": "CVE-2022-24769 fixed \u2014 capabilities vulnerability patched \u2713",
    },
    "CVE-2022-3162": {
        "service": "kubernetes",
        "steps": ["Upgrade Kubernetes to 1.24.9+", "Review RBAC policies"],
        "result": "CVE-2022-3162 fixed \u2014 RBAC bypass patched \u2713",
    },
    "CVE-2021-31166": {
        "service": "iis",
        "steps": ["Apply Windows Update KB5003173", "Disable HTTP trailer support"],
        "result": "CVE-2021-31166 fixed \u2014 HTTP stack RCE patched \u2713",
    },
    "CVE-2019-12815": {
        "service": "proftpd",
        "steps": ["Upgrade ProFTPD to 1.3.6b+", "Disable mod_copy module"],
        "result": "CVE-2019-12815 fixed \u2014 arbitrary file copy patched \u2713",
    },
    # Flask / Werkzeug CVEs (target: 172.25.8.172:5000)
    "CVE-2023-30861": {
        "service": "flask",
        "steps": ["Upgrade Flask to 2.3.2+", "Set SESSION_COOKIE_SAMESITE='Lax'", "Ensure Vary: Cookie header is set on responses"],
        "result": "CVE-2023-30861 fixed \u2014 session cookie exposure patched \u2713",
    },
    "CVE-2023-25577": {
        "service": "werkzeug",
        "steps": ["Upgrade Werkzeug to 2.2.3+", "Set max_form_memory_size limit", "Configure request.max_content_length"],
        "result": "CVE-2023-25577 fixed \u2014 multipart parser DoS patched \u2713",
    },
    "CVE-2023-23934": {
        "service": "werkzeug",
        "steps": ["Upgrade Werkzeug to 2.2.3+", "Validate cookie domain settings", "Set SESSION_COOKIE_DOMAIN explicitly"],
        "result": "CVE-2023-23934 fixed \u2014 cookie injection patched \u2713",
    },
    "CVE-2024-34069": {
        "service": "werkzeug",
        "steps": ["Upgrade Werkzeug to 3.0.3+", "Disable debugger in production: WERKZEUG_DEBUG_PIN=off", "Remove debug=True from all Flask configs"],
        "result": "CVE-2024-34069 fixed \u2014 debugger RCE patched \u2713",
    },
    "CVE-2023-46136": {
        "service": "werkzeug",
        "steps": ["Upgrade Werkzeug to 3.0.1+", "Limit multipart form data size", "Set request timeout"],
        "result": "CVE-2023-46136 fixed \u2014 multipart resource exhaustion patched \u2713",
    },
    "CVE-2024-49767": {
        "service": "werkzeug",
        "steps": ["Upgrade Werkzeug to 3.1.0+", "Set request.max_form_parts limit"],
        "result": "CVE-2024-49767 fixed \u2014 form data resource exhaustion patched \u2713",
    },
    "CVE-2019-1010083": {
        "service": "flask",
        "steps": ["Upgrade Flask to 1.0+", "Disable debug mode in production", "Set TRAP_BAD_REQUEST_ERRORS=False"],
        "result": "CVE-2019-1010083 fixed \u2014 unexpected DoS patched \u2713",
    },
}

# Port → canonical service name for fast lookup
_PORT_TO_SERVICE: Dict[int, str] = {}
for _svc, _meta in _PATCH_CATALOG.items():
    for _p in _meta["ports"]:
        _PORT_TO_SERVICE[_p] = _svc

# Idempotency tracker: set of patch keys already applied
_applied_patches: Set[str] = set()
_applied_cve_fixes: Set[str] = set()


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

    Handles two event types:
      - response_complete → service-level hardening from the patch catalogue
      - vulnerability_found → CVE-specific targeted fixes from scanner pipeline

    Call register() once during system initialisation to wire the subscription.
    Patching is idempotent — the same service:port or CVE is only patched once.

    Emits:
        patch_complete — after each successful patch application
    """

    def __init__(self) -> None:
        self.patch_count: int = 0
        self.cve_fix_count: int = 0

    # ------------------------------------------------------------------
    # Subscription wiring
    # ------------------------------------------------------------------

    def register(self) -> None:
        """Subscribe to response_complete and vulnerability_found events."""
        event_bus.subscribe("response_complete", self._on_response_complete)
        event_bus.subscribe("vulnerability_found", self._on_vulnerability_found)

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

    # ------------------------------------------------------------------
    # CVE-specific fix handler
    # ------------------------------------------------------------------

    async def _on_vulnerability_found(
        self, event_type: str, data: Dict[str, Any]
    ) -> None:
        """vulnerability_found → apply CVE-specific fix if available."""
        cve_id = data.get("cve_id", "")
        if not cve_id:
            return

        # Idempotency: don't fix the same CVE twice
        if cve_id in _applied_cve_fixes:
            return

        fix_entry = _CVE_FIX_CATALOG.get(cve_id)
        if not fix_entry:
            # Fall back to service-level hardening
            service = data.get("service", "")
            port = data.get("port")
            if service or port:
                await self._on_response_complete(event_type, {
                    "service": service,
                    "port": port,
                })
            return

        host = data.get("host", "unknown")
        port = data.get("port", 0)
        service = data.get("service", fix_entry.get("service", "unknown"))
        severity = data.get("severity", "unknown")

        ts = _ts()
        print(
            f"{ts} > cve_fix({json.dumps({'cve': cve_id, 'service': service, 'host': host, 'severity': severity})})"
        )

        # Simulate applying CVE-specific fix steps
        for step in fix_entry["steps"]:
            await asyncio.sleep(0.08)  # simulate package download / config change
            logger.debug(f"AutoPatcher [CVE {cve_id}]: {step}")

        _applied_cve_fixes.add(cve_id)
        self.cve_fix_count += 1
        self.patch_count += 1

        ts = _ts()
        print(f"{ts} < cve_fix: {fix_entry['result']}")

        await event_bus.emit("patch_complete", {
            "service": service,
            "port": port,
            "cve_id": cve_id,
            "action": "cve_fix",
            "steps_applied": fix_entry["steps"],
            "status": "CVE_FIXED",
            "severity": severity,
        })
