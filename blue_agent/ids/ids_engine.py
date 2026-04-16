"""Intrusion Detection System (IDS) Engine.

Subscribes to Red team findings via the EventBus and generates real-time
intrusion alerts. Each detected attack pattern is broadcast as a tool call
to the Blue dashboard.

Alert categories:
  sql_injection, brute_force, port_scan, data_exfiltration,
  credential_theft, unauthorized_access, tech_disclosure
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.event_bus import event_bus

_CATEGORY_TO_SIGNATURE: Dict[str, Dict[str, str]] = {
    "sql_injection":       {"name": "SQL Injection Attempt",        "rule": "SIG-001", "mitre": "T1190"},
    "sql_injection_fix":   {"name": "SQL Injection Attempt",        "rule": "SIG-001", "mitre": "T1190"},
    "credential_theft":    {"name": "Credential Harvesting",        "rule": "SIG-002", "mitre": "T1078"},
    "password_hashing":    {"name": "Plaintext Credential Exposure", "rule": "SIG-003", "mitre": "T1552"},
    "data_exfiltration":   {"name": "Data Exfiltration Detected",   "rule": "SIG-004", "mitre": "T1041"},
    "database_compromised":{"name": "Database Breach Detected",     "rule": "SIG-005", "mitre": "T1005"},
    "rate_limiting":       {"name": "Brute Force / Flood Detected", "rule": "SIG-006", "mitre": "T1110"},
    "waf_deployment":      {"name": "Web Application Attack",       "rule": "SIG-007", "mitre": "T1190"},
    "admin_separation":    {"name": "Privilege Escalation Risk",    "rule": "SIG-008", "mitre": "T1078.004"},
    "captcha":             {"name": "Bot / Automation Detected",    "rule": "SIG-009", "mitre": "T1589"},
    "open_port":           {"name": "Port Scan Detected",           "rule": "SIG-010", "mitre": "T1046"},
    "tech_disclosure":     {"name": "Tech Stack Fingerprinting",    "rule": "SIG-011", "mitre": "T1592"},
    "endpoint_discovered": {"name": "Directory Traversal / Recon",  "rule": "SIG-012", "mitre": "T1083"},
    "server_hardening":    {"name": "Server Misconfiguration Found", "rule": "SIG-013", "mitre": "T1082"},
    "idor_protection":     {"name": "IDOR Vulnerability Detected",  "rule": "SIG-014", "mitre": "T1212"},
}


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


class IDSEngine:
    """Real-time Intrusion Detection System.

    Subscribes to the event bus and raises alerts when Red team attack
    patterns are detected. Each alert is broadcast to the dashboard as
    a tool_call event.
    """

    def __init__(self) -> None:
        self.alerts: List[Dict[str, Any]] = []
        self.total_alerts: int = 0
        self.alerts_by_severity: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        self._registered: bool = False
        self._broadcast_cb = None

    def set_broadcast(self, cb) -> None:
        self._broadcast_cb = cb

    def _broadcast(self, payload: dict) -> None:
        if self._broadcast_cb:
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.ensure_future(self._broadcast_cb(payload))
            except RuntimeError:
                pass

    def register(self) -> None:
        """Subscribe to Red team findings (idempotent)."""
        if self._registered:
            return
        self._registered = True
        event_bus.subscribe("red_finding_received", self._on_finding)
        print(f"{_ts()} [IDS] Engine registered — monitoring for intrusions")

    async def _on_finding(self, event_type: str, data: Dict[str, Any]) -> None:
        """Handle a Red finding → raise an IDS alert."""
        finding = data.get("finding", {})
        category = finding.get("category", "")
        severity = finding.get("severity", "medium")
        description = finding.get("description", "")
        endpoint = finding.get("endpoint", "")

        sig = _CATEGORY_TO_SIGNATURE.get(category)
        if not sig:
            return  # No signature match — unknown category

        alert_id = str(uuid.uuid4())
        alert = {
            "alert_id": alert_id,
            "rule": sig["rule"],
            "signature": sig["name"],
            "mitre_attack": sig["mitre"],
            "category": category,
            "severity": severity,
            "description": description,
            "endpoint": endpoint or None,
            "status": "ALERT",
            "timestamp": datetime.now().isoformat(),
        }
        self.alerts.append(alert)
        self.total_alerts += 1
        self.alerts_by_severity[severity] = self.alerts_by_severity.get(severity, 0) + 1

        ts = _ts()
        print(
            f"{ts} [IDS] {sig['rule']} TRIGGERED: {sig['name']} "
            f"[{severity.upper()}] {description[:60]}"
        )

        # Broadcast as a tool_call to the Blue dashboard
        self._broadcast({
            "type": "tool_call",
            "payload": {
                "id": alert_id,
                "name": "ids_alert",
                "category": "ids",
                "status": "DONE",
                "params": {
                    "rule": sig["rule"],
                    "signature": sig["name"],
                    "mitre": sig["mitre"],
                    "endpoint": endpoint or "N/A",
                },
                "result": {
                    "alert_id": alert_id,
                    "severity": severity,
                    "detail": description[:80],
                    "status": "ALERT",
                },
                "started_at": datetime.now().isoformat(),
                "finished_at": datetime.now().isoformat(),
            },
        })

        # Also log it
        self._broadcast({
            "type": "log",
            "payload": {
                "timestamp": datetime.now().isoformat(),
                "level": "WARN" if severity in ("critical", "high") else "INFO",
                "message": f"[IDS] {sig['rule']} — {sig['name']}: {description[:80]}",
            },
        })

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.alerts[-limit:]

    def get_status(self) -> Dict[str, Any]:
        return {
            "active": self._registered,
            "total_alerts": self.total_alerts,
            "alerts_by_severity": self.alerts_by_severity,
            "signatures_loaded": len(_CATEGORY_TO_SIGNATURE),
            "recent_alerts": self.alerts[-10:],
        }
