"""SIEM (Security Information and Event Management) Engine.

Aggregates events from the IDS, RemediationEngine, and EventBus into a
correlated security timeline. Produces attack-chain summaries and a
risk dashboard that the Blue team operator can review.

Event sources:
  - red_finding_received  → ingests raw Red findings
  - remediation_started   → tracks when fixes begin
  - remediation_complete  → records resolved findings
  - IDS alerts            → pull from IDSEngine.get_alerts()
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List

from core.event_bus import event_bus

_ATTACK_PHASE_MAP: Dict[str, str] = {
    "open_port":           "Reconnaissance",
    "tech_disclosure":     "Reconnaissance",
    "endpoint_discovered": "Reconnaissance",
    "sql_injection":       "Exploitation",
    "sql_injection_fix":   "Exploitation",
    "database_compromised":"Exploitation",
    "data_exfiltration":   "Exfiltration",
    "credential_theft":    "Exfiltration",
    "password_hashing":    "Persistence",
    "rate_limiting":       "Impact",
    "waf_deployment":      "Defense Evasion",
    "admin_separation":    "Privilege Escalation",
    "captcha":             "Defense Evasion",
    "server_hardening":    "Persistence",
    "idor_protection":     "Exploitation",
}


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


class SIEMEngine:
    """Security Information and Event Management engine.

    Correlates events across the Red/Blue pipeline and produces
    a real-time security report for the operator.
    """

    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []
        self.attack_timeline: List[Dict[str, Any]] = []
        self.phase_counts: Dict[str, int] = {}
        self.severity_counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        self.remediated_count: int = 0
        self.active_threats: int = 0
        self._registered: bool = False
        self._broadcast_cb = None
        self._report_id: str = str(uuid.uuid4())

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
        """Subscribe to all relevant events (idempotent)."""
        if self._registered:
            return
        self._registered = True
        event_bus.subscribe("red_finding_received",  self._on_finding)
        event_bus.subscribe("remediation_started",   self._on_remediation_started)
        event_bus.subscribe("remediation_complete",  self._on_remediation_complete)
        event_bus.subscribe("red_report_complete",   self._on_report_complete)
        print(f"{_ts()} [SIEM] Engine registered — aggregating security events")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    async def _on_finding(self, event_type: str, data: Dict[str, Any]) -> None:
        finding = data.get("finding", {})
        category = finding.get("category", "")
        severity = finding.get("severity", "medium")
        phase = _ATTACK_PHASE_MAP.get(category, "Unknown")

        self.severity_counts[severity] = self.severity_counts.get(severity, 0) + 1
        self.phase_counts[phase] = self.phase_counts.get(phase, 0) + 1
        self.active_threats += 1

        event_entry = {
            "event_id": str(uuid.uuid4()),
            "source": "red_agent",
            "type": "threat_detected",
            "phase": phase,
            "category": category,
            "severity": severity,
            "description": finding.get("description", ""),
            "timestamp": datetime.now().isoformat(),
            "status": "active",
        }
        self.events.append(event_entry)
        self.attack_timeline.append({
            "time": _ts(),
            "phase": phase,
            "event": f"{category.replace('_', ' ').title()} [{severity.upper()}]",
            "source": "Red Agent",
        })

        print(f"{_ts()} [SIEM] Event ingested: {phase} — {category} [{severity}]")

    async def _on_remediation_started(self, event_type: str, data: Dict[str, Any]) -> None:
        category = data.get("category", "")
        self.events.append({
            "event_id": str(uuid.uuid4()),
            "source": "blue_agent",
            "type": "remediation_queued",
            "category": category,
            "severity": data.get("severity", ""),
            "timestamp": datetime.now().isoformat(),
            "status": "queued",
        })

    async def _on_remediation_complete(self, event_type: str, data: Dict[str, Any]) -> None:
        category = data.get("category", "")
        self.remediated_count += 1
        self.active_threats = max(0, self.active_threats - 1)

        self.events.append({
            "event_id": str(uuid.uuid4()),
            "source": "blue_agent",
            "type": "remediation_applied",
            "category": category,
            "fix": data.get("fix", ""),
            "timestamp": datetime.now().isoformat(),
            "status": "resolved",
        })
        self.attack_timeline.append({
            "time": _ts(),
            "phase": "Remediation",
            "event": f"Fix applied: {data.get('fix', category)} [{data.get('severity', '')}]",
            "source": "Blue Agent",
        })
        print(f"{_ts()} [SIEM] Remediation logged: {category}")

    async def _on_report_complete(self, event_type: str, data: Dict[str, Any]) -> None:
        total = data.get("total_findings", 0)
        print(f"{_ts()} [SIEM] Red report complete — {total} findings ingested")

        # Broadcast SIEM correlation report to dashboard
        report = self.get_report()
        self._broadcast({
            "type": "tool_call",
            "payload": {
                "id": str(uuid.uuid4()),
                "name": "siem_correlate",
                "category": "siem",
                "status": "DONE",
                "params": {"report_id": self._report_id},
                "result": {
                    "total_events": report["total_events"],
                    "active_threats": report["active_threats"],
                    "remediated": report["remediated_count"],
                    "risk_score": report["risk_score"],
                    "detail": f"Correlated {total} findings across {len(self.phase_counts)} attack phases",
                },
                "started_at": datetime.now().isoformat(),
                "finished_at": datetime.now().isoformat(),
            },
        })
        self._broadcast({
            "type": "log",
            "payload": {
                "timestamp": datetime.now().isoformat(),
                "level": "INFO",
                "message": (
                    f"[SIEM] Correlation complete — {total} events | "
                    f"Risk Score: {report['risk_score']}/10 | "
                    f"Phases: {', '.join(self.phase_counts.keys())}"
                ),
            },
        })

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def get_report(self) -> Dict[str, Any]:
        """Return the current correlated security report."""
        total_events = len(self.events)
        critical = self.severity_counts.get("critical", 0)
        high = self.severity_counts.get("high", 0)
        medium = self.severity_counts.get("medium", 0)

        # Simple risk score: weighted sum capped at 10
        raw = critical * 2.0 + high * 1.0 + medium * 0.5
        risk_score = round(min(10.0, raw), 1)

        return {
            "report_id": self._report_id,
            "generated_at": datetime.now().isoformat(),
            "total_events": total_events,
            "active_threats": self.active_threats,
            "remediated_count": self.remediated_count,
            "risk_score": risk_score,
            "severity_counts": self.severity_counts,
            "phase_counts": self.phase_counts,
            "attack_timeline": self.attack_timeline[-20:],
            "top_threats": [
                e for e in self.events
                if e.get("severity") in ("critical", "high") and e.get("status") == "active"
            ][-10:],
        }

    def get_status(self) -> Dict[str, Any]:
        return {
            "active": self._registered,
            "total_events": len(self.events),
            "active_threats": self.active_threats,
            "remediated_count": self.remediated_count,
            "severity_counts": self.severity_counts,
            "phase_counts": self.phase_counts,
        }
