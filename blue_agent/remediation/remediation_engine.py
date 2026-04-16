"""Remediation Engine — receives Red findings and queues fixes for approval.

Subscribes to red_finding_received events from the EventBus. As each finding
arrives (while the Red Agent is still scanning), the engine queues the
appropriate fix for user approval before applying it.

Approval workflow:
  - Red Agent publishes findings as they're discovered
  - Blue Remediation Engine adds them to a pending-approval queue
  - The user reviews pending fixes via get_pending_fixes()
  - Fixes are applied only after explicit approval via approve_fix() / approve_all()
  - Fixes can be rejected via reject_fix()

The engine maps each finding category to a specific fix action:
  sql_injection          → fix_sql_injection()
  credential_theft       → fix_plaintext_passwords()
  data_exfiltration      → fix_secure_database()
  database_compromised   → fix_secure_database()
  rate_limiting          → fix_rate_limiting()
  waf_deployment         → fix_deploy_waf()
  admin_separation       → fix_admin_separation()
  captcha                → fix_add_captcha()
  password_hashing       → fix_plaintext_passwords()
  sql_injection_fix      → fix_sql_injection()
  server_hardening       → fix_server_hardening()
  idor_protection        → fix_idor_protection()

Emits:
  remediation_started  — when a finding is received and queued
  remediation_complete — when an approved fix succeeds
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.event_bus import event_bus
from blue_agent.remediation.flask_fixer import FlaskFixer

logger = logging.getLogger(__name__)


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


# ---------------------------------------------------------------------------
# Category → fix action mapping
# ---------------------------------------------------------------------------

_CATEGORY_TO_FIX = {
    # Direct vulnerability categories
    "sql_injection": "fix_sql_injection",
    "sql_injection_fix": "fix_sql_injection",
    "credential_theft": "fix_plaintext_passwords",
    "password_hashing": "fix_plaintext_passwords",
    "data_exfiltration": "fix_secure_database",
    "database_compromised": "fix_secure_database",
    "rate_limiting": "fix_rate_limiting",
    "waf_deployment": "fix_deploy_waf",
    "admin_separation": "fix_admin_separation",
    "captcha": "fix_add_captcha",
    "server_hardening": "fix_server_hardening",
    "idor_protection": "fix_idor_protection",
    # Recon categories that trigger hardening
    "open_port": "fix_server_hardening",
    "tech_disclosure": "fix_server_hardening",
    "endpoint_discovered": "fix_deploy_waf",
}


class RemediationEngine:
    """Receives Red team findings via EventBus and queues fixes for approval.

    Usage::

        engine = RemediationEngine()
        engine.register()  # subscribe to EventBus
        # Findings arrive and are queued — user must approve before they run
    """

    def __init__(self) -> None:
        self.flask_fixer = FlaskFixer()
        self.findings_received: int = 0
        self.fixes_dispatched: int = 0
        self.findings_log: List[Dict[str, Any]] = []
        self._running: bool = False
        self._pending_fixes: List[Dict[str, Any]] = []
        self._registered: bool = False

    # ------------------------------------------------------------------
    # Subscription wiring
    # ------------------------------------------------------------------

    def register(self) -> None:
        """Subscribe to Red team findings on the EventBus (idempotent)."""
        if self._registered:
            return
        self._registered = True
        event_bus.subscribe("red_finding_received", self._on_finding)
        event_bus.subscribe("red_report_complete", self._on_report_complete)
        ts = _ts()
        print(
            f"{ts} < remediation_engine: Subscribed to Red findings — "
            f"ready for approval-based remediation"
        )

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    async def _on_finding(self, event_type: str, data: Dict[str, Any]) -> None:
        """Handle a single Red team finding — queue the fix for approval."""
        finding = data.get("finding", {})
        target = data.get("target", "unknown")
        self.findings_received += 1
        self.findings_log.append(finding)

        category = finding.get("category", "")
        severity = finding.get("severity", "medium")
        description = finding.get("description", "")

        ts = _ts()
        print(
            f"{ts} < remediation_engine: [{severity.upper()}] Received finding: "
            f"{category} — {description[:60]}"
        )

        # Emit that we're starting remediation (queuing for approval)
        await event_bus.emit("remediation_started", {
            "finding_id": finding.get("id", ""),
            "category": category,
            "severity": severity,
        })

        # Look up the fix action for this category
        fix_method_name = _CATEGORY_TO_FIX.get(category)

        if fix_method_name:
            fix_id = str(uuid.uuid4())
            endpoint = finding.get("endpoint", "")
            pending_entry: Dict[str, Any] = {
                "fix_id": fix_id,
                "category": category,
                "severity": severity,
                "description": description,
                "endpoint": endpoint or None,
                "fix_method_name": fix_method_name,
                "finding": finding,
                "status": "pending_approval",
            }
            self._pending_fixes.append(pending_entry)

            ts = _ts()
            print(
                f"{ts} < remediation_engine: Queued fix {fix_method_name} "
                f"({fix_id[:8]}...) for approval"
            )
        else:
            ts = _ts()
            print(
                f"{ts} < remediation_engine: No specific fix mapped for "
                f"category '{category}' — logged for manual review"
            )

    async def _on_report_complete(self, event_type: str, data: Dict[str, Any]) -> None:
        """Handle the completion of a full Red team report."""
        total = data.get("total_findings", 0)
        severity_counts = data.get("severity_counts", {})

        pending_count = len(self._pending_fixes)
        ts = _ts()
        print(f"\n{ts} ╔═══════════════════════════════════════════════════════════════╗")
        print(f"{ts} ║  REMEDIATION SUMMARY                                         ║")
        print(f"{ts} ╠═══════════════════════════════════════════════════════════════╣")
        print(f"{ts} ║  Findings received: {self.findings_received:<40}║")
        print(f"{ts} ║  Fixes dispatched:  {self.fixes_dispatched:<40}║")
        print(f"{ts} ║  Pending approval:  {pending_count:<40}║")
        print(f"{ts} ║  Total fix steps:   {self.flask_fixer.total_steps:<40}║")
        print(f"{ts} ╠═══════════════════════════════════════════════════════════════╣")
        print(f"{ts} ║  Applied fixes:                                              ║")
        for fix in self.flask_fixer.get_applied_fixes():
            fix_name = fix.get("fix_id", "")[:45]
            status = fix.get("status", "")
            print(f"{ts} ║    ✓ {fix_name:<44} {status:>8} ║")
        if pending_count:
            print(f"{ts} ║  Pending fixes (awaiting approval):                          ║")
            for pf in self._pending_fixes:
                pf_name = pf["fix_method_name"][:45]
                print(f"{ts} ║    ⏳ {pf_name:<44} pending  ║")
        print(f"{ts} ╚═══════════════════════════════════════════════════════════════╝\n")

    # ------------------------------------------------------------------
    # Approval workflow
    # ------------------------------------------------------------------

    def get_pending_fixes(self) -> List[Dict[str, Any]]:
        """Return all fixes currently awaiting approval."""
        return [
            {
                "fix_id": pf["fix_id"],
                "category": pf["category"],
                "severity": pf["severity"],
                "description": pf["description"],
                "endpoint": pf.get("endpoint"),
                "status": pf["status"],
                "finding_details": pf["finding"],
            }
            for pf in self._pending_fixes
        ]

    async def approve_fix(self, fix_id: str) -> Dict[str, Any]:
        """Approve and apply a single pending fix by its fix_id.

        Returns a dict with fix_id, status, and fix_result.
        Raises ValueError if the fix_id is not found in the pending queue.
        """
        target_idx: Optional[int] = None
        for idx, pf in enumerate(self._pending_fixes):
            if pf["fix_id"] == fix_id:
                target_idx = idx
                break

        if target_idx is None:
            raise ValueError(f"No pending fix found with fix_id={fix_id}")

        pending_entry = self._pending_fixes.pop(target_idx)
        result = await self._apply_fix(pending_entry)
        return result

    async def approve_all(self) -> List[Dict[str, Any]]:
        """Approve and apply every pending fix. Returns list of results."""
        results: List[Dict[str, Any]] = []
        while self._pending_fixes:
            pending_entry = self._pending_fixes.pop(0)
            result = await self._apply_fix(pending_entry)
            results.append(result)
        return results

    def reject_fix(self, fix_id: str) -> Dict[str, Any]:
        """Reject a pending fix, removing it from the queue.

        Returns a dict with fix_id and status='rejected'.
        Raises ValueError if the fix_id is not found.
        """
        target_idx: Optional[int] = None
        for idx, pf in enumerate(self._pending_fixes):
            if pf["fix_id"] == fix_id:
                target_idx = idx
                break

        if target_idx is None:
            raise ValueError(f"No pending fix found with fix_id={fix_id}")

        removed = self._pending_fixes.pop(target_idx)
        ts = _ts()
        print(
            f"{ts} < remediation_engine: Rejected fix "
            f"{removed['fix_method_name']} ({fix_id[:8]}...)"
        )
        return {"fix_id": fix_id, "status": "rejected", "fix_result": None}

    # ------------------------------------------------------------------
    # Internal: apply a single fix entry
    # ------------------------------------------------------------------

    async def _apply_fix(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the fix described by *entry* and emit completion events."""
        fix_method_name = entry["fix_method_name"]
        category = entry["category"]
        severity = entry["severity"]
        fix_id = entry["fix_id"]
        finding = entry["finding"]

        fix_method = getattr(self.flask_fixer, fix_method_name, None)
        if not fix_method:
            return {
                "fix_id": fix_id,
                "status": "approved",
                "fix_result": {"error": f"Method {fix_method_name} not found on FlaskFixer"},
            }

        try:
            endpoint = entry.get("endpoint", "")
            if fix_method_name in ("fix_sql_injection", "fix_rate_limiting", "fix_idor_protection") and endpoint:
                result = await fix_method(endpoint)
            else:
                result = await fix_method()

            self.fixes_dispatched += 1

            await event_bus.emit("remediation_complete", {
                "finding_id": finding.get("id", ""),
                "category": category,
                "severity": severity,
                "fix": fix_method_name,
                "result": result,
                "status": "FIXED",
            })

            ts = _ts()
            print(
                f"{ts} < remediation_engine: Approved & applied "
                f"{fix_method_name} ({fix_id[:8]}...)"
            )

            return {"fix_id": fix_id, "status": "approved", "fix_result": result}

        except Exception as exc:
            logger.error(f"RemediationEngine: fix failed for {category}: {exc}")
            ts = _ts()
            print(f"{ts} < remediation_engine: Fix FAILED for {category}: {exc}")
            return {
                "fix_id": fix_id,
                "status": "approved",
                "fix_result": {"error": str(exc)},
            }

    # ------------------------------------------------------------------
    # Manual trigger — queue all fixes from a full report
    # ------------------------------------------------------------------

    async def remediate_full_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Process a full Red team report and queue all fixes for approval.

        Populates _pending_fixes synchronously by parsing the report directly —
        no event-bus queue timing dependency. Also emits streaming events for
        the dashboard.
        """
        from red_agent.report_ingester import parse_report

        target = report.get("target", "unknown")
        risk_score = report.get("risk_score", 0.0)

        findings = parse_report(report)
        print(f"{_ts()} < remediation_engine: parse_report returned {len(findings)} findings")

        severity_counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }

        # Build pending_list DIRECTLY in the loop — no separate state read needed
        pending_list: List[Dict[str, Any]] = []

        for finding in findings:
            category = finding.get("category", "")
            severity = finding.get("severity", "medium")
            description = finding.get("description", "")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            self.findings_received += 1
            self.findings_log.append(finding)

            print(
                f"{_ts()} < remediation_engine: [{severity.upper()}] {category} — "
                f"{description[:60]}"
            )

            # Emit for real-time dashboard streaming (non-blocking)
            await event_bus.emit("remediation_started", {
                "finding_id": finding.get("id", ""),
                "category": category,
                "severity": severity,
            })

            # Queue fix for approval directly — guaranteed, no timing race
            fix_method_name = _CATEGORY_TO_FIX.get(category)
            if fix_method_name:
                fix_id = str(uuid.uuid4())
                endpoint = finding.get("endpoint", "")
                internal_entry: Dict[str, Any] = {
                    "fix_id": fix_id,
                    "category": category,
                    "severity": severity,
                    "description": description,
                    "endpoint": endpoint or None,
                    "fix_method_name": fix_method_name,
                    "finding": finding,
                    "status": "pending_approval",
                }
                self._pending_fixes.append(internal_entry)
                # Build the API-facing dict in the same step — no second pass needed
                pending_list.append({
                    "fix_id": fix_id,
                    "category": category,
                    "severity": severity,
                    "description": description,
                    "endpoint": endpoint or None,
                    "status": "pending_approval",
                    "finding_details": finding,
                })
                print(
                    f"{_ts()} < remediation_engine: Queued {fix_method_name} "
                    f"({fix_id[:8]}...) for approval"
                )
            else:
                print(f"{_ts()} < remediation_engine: No fix mapped for '{category}'")

        summary = {
            "target": target,
            "risk_score": risk_score,
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "findings_published": len(findings),
        }
        await event_bus.emit("red_report_complete", summary)

        print(f"{_ts()} < remediation_engine: {len(pending_list)} fixes queued for approval — returning pending_fixes_list")

        return {
            "report_summary": summary,
            "pending_fixes_list": pending_list,
            "remediation": {
                "findings_received": self.findings_received,
                "fixes_applied": self.fixes_dispatched,
                "pending_fixes": len(self._pending_fixes),
                "total_steps": self.flask_fixer.total_steps,
                "applied_fixes": self.flask_fixer.get_applied_fixes(),
            },
        }

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        return {
            "findings_received": self.findings_received,
            "fixes_dispatched": self.fixes_dispatched,
            "total_steps": self.flask_fixer.total_steps,
            "applied_fixes": self.flask_fixer.get_applied_fixes(),
        }
