"""Mission orchestrator — coordinates ReconAgent and ExploitAgent.

The orchestrator is a COORDINATOR. It:
  1. Receives a target from the user (frontend)
  2. Hands it to ReconAgent — lets it decide what to scan
  3. Listens to recon events in real-time, streams them to the frontend
  4. Collects recon findings, hands them to ExploitAgent
  5. Listens to exploit events in real-time, streams them to the frontend
  6. Generates structured MITRE ATT&CK report from both agents' results
  7. Publishes report on EventBus for Blue agent

All agent events flow:
  Agent → EventBus → Orchestrator → WebSocket → Frontend
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.event_bus import event_bus
from red_agent.backend.schemas.red_schemas import (
    LogEntry,
    MissionPhase,
    ToolCall,
    ToolStatus,
)

_logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════
# MITRE ATT&CK Mapping
# ══════════════════════════════════════════════════════════════════════

MITRE_MAP: dict[str, dict[str, str]] = {
    "sql_injection": {
        "tactic": "Initial Access",
        "technique": "T1190",
        "name": "Exploit Public-Facing Application",
        "mitigation": "M1030",
    },
    "lfi": {
        "tactic": "Initial Access",
        "technique": "T1190",
        "name": "Exploit Public-Facing Application",
        "mitigation": "M1030",
    },
    "path_traversal": {
        "tactic": "Collection",
        "technique": "T1005",
        "name": "Data from Local System",
        "mitigation": "M1041",
    },
    "command_injection": {
        "tactic": "Execution",
        "technique": "T1059",
        "name": "Command and Scripting Interpreter",
        "mitigation": "M1038",
    },
    "rce": {
        "tactic": "Execution",
        "technique": "T1059",
        "name": "Command and Scripting Interpreter",
        "mitigation": "M1038",
    },
    "brute_force": {
        "tactic": "Credential Access",
        "technique": "T1110",
        "name": "Brute Force",
        "mitigation": "M1032",
    },
    "xss": {
        "tactic": "Initial Access",
        "technique": "T1189",
        "name": "Drive-by Compromise",
        "mitigation": "M1021",
    },
    "ssrf": {
        "tactic": "Discovery",
        "technique": "T1046",
        "name": "Network Service Discovery",
        "mitigation": "M1031",
    },
    "default": {
        "tactic": "Initial Access",
        "technique": "T1190",
        "name": "Exploit Public-Facing Application",
        "mitigation": "M1030",
    },
}

_VULN_TYPE_ALIASES: dict[str, str] = {
    "sqli": "sql_injection", "sql": "sql_injection", "sql injection": "sql_injection",
    "lfi": "lfi", "local file inclusion": "lfi",
    "path traversal": "path_traversal", "traversal": "path_traversal", "directory traversal": "path_traversal",
    "command injection": "command_injection", "cmdi": "command_injection", "os command": "command_injection",
    "rce": "rce", "remote code execution": "rce",
    "brute force": "brute_force", "brute": "brute_force", "hydra": "brute_force",
    "xss": "xss", "cross-site scripting": "xss",
    "ssrf": "ssrf", "server-side request forgery": "ssrf",
}


def _resolve_mitre(vuln_type: str) -> dict[str, str]:
    key = vuln_type.lower().strip()
    if key in MITRE_MAP:
        return MITRE_MAP[key]
    resolved = _VULN_TYPE_ALIASES.get(key)
    if resolved:
        return MITRE_MAP[resolved]
    for alias, mitre_key in _VULN_TYPE_ALIASES.items():
        if alias in key or key in alias:
            return MITRE_MAP[mitre_key]
    return MITRE_MAP["default"]


def _classify_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    return "LOW"


def _risk_to_cvss(risk_score: float) -> float:
    return round(min(risk_score, 10.0), 1)


_RECOMMENDATIONS: dict[str, dict[str, str]] = {
    "sql_injection": {
        "priority": "CRITICAL",
        "action": "PATCH_SQL_INJECTION",
        "description": "Use parameterized queries / prepared statements. Deploy a WAF. Validate and sanitize all user input.",
        "mitre_mitigation": "M1030",
    },
    "lfi": {
        "priority": "HIGH",
        "action": "PATCH_LFI",
        "description": "Never use user input in file paths. Implement whitelist-based file access. Use chroot or containerization.",
        "mitre_mitigation": "M1030",
    },
    "path_traversal": {
        "priority": "HIGH",
        "action": "PATCH_PATH_TRAVERSAL",
        "description": "Canonicalize file paths before use. Reject any input containing '..' or path separators. Use chroot.",
        "mitre_mitigation": "M1041",
    },
    "command_injection": {
        "priority": "CRITICAL",
        "action": "PATCH_COMMAND_INJECTION",
        "description": "Never pass user input to system commands. Use language-native libraries. Run services with minimal OS privileges.",
        "mitre_mitigation": "M1038",
    },
    "rce": {
        "priority": "CRITICAL",
        "action": "PATCH_RCE",
        "description": "Patch vulnerable service immediately. Sandbox application processes. Implement strict input validation.",
        "mitre_mitigation": "M1038",
    },
    "brute_force": {
        "priority": "MEDIUM",
        "action": "HARDEN_AUTH",
        "description": "Implement account lockout after N failed attempts. Add CAPTCHA. Enforce strong password policies. Use MFA.",
        "mitre_mitigation": "M1032",
    },
    "xss": {
        "priority": "HIGH",
        "action": "PATCH_XSS",
        "description": "Encode all output. Use Content-Security-Policy headers. Sanitize user input on both client and server.",
        "mitre_mitigation": "M1021",
    },
    "ssrf": {
        "priority": "HIGH",
        "action": "PATCH_SSRF",
        "description": "Validate and whitelist outbound URLs. Block requests to internal/private IP ranges. Use network segmentation.",
        "mitre_mitigation": "M1031",
    },
}


# ══════════════════════════════════════════════════════════════════════
# Mission dataclass
# ══════════════════════════════════════════════════════════════════════

@dataclass
class Mission:
    id: str
    target: str
    phase: MissionPhase = MissionPhase.IDLE
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    _recon_result: Any = field(default=None, repr=False)
    _exploit_result: Any = field(default=None, repr=False)
    structured_report: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    _task: asyncio.Task | None = field(default=None, repr=False)
    _paused_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)

    # Compat fields for chat_routes / frontend
    recon_result: dict[str, Any] = field(default_factory=dict)
    exploit_result: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "target": self.target, "phase": self.phase.value,
            "created_at": self.created_at, "error": self.error,
        }


class MissionOrchestrator:

    def __init__(self) -> None:
        self._missions: dict[str, Mission] = {}

    # ── Mission lifecycle ────────────────────────────────────────────

    async def start_mission(self, target: str) -> Mission:
        mission = Mission(id=str(uuid.uuid4()), target=target)
        self._missions[mission.id] = mission
        mission._task = asyncio.create_task(self._run_mission(mission))
        mission._task.add_done_callback(
            lambda t: _logger.error("Mission task failed: %s", t.exception()) if t.exception() else None
        )
        await self._emit_log(mission, "INFO", f"Mission created against {target}")
        return mission

    async def pause_mission(self, mission_id: str) -> bool:
        m = self._missions.get(mission_id)
        if not m or m.phase in (MissionPhase.DONE, MissionPhase.FAILED):
            return False
        m.phase = MissionPhase.PAUSED
        await self._emit_log(m, "WARN", "Mission paused")
        return True

    async def resume_mission(self, mission_id: str) -> bool:
        m = self._missions.get(mission_id)
        if not m or m.phase != MissionPhase.PAUSED:
            return False
        m._paused_event.set()
        await self._emit_log(m, "INFO", "Mission resumed")
        return True

    async def abort_mission(self, mission_id: str) -> bool:
        m = self._missions.get(mission_id)
        if not m or m.phase in (MissionPhase.DONE, MissionPhase.FAILED):
            return False
        if m._task and not m._task.done():
            m._task.cancel()
        m.phase = MissionPhase.FAILED
        m.error = "Aborted by operator"
        await self._emit_log(m, "ERROR", "Mission aborted")
        return True

    def get_mission(self, mission_id: str) -> Mission | None:
        return self._missions.get(mission_id)

    def list_missions(self) -> list[dict]:
        return [m.to_dict() for m in self._missions.values()]

    # ══════════════════════════════════════════════════════════════════
    # Live event bridge — Agent EventBus → WebSocket → Frontend
    # ══════════════════════════════════════════════════════════════════

    def _build_event_handlers(self, mission: Mission) -> dict[str, Any]:
        """Create EventBus handlers that forward agent events to WebSocket.

        Returns a dict of {event_type: handler} so they can be
        subscribed before agents run and unsubscribed after.
        """
        # Track live tool-call cards so we can update RUNNING → DONE
        _live_tool_cards: dict[str, ToolCall] = {}

        async def on_recon_started(data: dict) -> None:
            await self._emit_chat(
                mission,
                f"**[Recon Agent]** Starting reconnaissance on `{data.get('target', mission.target)}`",
            )

        async def on_recon_cve_fetched(data: dict) -> None:
            count = data.get("cve_count", 0)
            if count > 0:
                await self._emit_chat(
                    mission,
                    f"**[Recon Agent]** Fetched **{count}** CVEs from NVD for threat intelligence",
                )
                await self._emit_log(mission, "INFO", f"Recon: {count} CVEs fetched from NVD")

        async def on_recon_tool_done(data: dict) -> None:
            tool_name = data.get("tool", "unknown")
            ok = data.get("ok", False)
            findings = data.get("finding_count", 0)
            status_icon = "done" if ok else "failed"

            # Create a tool_call card for this tool execution
            tc = self._make_tool_call(f"recon_{tool_name}", "scan", {
                "target": mission.target,
                "agent": "Recon Agent",
            })
            self._finish_tool_call(tc, {
                "ok": ok,
                "findings_count": findings,
            }, status=ToolStatus.DONE if ok else ToolStatus.FAILED)
            await self._emit_tool_call_ws(tc)

            await self._emit_chat(
                mission,
                f"**[Recon Agent]** `{tool_name}` {status_icon} — **{findings}** finding(s)",
            )
            await self._emit_log(
                mission,
                "INFO" if ok else "WARN",
                f"Recon: {tool_name} → {findings} findings",
            )

        async def on_exploit_started(data: dict) -> None:
            vectors = data.get("recon_vectors", 0)
            await self._emit_chat(
                mission,
                f"**[Exploit Agent]** Starting exploitation with **{vectors}** attack vector(s)",
            )

        async def on_exploit_tool_done(data: dict) -> None:
            tool_name = data.get("tool", "unknown")
            ok = data.get("ok", False)
            details = data.get("details", {})

            tc = self._make_tool_call(f"exploit_{tool_name}", "exploit", {
                "target": mission.target,
                "agent": "Exploit Agent",
            })
            self._finish_tool_call(tc, {
                "ok": ok,
                **{k: v for k, v in details.items() if k not in ("output",)},
            }, status=ToolStatus.DONE if ok else ToolStatus.FAILED)
            await self._emit_tool_call_ws(tc)

            # Build a human-readable summary of what the tool found
            summary_parts = [f"`{tool_name}` {'done' if ok else 'failed'}"]
            if details.get("databases"):
                summary_parts.append(f"databases: {details['databases']}")
            if details.get("tables"):
                summary_parts.append(f"tables: {list(details['tables'])}")
            if details.get("credentials_found"):
                count = len(details["credentials_found"])
                summary_parts.append(f"**{count} credential(s) exfiltrated!**")
            if details.get("rows_dumped"):
                summary_parts.append(f"{details['rows_dumped']} rows dumped")

            await self._emit_chat(
                mission,
                f"**[Exploit Agent]** {' — '.join(summary_parts)}",
            )
            await self._emit_log(
                mission,
                "INFO" if ok else "WARN",
                f"Exploit: {tool_name} → {json.dumps(details, default=str)[:120]}",
            )

        return {
            "recon.started": on_recon_started,
            "recon.cve_fetched": on_recon_cve_fetched,
            "recon.tool_done": on_recon_tool_done,
            "exploit.started": on_exploit_started,
            "exploit.tool_done": on_exploit_tool_done,
        }

    # ══════════════════════════════════════════════════════════════════
    # Main pipeline — orchestrator coordinates, agents decide
    # ══════════════════════════════════════════════════════════════════

    async def _run_mission(self, mission: Mission) -> None:
        from red_agent.scanner.recon_agent import ReconAgent
        from red_agent.exploiter.exploit_agent import ExploitAgent

        # Subscribe to agent events BEFORE they start
        handlers = self._build_event_handlers(mission)
        for event_type, handler in handlers.items():
            event_bus.subscribe(event_type, handler)

        try:
            # ── Phase 1: RECON ───────────────────────────────────────
            await self._emit_phase(mission, MissionPhase.RECON)
            await self._emit_chat(
                mission,
                f"Starting mission against **{mission.target}**\n\n"
                f"Handing off to Recon Agent — it will autonomously decide "
                f"what tools to run (nmap, nuclei, gobuster, sqlmap, etc.)\n\n"
                f"Watch the activity panel for live tool executions.",
            )

            recon_tc = self._make_tool_call("recon_agent", "scan", {"target": mission.target})
            await self._emit_tool_call_ws(recon_tc)

            recon_agent = ReconAgent(mission.target)
            recon_result = await recon_agent.run()

            mission._recon_result = recon_result
            mission.recon_result = recon_result.to_dict()

            self._finish_tool_call(recon_tc, {
                "status": recon_result.status,
                "vectors": len(recon_result.attack_vectors),
                "ports": recon_result.open_ports,
                "tools": recon_result.tools_run,
            })
            await self._emit_tool_call_ws(recon_tc)

            # Summarize recon to user
            vectors_summary = ""
            for v in recon_result.attack_vectors:
                vtype = v.get("type", "unknown")
                path = v.get("path", "")
                prio = v.get("priority", "?")
                vectors_summary += f"\n  - **{vtype}** at `{path}` (priority: {prio})"

            await self._emit_chat(
                mission,
                f"**Recon complete** ({recon_result.duration_seconds:.1f}s)\n\n"
                f"Open ports: `{recon_result.open_ports or 'none'}`\n"
                f"Tech stack: {', '.join(recon_result.tech_stack) or 'unknown'}\n"
                f"Risk score: **{recon_result.risk_score}/10**\n"
                f"Tools used: {', '.join(recon_result.tools_run)}\n\n"
                f"**Attack vectors found ({len(recon_result.attack_vectors)}):**"
                f"{vectors_summary or '\n  None identified.'}",
            )

            # ── Phase 2: EXPLOIT ─────────────────────────────────────
            await self._emit_phase(mission, MissionPhase.EXPLOIT)

            if not recon_result.attack_vectors:
                await self._emit_chat(
                    mission,
                    "No attack vectors found during recon. Skipping exploitation phase.",
                )
            else:
                primary_vuln = recon_result.attack_vectors[0].get("type", "unknown")
                await self._emit_chat(
                    mission,
                    f"Handing **{len(recon_result.attack_vectors)}** attack vector(s) "
                    f"to Exploit Agent.\n\n"
                    f"Primary vulnerability: **{primary_vuln}**\n"
                    f"Exploit Agent will autonomously pick the attack strategy.",
                )

                exploit_tc = self._make_tool_call("exploit_agent", "exploit", {
                    "target": mission.target,
                    "vectors": len(recon_result.attack_vectors),
                    "primary_vuln": primary_vuln,
                })
                await self._emit_tool_call_ws(exploit_tc)

                exploit_agent = ExploitAgent(
                    target_url=mission.target,
                    recon_session_id=recon_result.session_id,
                    vulnerability_type=primary_vuln,
                    recon_context=recon_result.attack_vectors,
                )
                exploit_result = await exploit_agent.run()

                mission._exploit_result = exploit_result
                mission.exploit_result = exploit_result.to_dict()

                self._finish_tool_call(exploit_tc, {
                    "status": exploit_result.status,
                    "databases": exploit_result.databases_found,
                    "credentials": len(exploit_result.credentials_found),
                    "tools": exploit_result.tools_run,
                })
                await self._emit_tool_call_ws(exploit_tc)

                # Summarize exploitation to user
                creds_text = ""
                if exploit_result.credentials_found:
                    creds_text = "\n\n**Credentials exfiltrated:**"
                    for c in exploit_result.credentials_found:
                        u = c.get("username", "?")
                        p = c.get("password_hash", "?")
                        creds_text += f"\n  - `{u}` : `{p}`"

                await self._emit_chat(
                    mission,
                    f"**Exploitation complete** ({exploit_result.duration_seconds:.1f}s)\n\n"
                    f"DBMS: {exploit_result.dbms or 'N/A'}\n"
                    f"Databases: {exploit_result.databases_found or 'none'}\n"
                    f"Data dumps: {len(exploit_result.data_exfiltrated)}\n"
                    f"Tools used: {', '.join(exploit_result.tools_run)}"
                    f"{creds_text}",
                )

            # ── Phase 3: REPORT ──────────────────────────────────────
            await self._emit_phase(mission, MissionPhase.REPORT)
            await self._emit_chat(
                mission,
                "Generating structured report with MITRE ATT&CK mappings...",
            )

            report_tc = self._make_tool_call("generate_report", "strategy", {"mission_id": mission.id})
            await self._emit_tool_call_ws(report_tc)

            report = self._generate_structured_report(mission)
            mission.structured_report = report

            await event_bus.publish("report.generated", report)

            self._finish_tool_call(report_tc, {"status": "complete", "report_id": report["report_id"]})
            await self._emit_tool_call_ws(report_tc)

            vuln_count = len(report.get("vulnerabilities", []))
            cred_count = len(report.get("exploitation_results", {}).get("credentials_exfiltrated", []))
            rec_count = len(report.get("recommendations", []))

            # Final summary with full report details
            vuln_lines = ""
            for v in report.get("vulnerabilities", []):
                exploited = " **(EXPLOITED)**" if v.get("exploited") else ""
                vuln_lines += (
                    f"\n  - `{v['id']}` **{v['type']}** [{v['severity']}] "
                    f"at `{v['location']}` — {v['mitre_attack']['technique']}{exploited}"
                )

            rec_lines = ""
            for r in report.get("recommendations", []):
                rec_lines += f"\n  - [{r['priority']}] {r['action']}: {r['description'][:80]}"

            await self._emit_chat(
                mission,
                f"**MISSION REPORT**\n\n"
                f"Report ID: `{report['report_id']}`\n"
                f"Target: `{report['target']}`\n"
                f"Overall Risk: **{report['overall_risk']}** ({report['risk_score']}/10)\n\n"
                f"**Vulnerabilities ({vuln_count}):**{vuln_lines or ' None'}\n\n"
                f"**Exploitation:**\n"
                f"  Credentials exfiltrated: {cred_count}\n"
                f"  Data breach severity: "
                f"{report.get('exploitation_results', {}).get('data_breach_severity', 'N/A')}\n\n"
                f"**Recommendations ({rec_count}):**{rec_lines}\n\n"
                f"Report published to Blue Team agent via EventBus.",
            )

            # ── DONE ─────────────────────────────────────────────────
            await self._emit_phase(mission, MissionPhase.DONE)

        except asyncio.CancelledError:
            mission.phase = MissionPhase.FAILED
            mission.error = "Aborted by operator"
        except Exception as exc:
            mission.phase = MissionPhase.FAILED
            mission.error = str(exc)
            await self._emit_log(mission, "ERROR", f"Mission failed: {exc}")
            _logger.exception("Mission %s error", mission.id[:8])
        finally:
            # Always unsubscribe — don't leak handlers across missions
            for event_type, handler in handlers.items():
                event_bus.unsubscribe(event_type, handler)

    # ══════════════════════════════════════════════════════════════════
    # Structured Report Generation
    # ══════════════════════════════════════════════════════════════════

    def _generate_structured_report(self, mission: Mission) -> dict[str, Any]:
        """Build structured JSON report directly from agent results on the mission."""

        now = datetime.now(timezone.utc).isoformat()
        recon = mission._recon_result
        exploit = mission._exploit_result

        open_ports = recon.open_ports if recon else []
        tech_stack = recon.tech_stack if recon else []
        attack_vectors = recon.attack_vectors if recon else []
        risk_score = recon.risk_score if recon else 0.0

        reconnaissance = {
            "open_ports": open_ports,
            "tech_stack": tech_stack,
            "attack_surface": (
                "web_application"
                if any(p in open_ports for p in [80, 443, 5000, 8080, 8443, 3000])
                else "network"
            ),
        }

        # ── Vulnerabilities ──
        vulnerabilities = []
        seen_types: set[str] = set()

        for i, vec in enumerate(attack_vectors, 1):
            vtype = vec.get("type", "unknown").upper().replace(" ", "_")
            raw_type = vec.get("type", "unknown")
            mitre = _resolve_mitre(raw_type)
            cvss = _risk_to_cvss(
                float(vec["priority_score"]) if "priority_score" in vec else risk_score
            )

            vuln_entry: dict[str, Any] = {
                "id": f"VULN-{i:03d}",
                "type": vtype,
                "severity": _classify_severity(cvss),
                "cvss": cvss,
                "location": vec.get("path", "N/A"),
                "parameter": vec.get("parameter", "N/A"),
                "mitre_attack": {
                    "tactic": mitre["tactic"],
                    "technique": mitre["technique"],
                    "name": mitre["name"],
                },
                "evidence": vec.get("evidence", "Detected during reconnaissance"),
                "exploited": False,
            }

            if exploit and raw_type.lower().replace(" ", "_") in exploit.vulnerability_type.lower().replace(" ", "_"):
                vuln_entry["exploited"] = True

            vulnerabilities.append(vuln_entry)
            seen_types.add(raw_type.lower())

        if exploit and exploit.vulnerability_type:
            normalized = exploit.vulnerability_type.lower().replace(" ", "_")
            if not any(normalized in t for t in seen_types):
                mitre = _resolve_mitre(exploit.vulnerability_type)
                cvss = _risk_to_cvss(risk_score)
                vulnerabilities.append({
                    "id": f"VULN-{len(vulnerabilities) + 1:03d}",
                    "type": exploit.vulnerability_type.upper().replace(" ", "_"),
                    "severity": _classify_severity(cvss),
                    "cvss": cvss,
                    "location": exploit.injection_point or "N/A",
                    "parameter": "N/A",
                    "mitre_attack": {
                        "tactic": mitre["tactic"],
                        "technique": mitre["technique"],
                        "name": mitre["name"],
                    },
                    "evidence": f"Confirmed via exploitation ({', '.join(exploit.tools_run)})",
                    "exploited": True,
                })

        # ── Exploitation results ──
        exploitation_results: dict[str, Any] = {}
        if exploit:
            exploitation_results = {
                "dbms": exploit.dbms or "N/A",
                "databases": exploit.databases_found,
                "tables_accessed": [],
                "credentials_exfiltrated": exploit.credentials_found,
                "data_breach_severity": (
                    "CRITICAL" if exploit.credentials_found
                    else "HIGH" if exploit.data_exfiltrated
                    else "LOW"
                ),
            }
            for db, tables in exploit.tables_found.items():
                for t in tables:
                    exploitation_results["tables_accessed"].append(f"{db}.{t}" if db else t)
            if exploit.data_exfiltrated:
                exploitation_results["data_exfiltrated"] = [
                    {
                        "database": d.get("database", ""),
                        "table": d.get("table", ""),
                        "columns": d.get("columns", []),
                        "row_count": d.get("row_count", 0),
                    }
                    for d in exploit.data_exfiltrated
                ]

        # ── Overall risk ──
        overall_risk_score = risk_score
        if exploit and exploit.credentials_found:
            overall_risk_score = max(overall_risk_score, 9.5)
        elif exploit and exploit.data_exfiltrated:
            overall_risk_score = max(overall_risk_score, 8.0)
        overall_risk_score = round(min(overall_risk_score, 10.0), 1)

        # ── Recommendations ──
        recommendations = []
        recommended_types: set[str] = set()
        for vuln in vulnerabilities:
            raw = vuln["type"].lower().replace("_", " ")
            mitre_key = None
            for alias, mk in _VULN_TYPE_ALIASES.items():
                if alias in raw or raw in alias:
                    mitre_key = mk
                    break
            if mitre_key and mitre_key not in recommended_types:
                recommended_types.add(mitre_key)
                rec = _RECOMMENDATIONS.get(mitre_key)
                if rec:
                    recommendations.append(rec)

        recommendations.append({
            "priority": "MEDIUM",
            "action": "GENERAL_HARDENING",
            "description": (
                "Keep all software up to date. Conduct regular penetration testing. "
                "Implement network segmentation. Enable logging and monitoring. Follow OWASP Top 10."
            ),
            "mitre_mitigation": "M1051",
        })

        return {
            "report_id": f"report_{datetime.now(timezone.utc).strftime('%Y%m%d')}_{mission.id[:8]}",
            "classification": "RED_TEAM_ASSESSMENT",
            "target": mission.target,
            "timestamp": now,
            "overall_risk": _classify_severity(overall_risk_score),
            "risk_score": overall_risk_score,
            "reconnaissance": reconnaissance,
            "vulnerabilities": vulnerabilities,
            "exploitation_results": exploitation_results,
            "recommendations": recommendations,
        }

    # ══════════════════════════════════════════════════════════════════
    # WebSocket helpers
    # ══════════════════════════════════════════════════════════════════

    def _make_tool_call(self, name: str, category: str, params: dict[str, Any]) -> ToolCall:
        return ToolCall(
            id=str(uuid.uuid4()), name=name, category=category,
            status=ToolStatus.RUNNING, params=params,
        )

    def _finish_tool_call(self, tc: ToolCall, result: dict[str, Any],
                          status: ToolStatus = ToolStatus.DONE) -> None:
        tc.status = status
        tc.result = result
        tc.finished_at = datetime.now(timezone.utc)

    async def _emit_tool_call_ws(self, tc: ToolCall) -> None:
        from red_agent.backend.websocket.red_ws import manager
        await manager.broadcast({"type": "tool_call", "payload": tc.model_dump(mode="json")})

    async def _emit_log(self, mission: Mission, level: str, message: str) -> None:
        from red_agent.backend.websocket.red_ws import manager
        entry = LogEntry(level=level, message=f"[{mission.id[:8]}] {message}")
        await manager.broadcast({"type": "log", "payload": entry.model_dump(mode="json")})

    async def _emit_chat(self, mission: Mission, content: str) -> None:
        from red_agent.backend.websocket.red_ws import manager
        await manager.broadcast({
            "type": "chat_response",
            "payload": {
                "id": str(uuid.uuid4()), "role": "agent", "content": content,
                "timestamp": datetime.now(timezone.utc).isoformat(), "tool_calls": [],
            },
        })

    async def _emit_phase(self, mission: Mission, phase: MissionPhase) -> None:
        from red_agent.backend.websocket.red_ws import manager
        mission.phase = phase
        await event_bus.publish("mission.phase_changed", {
            "mission_id": mission.id, "phase": phase.value, "target": mission.target,
        })
        await manager.broadcast({
            "type": "mission_phase",
            "payload": {"mission_id": mission.id, "phase": phase.value},
        })
        await self._emit_log(mission, "INFO", f"Phase -> {phase.value}")


orchestrator = MissionOrchestrator()
