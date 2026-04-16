from __future__ import annotations
"""Report generation and download endpoints."""


import json
from datetime import datetime, timezone
from io import BytesIO

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from red_agent.scanner.recon_agent import get_session_result as get_recon, list_sessions as list_recon
from red_agent.exploiter.exploit_agent import get_exploit_result, list_exploit_sessions

router = APIRouter()


def _generate_report(recon_id: str | None, exploit_id: str | None) -> str:
    """Generate a full pentest report combining recon + exploit findings."""

    recon = get_recon(recon_id) if recon_id else None
    exploit = get_exploit_result(exploit_id) if exploit_id else None

    # If only recon_id given, find the linked exploit
    if recon and not exploit:
        for sess in list_exploit_sessions():
            er = get_exploit_result(sess["exploit_id"])
            if er and er.recon_session_id == recon_id:
                exploit = er
                break

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    target = (recon.target if recon else exploit.target if exploit else "Unknown")

    lines = []
    lines.append("=" * 70)
    lines.append("   RED TEAM AUTONOMOUS PENETRATION TEST REPORT")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"  Generated : {now}")
    lines.append(f"  Target    : {target}")
    if recon:
        lines.append(f"  Recon ID  : {recon.session_id}")
    if exploit:
        lines.append(f"  Exploit ID: {exploit.exploit_id}")
    lines.append(f"  Status    : {'COMPLETE' if (recon and exploit) else 'PARTIAL'}")
    lines.append("")

    # ---------- EXECUTIVE SUMMARY ----------
    lines.append("-" * 70)
    lines.append("  1. EXECUTIVE SUMMARY")
    lines.append("-" * 70)
    lines.append("")

    risk = recon.risk_score if recon else 0
    creds_count = len(exploit.credentials_found) if exploit else 0
    vectors_count = len(recon.attack_vectors) if recon else 0

    if risk >= 8:
        severity = "CRITICAL"
    elif risk >= 5:
        severity = "HIGH"
    elif risk >= 3:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    lines.append(f"  Overall Risk Score : {risk}/10 ({severity})")
    lines.append(f"  Vulnerabilities    : {vectors_count} found")
    lines.append(f"  Credentials Leaked : {creds_count}")
    if exploit:
        lines.append(f"  Databases Found    : {len(exploit.databases_found)}")
        lines.append(f"  DBMS               : {exploit.dbms or 'N/A'}")
    lines.append("")

    if creds_count > 0:
        lines.append("  *** CRITICAL: User credentials were successfully exfiltrated. ***")
        lines.append("  *** Immediate remediation required. ***")
        lines.append("")

    # ---------- RECON PHASE ----------
    if recon:
        lines.append("-" * 70)
        lines.append("  2. RECONNAISSANCE PHASE")
        lines.append("-" * 70)
        lines.append("")
        lines.append(f"  Context      : {recon.context}")
        lines.append(f"  Duration     : {recon.duration_seconds}s")
        lines.append(f"  Tools Used   : {', '.join(recon.tools_run)}")
        lines.append(f"  CVEs Fetched : {recon.cves_fetched}")
        lines.append("")

        # Open Ports
        lines.append("  2.1 Open Ports")
        lines.append("  " + "-" * 40)
        if recon.open_ports:
            for port in recon.open_ports:
                lines.append(f"    - Port {port}")
        else:
            lines.append("    No open ports discovered.")
        lines.append("")

        # Tech Stack
        lines.append("  2.2 Technology Stack")
        lines.append("  " + "-" * 40)
        if recon.tech_stack:
            for tech in recon.tech_stack:
                lines.append(f"    - {tech}")
        else:
            lines.append("    No technologies identified.")
        lines.append("")

        # Attack Vectors
        lines.append("  2.3 Attack Vectors Discovered")
        lines.append("  " + "-" * 40)
        if recon.attack_vectors:
            for i, v in enumerate(recon.attack_vectors, 1):
                lines.append(f"    [{i}] {v.get('type', 'Unknown')}")
                lines.append(f"        Path     : {v.get('path', 'N/A')}")
                lines.append(f"        Priority : {v.get('priority', 'N/A').upper()}")
                lines.append(f"        Evidence : {v.get('evidence', 'N/A')}")
                lines.append(f"        MITRE    : {v.get('mitre_technique', 'N/A')}")
                lines.append(f"        Tool     : {v.get('recommended_tool', 'N/A')}")
                lines.append("")
        else:
            lines.append("    No attack vectors identified.")
            lines.append("")

    # ---------- EXPLOIT PHASE ----------
    if exploit:
        lines.append("-" * 70)
        lines.append("  3. EXPLOITATION PHASE")
        lines.append("-" * 70)
        lines.append("")
        lines.append(f"  Vulnerability  : {exploit.vulnerability_type}")
        lines.append(f"  Target         : {exploit.injection_point}")
        lines.append(f"  Duration       : {exploit.duration_seconds}s")
        lines.append(f"  Tools Used     : {', '.join(exploit.tools_run)}")
        lines.append(f"  Status         : {exploit.status.upper()}")
        lines.append("")

        # Databases
        lines.append("  3.1 Databases Discovered")
        lines.append("  " + "-" * 40)
        if exploit.databases_found:
            lines.append(f"    DBMS: {exploit.dbms}")
            for db in exploit.databases_found:
                lines.append(f"    - {db}")
                tables = exploit.tables_found.get(db, [])
                if tables:
                    for t in tables:
                        marker = " *** SENSITIVE" if t.lower() in ("users", "credentials", "accounts", "admin") else ""
                        lines.append(f"      └── {t}{marker}")
        else:
            lines.append("    No databases discovered.")
        lines.append("")

        # Exfiltrated Data
        lines.append("  3.2 Data Exfiltrated")
        lines.append("  " + "-" * 40)
        if exploit.data_exfiltrated:
            for dump in exploit.data_exfiltrated:
                db = dump.get("database", "")
                table = dump.get("table", "")
                cols = dump.get("columns", [])
                rows = dump.get("sample_rows", [])
                row_count = dump.get("row_count", 0)

                if table:
                    lines.append(f"    Table: {db}.{table} ({row_count} rows)")
                    if cols:
                        lines.append(f"    Columns: {', '.join(cols)}")
                    lines.append("")

                    if rows:
                        # Table header
                        col_widths = {}
                        for c in cols:
                            col_widths[c] = max(len(c), max((len(str(r.get(c, ""))) for r in rows), default=4))
                            col_widths[c] = min(col_widths[c], 30)

                        header = "    | " + " | ".join(c.ljust(col_widths.get(c, 10))[:30] for c in cols) + " |"
                        sep = "    +" + "+".join("-" * (col_widths.get(c, 10) + 2) for c in cols) + "+"

                        lines.append(sep)
                        lines.append(header)
                        lines.append(sep)
                        for row in rows[:20]:
                            row_line = "    | " + " | ".join(
                                str(row.get(c, "")).ljust(col_widths.get(c, 10))[:30]
                                for c in cols
                            ) + " |"
                            lines.append(row_line)
                        lines.append(sep)
                        lines.append("")
        else:
            lines.append("    No data exfiltrated.")
            lines.append("")

        # CREDENTIALS - THE MONEY SHOT
        lines.append("  3.3 CREDENTIALS FOUND")
        lines.append("  " + "=" * 40)
        if exploit.credentials_found:
            lines.append("")
            lines.append("    *** WARNING: PLAINTEXT/HASHED CREDENTIALS EXTRACTED ***")
            lines.append("")
            lines.append(f"    {'Username':<30} {'Password/Hash':<40}")
            lines.append(f"    {'-'*30} {'-'*40}")
            for cred in exploit.credentials_found:
                u = cred.get("username", "N/A")
                p = cred.get("password_hash", "N/A")
                lines.append(f"    {u:<30} {p:<40}")
            lines.append("")
            lines.append(f"    Total: {len(exploit.credentials_found)} credential(s) exfiltrated")
        else:
            lines.append("    No credentials found.")
        lines.append("")

    # ---------- RECOMMENDATIONS ----------
    lines.append("-" * 70)
    lines.append("  4. RECOMMENDATIONS")
    lines.append("-" * 70)
    lines.append("")

    if recon and recon.attack_vectors:
        for v in recon.attack_vectors:
            vtype = v.get("type", "").lower()
            if "sql" in vtype:
                lines.append("  [CRITICAL] SQL Injection Remediation:")
                lines.append("    - Use parameterized queries / prepared statements")
                lines.append("    - Implement input validation and sanitization")
                lines.append("    - Use an ORM instead of raw SQL queries")
                lines.append("    - Deploy a Web Application Firewall (WAF)")
                lines.append("")
            if "lfi" in vtype or "traversal" in vtype:
                lines.append("  [HIGH] LFI / Path Traversal Remediation:")
                lines.append("    - Never use user input directly in file paths")
                lines.append("    - Implement whitelist-based file access")
                lines.append("    - Use chroot or containerization")
                lines.append("    - Disable directory traversal in web server config")
                lines.append("")
            if "command" in vtype or "rce" in vtype:
                lines.append("  [CRITICAL] Command Injection Remediation:")
                lines.append("    - Never pass user input to system commands")
                lines.append("    - Use language-native libraries instead of shell commands")
                lines.append("    - Implement strict input validation (whitelist)")
                lines.append("    - Run services with minimal OS privileges")
                lines.append("")
            if "brute" in vtype or "ssh" in vtype:
                lines.append("  [MEDIUM] Brute Force / Auth Remediation:")
                lines.append("    - Implement account lockout after N failed attempts")
                lines.append("    - Add CAPTCHA on login forms")
                lines.append("    - Enforce strong password policies")
                lines.append("    - Use multi-factor authentication (MFA)")
                lines.append("")

    lines.append("  General Recommendations:")
    lines.append("    - Keep all software and dependencies up to date")
    lines.append("    - Conduct regular penetration testing")
    lines.append("    - Implement network segmentation")
    lines.append("    - Enable logging and monitoring for all services")
    lines.append("    - Follow OWASP Top 10 guidelines")
    lines.append("")

    # ---------- FOOTER ----------
    lines.append("=" * 70)
    lines.append("  Report generated by: Red Team Autonomous Agent")
    lines.append("  Agents: Recon Agent (Groq LLM) + Exploit Agent (Groq LLM)")
    lines.append("  Tools: nmap, nuclei, gobuster, ffuf, sqlmap, hydra")
    lines.append("  Framework: Groq SDK (function calling)")
    lines.append(f"  Timestamp: {now}")
    lines.append("=" * 70)

    return "\n".join(lines)


@router.get("/download/{recon_session_id}")
async def download_report(recon_session_id: str, exploit_id: str | None = None):
    """Download full pentest report as a text file."""
    recon = get_recon(recon_session_id)
    if not recon:
        raise HTTPException(status_code=404, detail="Recon session not found")

    report = _generate_report(recon_session_id, exploit_id)
    target_safe = recon.target.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "-")
    filename = f"pentest_report_{target_safe}_{recon_session_id}.txt"

    buffer = BytesIO(report.encode("utf-8"))
    return StreamingResponse(
        buffer,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/view/{recon_session_id}")
async def view_report(recon_session_id: str, exploit_id: str | None = None):
    """View report as JSON (for frontend rendering)."""
    recon = get_recon(recon_session_id)
    if not recon:
        raise HTTPException(status_code=404, detail="Recon session not found")

    exploit = get_exploit_result(exploit_id) if exploit_id else None
    if not exploit:
        for sess in list_exploit_sessions():
            er = get_exploit_result(sess["exploit_id"])
            if er and er.recon_session_id == recon_session_id:
                exploit = er
                break

    return {
        "target": recon.target,
        "risk_score": recon.risk_score,
        "recon": recon.to_dict(),
        "exploit": exploit.to_dict() if exploit else None,
        "credentials_found": exploit.credentials_found if exploit else [],
        "databases": exploit.databases_found if exploit else [],
        "download_url": f"/report/download/{recon_session_id}",
    }
