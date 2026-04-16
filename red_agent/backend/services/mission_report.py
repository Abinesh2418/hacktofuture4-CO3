"""Generate a downloadable markdown report from a finished mission.

Pulls together:
  - Mission metadata (target, attack profile, phase, duration)
  - Recon tool findings (from agents.tools cache)
  - Deterministic auto-pwn evidence (from auto_pwn history)
  - LLM agent outputs (recon / analysis / exploit / final)
  - A remediation section keyed by what was actually found
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from red_agent.backend.services.auto_pwn import recent_steps
from red_agent.backend.services.orchestrator import Mission, orchestrator
from red_agent.agents.tools import get_recent_tool_results


_ATTACK_PROFILES = {
    "sqli": "SQL Injection (scoped)",
    "cmdi": "Command Injection (scoped)",
    "lfi": "Local File Inclusion (scoped)",
    "idor": "Insecure Direct Object Reference (scoped)",
    "xss": "Cross-Site Scripting (scoped)",
    "full": "Full Scope",
}


_REMEDIATION: dict[str, list[tuple[str, str]]] = {
    "sqli": [
        ("Use parameterized queries",
         "Replace string concatenation in SQL with prepared statements / bound parameters. "
         "All major language drivers expose this — `cursor.execute('... WHERE u = ?', (user,))` "
         "in Python, `?` placeholders in JDBC, `$1` in pg, etc."),
        ("Input validation at the boundary",
         "Reject unexpected characters at the API edge — especially `'`, `--`, `/*`, `;`, "
         "`UNION`, `SELECT`. Use an allow-list per field type, not a deny-list."),
        ("Least-privilege DB credentials",
         "The application's DB user should have ONLY the rights it needs. Strip DDL, "
         "FILE, and cross-schema privileges. A compromised app can't dump what it can't read."),
        ("Deploy a WAF in front of the app",
         "ModSecurity with the OWASP Core Rule Set blocks the boolean-based and UNION-based "
         "payloads sqlmap defaulted to here."),
        ("Verify the fix",
         "Re-run a `sqlmap_detect` scan against the same URL after deployment. The parameter "
         "should no longer appear injectable."),
    ],
    "cmdi": [
        ("Never pass untrusted input to a shell",
         "Use language-native APIs (`subprocess.run([...], shell=False)` in Python, "
         "`execFile()` in Node) — pass arguments as a list, never as a string."),
        ("If a shell is unavoidable, hard-allowlist",
         "Restrict the input to a strict regex (e.g. `^[a-zA-Z0-9._-]+$` for hostnames). "
         "Reject anything else at the boundary."),
        ("Run the worker process under a sandbox",
         "Containers, seccomp profiles, or AppArmor confining the binary's syscalls limit "
         "blast radius if a payload does land."),
    ],
    "lfi": [
        ("Resolve every requested path against an allow-list directory",
         "`os.path.realpath()` then verify the result is a child of the intended template "
         "directory — block anything else."),
        ("Strip path traversal sequences",
         "Reject `..`, `%2e%2e`, null bytes, and absolute paths at the boundary."),
        ("Disable PHP `allow_url_include` / equivalent dangerous loaders",
         "If the language allows remote includes via the same parameter, RFI piggybacks on LFI."),
    ],
    "idor": [
        ("Authorize every object access against the caller's identity",
         "Don't trust the ID in the URL — load the object, then verify the caller owns it."),
        ("Use unguessable identifiers where the resource is sensitive",
         "UUIDv4 instead of incrementing integers prevents brute-force enumeration as a "
         "second line of defense."),
        ("Centralize the access-check decorator/middleware",
         "Per-route checks rot. A central authorization layer fails closed by default."),
    ],
    "xss": [
        ("Context-aware output encoding",
         "Use the templating engine's auto-escape (Jinja, React JSX, Razor) — never paste "
         "raw user input into HTML, attributes, or JS contexts."),
        ("Strict Content-Security-Policy header",
         "`script-src 'self'` blocks inline-injected scripts even when an XSS sink slips through."),
        ("Sanitize rich-text fields with DOMPurify (or equivalent server-side)",
         "Free-text fields that legitimately need HTML must be sanitized, not raw-stored."),
    ],
}


_REMEDIATION_GENERIC = [
    ("Fix the root cause, not the symptom",
     "The findings below are evidence of a class of bug, not isolated incidents. Audit "
     "every endpoint that handles the same kind of input."),
    ("Add regression coverage",
     "For each finding, add an integration test that fails before the patch and passes after."),
]


# ─────────────────────────────────────────────────────────────────────


def _h(text: str, level: int = 1) -> str:
    return f"{'#' * level} {text}\n"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not headers:
        return ""
    out = ["| " + " | ".join(headers) + " |"]
    out.append("| " + " | ".join("---" for _ in headers) + " |")
    for r in rows:
        cells = [(c or "").replace("|", "\\|").replace("\n", " ")[:120] for c in r]
        # pad/truncate to header width
        if len(cells) < len(headers):
            cells += [""] * (len(headers) - len(cells))
        cells = cells[: len(headers)]
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out) + "\n"


def _format_findings(findings: list[dict]) -> str:
    if not findings:
        return "_no findings_\n"
    lines: list[str] = []
    for f in findings[:25]:
        if not isinstance(f, dict):
            continue
        if "port" in f and "service" in f:
            lines.append(f"- port **{f.get('port')}/{f.get('service','?')}** "
                         f"({f.get('state','?')}) {f.get('product','') or ''} {f.get('version','') or ''}".rstrip())
        elif f.get("type") == "injection":
            lines.append(f"- **INJECTION** — parameter `{f.get('param')}` ({f.get('place')})")
        elif f.get("type") == "dbms":
            lines.append(f"- DBMS detected: **{f.get('value')}**")
        elif f.get("type") == "database":
            lines.append(f"- database: `{f.get('name')}`")
        elif f.get("type") == "table":
            lines.append(f"- table: `{f.get('db','')}.{f.get('name')}`")
        elif "url" in f:
            lines.append(f"- {f['url']}" + (f" — {f.get('status_code','')}" if f.get('status_code') else ""))
        elif "path" in f:
            lines.append(f"- `{f['path']}` (status {f.get('status','?')})")
        elif "name" in f:
            sev = f.get("severity", "")
            lines.append(f"- [{sev}] {f.get('name')}")
        else:
            lines.append(f"- {str(f)[:120]}")
    if len(findings) > 25:
        lines.append(f"- _… {len(findings) - 25} more (see appendix)_")
    return "\n".join(lines) + "\n"


def _exec_summary(mission: Mission, sqli: dict | None, dump_step: dict | None) -> str:
    bullets: list[str] = []
    if sqli:
        bullets.append(
            f"**1× confirmed SQL injection** at `{sqli.get('url')}` "
            f"(parameter `{sqli.get('param','?')}`, DBMS: {sqli.get('dbms','?')})"
        )
    if dump_step:
        section_count = len(dump_step.get("sections", []))
        row_total = sum(s.get("row_count", 0) for s in dump_step.get("sections", []))
        bullets.append(
            f"**{row_total} sample records captured across {section_count} table(s)** — "
            f"finding is exploitable, not theoretical"
        )
    if not bullets:
        bullets.append("No high-impact findings were confirmed in this run.")

    if sqli or dump_step:
        rating = "CRITICAL"
    else:
        rating = "INFORMATIONAL"

    out = ["A scoped security assessment was performed against the in-scope target.\n"]
    out.append(f"**Risk Rating:** {rating}\n")
    out.append("\n**Key Findings:**\n")
    for b in bullets:
        out.append(f"- {b}\n")
    return "".join(out)


def _duration(mission: Mission) -> str:
    try:
        start = datetime.fromisoformat(mission.created_at.replace("Z", ""))
        delta = datetime.utcnow() - start
        sec = int(delta.total_seconds())
        if sec < 60:
            return f"{sec}s"
        return f"{sec // 60}m {sec % 60}s"
    except Exception:
        return "?"


def _extract_sqli(tool_results: dict) -> dict | None:
    """Pull a flat SQLi summary out of the cached sqlmap_detect result."""
    detect = tool_results.get("sqlmap_detect")
    if not detect:
        return None
    findings = detect.get("result", {}).get("findings", [])
    inj = next((f for f in findings if f.get("type") == "injection"), None)
    dbms = next((f for f in findings if f.get("type") == "dbms"), None)
    if not inj:
        return None
    return {
        "url": detect.get("params", {}).get("target", "?"),
        "param": inj.get("param"),
        "place": inj.get("place"),
        "dbms": dbms.get("value") if dbms else "unknown",
    }


def _autopwn_for_target(target: str | None) -> tuple[list[dict], dict | None]:
    """Return (all_steps, the_consolidated_dump_step) for this mission's target."""
    steps = [s.model_dump(mode="json") for s in recent_steps(limit=200)]
    if target:
        steps = [s for s in steps if (s.get("target") or "").startswith(target.split("?")[0].rstrip("/"))]
    dump = next(
        (s for s in reversed(steps) if s.get("kind") == "SQLMAP_DUMP" and s.get("sections")),
        None,
    )
    return steps, dump


def generate_markdown_report(mission_id: str | None = None) -> tuple[str, str]:
    """Return (filename, markdown_body) for a finished or in-progress mission."""
    mission: Mission | None = None
    if mission_id:
        mission = orchestrator.get_mission(mission_id)
    if mission is None:
        # Fall back to most recently created mission
        all_missions = list(orchestrator._missions.values())
        if all_missions:
            mission = sorted(all_missions, key=lambda m: m.created_at)[-1]

    if mission is None:
        body = (
            "# RED ARSENAL — Report\n\n"
            "_No mission has been launched yet. Launch a mission, wait for "
            "results, then click REPORT again._\n"
        )
        return ("red-arsenal-report-empty.md", body)

    tool_results = get_recent_tool_results()
    sqli = _extract_sqli(tool_results)
    autopwn_steps, dump_step = _autopwn_for_target(mission.target)

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    profile = _ATTACK_PROFILES.get(mission.attack_type, mission.attack_type.upper())

    out: list[str] = []

    # ── Title ──
    out.append(_h("RED ARSENAL — Penetration Assessment Report", 1))
    out.append(f"_Generated {now}_  \n")
    out.append("---\n\n")

    # ── Metadata table ──
    out.append(_table(
        ["Field", "Value"],
        [
            ["Mission ID", mission.id],
            ["Target", mission.target],
            ["Attack Profile", profile],
            ["Status", mission.phase.value],
            ["Started", mission.created_at],
            ["Duration", _duration(mission)],
            ["Error", mission.error or "—"],
        ],
    ))
    out.append("\n")

    # ── 1. Executive Summary ──
    out.append(_h("1. Executive Summary", 2))
    out.append(_exec_summary(mission, sqli, dump_step))
    out.append("\n---\n\n")

    # ── 2. Reconnaissance ──
    out.append(_h("2. Reconnaissance", 2))
    recon_tool_names = ["nmap_scan", "httpx_probe", "gobuster_scan",
                        "nuclei_scan", "katana_crawl", "dirsearch_scan", "sqlmap_detect"]
    any_recon = False
    for name in recon_tool_names:
        entry = tool_results.get(name)
        if not entry:
            continue
        any_recon = True
        out.append(_h(f"2.{recon_tool_names.index(name)+1} {name}", 3))
        findings = entry.get("result", {}).get("findings", [])
        out.append(_format_findings(findings))
        out.append("\n")
    if not any_recon:
        out.append("_no recon tools have completed yet_\n\n")

    # ── 3. SQLi confirmation ──
    if sqli:
        out.append(_h("3. SQL Injection Confirmation", 2))
        out.append(_table(
            ["Field", "Value"],
            [
                ["Injectable URL", sqli.get("url", "?")],
                ["Parameter", str(sqli.get("param") or "?")],
                ["Method", str(sqli.get("place") or "?")],
                ["Back-end DBMS", str(sqli.get("dbms") or "?")],
            ],
        ))
        out.append("\n---\n\n")

    # ── 4. Auto-Pwn Evidence ──
    out.append(_h("4. Validation Evidence — Deterministic Pipeline", 2))
    if not autopwn_steps:
        out.append("_pipeline did not run (no SQLi was confirmed)_\n\n")
    else:
        for s in autopwn_steps:
            kind = s.get("kind", "?")
            status = s.get("status", "?")
            summary = s.get("summary", "")
            out.append(f"- **[{kind}]** {status} — {summary}\n")
        out.append("\n")

        if dump_step:
            out.append(_h("4.1 Captured Records", 3))
            for sec in dump_step.get("sections", []):
                db = sec.get("db", "?")
                tbl = sec.get("table", "?")
                rows = sec.get("rows", [])
                row_count = sec.get("row_count", 0)
                if not rows:
                    if sec.get("error"):
                        out.append(f"\n**`{db}.{tbl}`** — _error: {sec['error']}_\n\n")
                    else:
                        out.append(f"\n**`{db}.{tbl}`** — _no rows captured_\n\n")
                    continue
                hdr, *data = rows
                out.append(f"\n**`{db}.{tbl}`** — {row_count} row(s)\n\n")
                out.append(_table(hdr or [f"col{i}" for i in range(len(data[0]))], data[:50]))
                if len(data) > 50:
                    out.append(f"\n_… {len(data) - 50} more rows truncated_\n")
                out.append("\n")
        out.append("---\n\n")

    # ── 5. LLM Agent Outputs ──
    out.append(_h("5. LLM Agent Reports", 2))
    if mission.recon_output:
        out.append(_h("5.1 Recon Specialist", 3))
        out.append("```\n" + mission.recon_output[:6000] + "\n```\n\n")
    if mission.analysis_output:
        out.append(_h("5.2 Security Analyst", 3))
        out.append("```\n" + mission.analysis_output[:6000] + "\n```\n\n")
    if mission.exploit_output:
        out.append(_h("5.3 Validation Specialist", 3))
        out.append("```\n" + mission.exploit_output[:6000] + "\n```\n\n")
    if not (mission.recon_output or mission.analysis_output or mission.exploit_output):
        out.append("_LLM agent outputs not available yet_\n\n")
    out.append("---\n\n")

    # ── 6. Remediation ──
    out.append(_h("6. Remediation", 2))
    profile_key = mission.attack_type if mission.attack_type != "full" else (
        "sqli" if sqli else "cmdi"
    )
    rem_items = _REMEDIATION.get(profile_key, []) + _REMEDIATION_GENERIC
    if sqli:
        out.append(f"### Affected Endpoint\n\n`{sqli.get('url','?')}` "
                   f"(parameter: `{sqli.get('param','?')}`)\n\n")
    for i, (title, body) in enumerate(rem_items, 1):
        out.append(f"**{i}. {title}**  \n{body}\n\n")
    out.append("---\n\n")

    # ── 7. Appendix ──
    out.append(_h("7. Appendix — Tool Result Cache", 2))
    out.append("Last raw output snippet per tool (truncated to 1.5 KB each):\n\n")
    for name, entry in tool_results.items():
        raw = entry.get("result", {}).get("raw_output") or ""
        if not raw:
            continue
        out.append(f"### {name}\n```\n{raw[:1500]}\n```\n\n")

    out.append("---\n\n")
    out.append("_Report generated by Red Arsenal — Autonomous Pentest Agent._\n")

    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    fname = f"red-arsenal-report-{mission.id[:8]}-{timestamp}.md"
    return (fname, "".join(out))


def latest_mission_id() -> str | None:
    missions = list(orchestrator._missions.values())
    if not missions:
        return None
    return sorted(missions, key=lambda m: m.created_at)[-1].id
