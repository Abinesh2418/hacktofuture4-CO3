"""CrewAI Tool wrappers — each tool broadcasts start/finish to the dashboard.

Every tool call appears as a card in the Activity Panel with:
- Tool name
- Which agent called it
- Status (RUNNING → DONE/FAILED)
- Results
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from datetime import datetime
from urllib.parse import urlparse

from crewai.tools import tool

_logger = logging.getLogger(__name__)

# ── Shared state: track which agent is currently active ──
_current_agent: str = "recon"  # Set by orchestrator before each phase

# Latest result per tool name — read by chat_routes to ground chat replies
# in actual findings instead of letting the LLM hallucinate.
_RECENT_TOOL_RESULTS: dict[str, dict] = {}

# Each tool belongs to exactly one logical agent. We derive the dashboard
# agent label from this map instead of trusting `_current_agent`, because
# CrewAI step_callback fires AFTER a step — so the first tool call by a
# new agent sees the *previous* agent's label.
_TOOL_AGENT: dict[str, str] = {
    # Recon
    "nmap_scan": "Recon Specialist",
    "httpx_probe": "Recon Specialist",
    "gobuster_scan": "Recon Specialist",
    "nuclei_scan": "Recon Specialist",
    "katana_crawl": "Recon Specialist",
    "dirsearch_scan": "Recon Specialist",
    "sqlmap_detect": "Recon Specialist",
    # Exploit
    "sqlmap_dbs": "Exploit Specialist",
    "sqlmap_tables": "Exploit Specialist",
    "sqlmap_dump": "Exploit Specialist",
    "nuclei_exploit": "Exploit Specialist",
    "ffuf_fuzz": "Exploit Specialist",
    "nmap_vuln_scan": "Exploit Specialist",
}

# Dedupe identical in-flight tool calls. The LLM occasionally emits the
# same tool_call N times in one turn (e.g. "sqlmap_dbs" × 3 at the same
# second). Without this every duplicate spawns its own ~2-minute sqlmap.
import time as _time
_INFLIGHT_RESULTS: dict[str, tuple[float, str]] = {}  # key -> (timestamp, return_str)
_DEDUP_WINDOW_S = 60.0


def _dedup_key(tool_name: str, args: dict) -> str:
    try:
        return f"{tool_name}:{json.dumps(args, sort_keys=True, default=str)}"
    except Exception:
        return f"{tool_name}:{args!r}"

# Every URL that sqlmap_detect confirmed injectable, in arrival order.
# Drained by the orchestrator at the EXPLOIT phase as a backstop.
_INJECTABLE_URLS: list[dict] = []

# URLs we've already fired the auto-pwn pipeline against (so the immediate
# fire-on-detect path and the orchestrator backstop don't double-launch).
_AUTO_PWN_FIRED: set[str] = set()


def get_recent_tool_results() -> dict[str, dict]:
    """Return a shallow copy of the latest finished-tool results."""
    return dict(_RECENT_TOOL_RESULTS)


def clear_recent_tool_results() -> None:
    _RECENT_TOOL_RESULTS.clear()
    _INJECTABLE_URLS.clear()
    _AUTO_PWN_FIRED.clear()
    _INFLIGHT_RESULTS.clear()


def drain_injectable_urls() -> list[dict]:
    """Return every SQLi-confirmed URL still pending auto-pwn launch.

    The CrewAI agent path schedules auto-pwn the moment SQLi is detected,
    so by the time the orchestrator drains, this is usually empty. Kept as
    a backstop in case scheduling failed (e.g., no main loop bound yet).
    """
    out = [u for u in _INJECTABLE_URLS if u.get("url") not in _AUTO_PWN_FIRED]
    _INJECTABLE_URLS.clear()
    for u in out:
        if u.get("url"):
            _AUTO_PWN_FIRED.add(u["url"])
    return out


def _fire_auto_pwn(url: str, dbms: str | None = None) -> None:
    """Schedule the deterministic SQLi pipeline on the main asyncio loop.

    Safe to call from a CrewAI worker thread — uses the same loop-binding
    trick the WebSocket broadcaster uses.
    """
    if not url or url in _AUTO_PWN_FIRED:
        return
    try:
        from red_agent.backend.websocket.red_ws import manager
        from red_agent.backend.services.auto_pwn import auto_sqli_pipeline
    except Exception as exc:
        _logger.warning("auto_pwn fire-on-detect unavailable: %s", exc)
        return

    loop = manager._main_loop
    if not loop or not loop.is_running():
        # Fall back to the orchestrator's backstop drain at EXPLOIT phase.
        return

    _AUTO_PWN_FIRED.add(url)
    asyncio.run_coroutine_threadsafe(auto_sqli_pipeline(url, dbms=dbms), loop)
    _logger.info("[tools] auto_pwn fired immediately on detection -> %s (dbms=%s)", url, dbms)


# Match `GET http://...` / `POST http://...` lines in sqlmap crawl output.
_FORM_URL_RE = re.compile(
    r"(?:GET|POST)\s+(https?://[^\s\"'<>]+)",
    re.IGNORECASE,
)


def _extract_injectable_url(raw_output: str, base_target: str, param: str) -> str:
    """Pull the actual injectable URL out of sqlmap's crawl log.

    The agent often passes a base URL (http://host:port) but sqlmap discovers
    the SQLi at a deeper endpoint like /search?q=. Auto-pwn needs the deeper
    URL or it has to re-crawl every step.
    """
    if not raw_output:
        return base_target
    candidates = [u.rstrip(",.;:)") for u in _FORM_URL_RE.findall(raw_output)]
    if param:
        for url in candidates:
            if f"?{param}=" in url or f"&{param}=" in url:
                return url
    if candidates:
        return candidates[0]
    return base_target


def _record_injectable(target: str, findings: list, raw_output: str = "") -> None:
    """If sqlmap_detect findings contain an injection, queue the URL."""
    if not findings:
        return
    dbms = None
    has_injection = False
    params: list[str] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        if f.get("type") == "injection":
            has_injection = True
            p = f.get("param")
            if p and p not in params:
                params.append(p)
        elif f.get("type") == "dbms":
            dbms = f.get("value")
    if has_injection:
        primary = params[0] if params else ""
        actual = _extract_injectable_url(raw_output, target, primary)
        _INJECTABLE_URLS.append({"url": actual, "dbms": dbms, "params": params})
        # Fire the deterministic exfil pipeline IMMEDIATELY — don't wait for
        # the LLM exploit phase. The dashboard's Exploit box lights up the
        # moment recon confirms SQLi.
        _fire_auto_pwn(actual, dbms=dbms)


def set_active_agent(name: str) -> None:
    global _current_agent
    _current_agent = name


def _host_only(target: str) -> str:
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target.split("/", 1)[0]


_COMMON_PORTS = "21,22,80,443,3000,3306,5000,5432,6379,8000,8080,8443,8888,9000,27017"


def _get_port(target: str) -> str:
    if "://" in target:
        parsed = urlparse(target)
        if parsed.port:
            return str(parsed.port)
        return "443" if parsed.scheme == "https" else "80"
    # Bare host:port
    if ":" in target and not target.count(".") >= 3:
        parts = target.rsplit(":", 1)
        if parts[1].isdigit():
            return parts[1]
    # IPv4 address with embedded ":port"
    if target.count(":") == 1:
        parts = target.rsplit(":", 1)
        if parts[1].isdigit():
            return parts[1]
    # Bare IP/host with no port — top common service ports beats 1-1000 by ~50x
    return _COMMON_PORTS


# ── WebSocket broadcasting from sync context ──

def _broadcast_tool_event(
    tool_name: str,
    status: str,
    category: str,
    params: dict,
    result: dict | None = None,
    *,
    call_id: str | None = None,
) -> None:
    """Broadcast a tool_call event to the dashboard from sync CrewAI context."""
    try:
        from red_agent.backend.websocket.red_ws import manager
        from red_agent.backend.schemas.red_schemas import ToolCall, ToolStatus

        tc = ToolCall(
            id=call_id or str(uuid.uuid4()),
            name=tool_name,
            category=category,
            status=ToolStatus(status),
            params=params,
            result=result,
            finished_at=datetime.utcnow() if status in ("DONE", "FAILED") else None,
        )
        # Remember latest result per tool so the chat LLM can ground answers
        if status in ("DONE", "FAILED") and result is not None:
            _RECENT_TOOL_RESULTS[tool_name] = {
                "status": status,
                "result": result,
                "params": params,
                "finished_at": datetime.utcnow().isoformat(),
            }

        payload = {"type": "tool_call", "payload": tc.model_dump(mode="json")}
        manager.broadcast_threadsafe(payload)
    except Exception as e:
        _logger.warning("Failed to broadcast tool event: %s", e)


def _broadcast_chat(content: str) -> None:
    """Broadcast a chat message to the dashboard (proactive agent updates)."""
    try:
        from red_agent.backend.websocket.red_ws import manager
        import uuid as _uuid
        from datetime import datetime as _dt

        payload = {
            "type": "chat_response",
            "payload": {
                "id": str(_uuid.uuid4()),
                "role": "agent",
                "content": content,
                "timestamp": _dt.utcnow().isoformat(),
                "tool_calls": [],
            },
        }
        manager.broadcast_threadsafe(payload)
    except Exception as e:
        _logger.warning("Failed to broadcast chat: %s", e)


def _broadcast_log(level: str, message: str) -> None:
    """Broadcast a log entry to the dashboard."""
    try:
        from red_agent.backend.websocket.red_ws import manager
        from red_agent.backend.schemas.red_schemas import LogEntry

        entry = LogEntry(level=level, message=message)
        payload = {"type": "log", "payload": entry.model_dump(mode="json")}
        manager.broadcast_threadsafe(payload)
    except Exception as e:
        _logger.warning("Failed to broadcast log: %s", e)


def _run_mcp_tool(
    tool_name: str,
    mcp_name: str,
    args: dict,
    category: str = "scan",
    *,
    findings_cap: int = 10,
    raw_cap: int = 500,
    return_cap: int = 4000,
) -> str:
    """Run an MCP tool with full dashboard streaming.

    Caps are higher for sqlmap-style tools so the LLM and dashboard see
    real exfiltrated rows, not a truncated stub.
    """
    # Derive agent label from the tool itself, not the volatile _current_agent
    # global. CrewAI's step_callback fires AFTER a step, so the first tool
    # call from a new agent would otherwise inherit the previous agent's name.
    agent = _TOOL_AGENT.get(tool_name, _current_agent)
    params = {"target": args.get("target", ""), "agent": agent}

    # Dedupe duplicate calls — the LLM sometimes emits the same tool_call
    # multiple times in one turn. Return the cached result instead of
    # spawning N concurrent sqlmaps against the same target.
    key = _dedup_key(tool_name, args)
    now = _time.time()
    cached = _INFLIGHT_RESULTS.get(key)
    if cached and (now - cached[0]) < _DEDUP_WINDOW_S:
        _broadcast_log(
            "WARN",
            f"[{agent}] {tool_name} deduped — identical call within "
            f"{int(_DEDUP_WINDOW_S)}s, returning cached result",
        )
        return cached[1]

    # Stable ID so the RUNNING and DONE/FAILED broadcasts collapse into a
    # single card on the dashboard instead of stacking duplicates.
    call_id = str(uuid.uuid4())

    # Broadcast: RUNNING
    _broadcast_tool_event(tool_name, "RUNNING", category, params, call_id=call_id)
    _broadcast_log("INFO", f"[{agent}] {tool_name} started")

    try:
        from red_agent.backend.services.mcp_client import call_tool_and_wait
        result = asyncio.run(call_tool_and_wait(mcp_name, args))

        findings = result.get("findings", [])
        ok = result.get("ok", True) and not result.get("error")
        status = "DONE" if ok else "FAILED"

        # Broadcast: DONE/FAILED with actual findings
        broadcast_result = {
            "ok": ok,
            "findings_count": len(findings),
            "findings": findings[:findings_cap],
            "duration": result.get("duration_s", 0),
            "agent": agent,
        }
        # Add error info if failed
        if result.get("error"):
            broadcast_result["error"] = str(result["error"])[:200]
        # Add raw output snippet for context
        raw = result.get("raw_tail", "")
        if raw:
            broadcast_result["raw_output"] = raw[:raw_cap]
        # Pass through sqlmap-specific metadata. Use a different loop var so
        # we don't shadow the outer `key` (the dedup-cache key).
        for meta_key in ("mode", "db", "table", "dump_all"):
            if meta_key in result:
                broadcast_result[meta_key] = result[meta_key]

        _broadcast_tool_event(tool_name, status, category, params, broadcast_result, call_id=call_id)

        # Log with key details
        detail = ""
        if findings:
            first = findings[0]
            if isinstance(first, dict):
                port = first.get("port", "")
                service = first.get("service", "")
                state = first.get("state", "")
                if port:
                    detail = f" — port {port}/{service} ({state})"
                else:
                    detail = f" — {json.dumps(first, default=str)[:80]}"
        if not ok and result.get("error"):
            # Surface the underlying failure (e.g. "connection timed out") in
            # the live log so the operator sees what actually went wrong.
            detail = f" — {str(result['error'])[:160]}"
        _broadcast_log(
            "INFO" if ok else "WARN",
            f"[{agent}] {tool_name} {'completed' if ok else 'failed'} — {len(findings)} findings{detail}",
        )

        # Return results for CrewAI agent — bigger cap for sqlmap so it can chain commands
        if findings:
            ret = json.dumps(findings[:findings_cap], indent=2, default=str)[:return_cap]
        else:
            raw = result.get("raw_tail", "")
            if raw:
                ret = f"{tool_name} output:\n{raw[:return_cap]}"
            else:
                ret = json.dumps(result, default=str)[:return_cap]

        # Cache so identical follow-up calls within the dedup window return
        # this result instead of re-spawning the tool.
        _INFLIGHT_RESULTS[key] = (now, ret)
        return ret

    except Exception as e:
        _broadcast_tool_event(tool_name, "FAILED", category, params, {"error": str(e), "agent": agent}, call_id=call_id)
        _broadcast_log("ERROR", f"[{agent}] {tool_name} error: {e}")
        return f"{tool_name} error: {e}"


# ══════════════════════════════════════════════════════════════════════
# Recon Tools
# ══════════════════════════════════════════════════════════════════════

@tool("nmap_scan")
def nmap_scan(target: str) -> str:
    """Run nmap service/version scan. Input: IP or URL. Returns open ports, services, versions."""
    host = _host_only(target)
    port = _get_port(target)
    # Drop -sC (default scripts run on every open port — adds minutes for
    # nothing useful here). -T4 + tight timeouts keep the recon agent moving
    # so sqlmap_detect can run while nmap is still finishing.
    return _run_mcp_tool("nmap_scan", "run_nmap", {
        "target": host, "ports": port,
        "scan_type": "-sV -Pn -T4 --max-retries 1 --host-timeout 90s",
        "wait": True,
    })


@tool("nuclei_scan")
def nuclei_scan(target: str) -> str:
    """Run nuclei vulnerability scanner. Input: full URL. Detects CVEs, misconfigs, exposed panels."""
    return _run_mcp_tool("nuclei_scan", "run_nuclei", {
        "target": target, "severity": "critical,high,medium", "wait": True,
    })


@tool("gobuster_scan")
def gobuster_scan(target: str) -> str:
    """Brute-force directories and files on a web server. Input: full URL."""
    return _run_mcp_tool("gobuster_scan", "run_gobuster", {
        "target": target, "wait": True,
    })


@tool("katana_crawl")
def katana_crawl(target: str) -> str:
    """Crawl a website to discover endpoints, forms, and links. Input: full URL."""
    return _run_mcp_tool("katana_crawl", "run_katana", {
        "target": target, "wait": True,
    })


@tool("dirsearch_scan")
def dirsearch_scan(target: str) -> str:
    """Directory and file discovery on web servers. Input: full URL."""
    return _run_mcp_tool("dirsearch_scan", "run_dirsearch", {
        "target": target, "wait": True,
    })


@tool("httpx_probe")
def httpx_probe(target: str) -> str:
    """Probe web server for technology stack, status codes, headers. Input: URL or domain."""
    return _run_mcp_tool("httpx_probe", "run_httpx", {
        "target": target, "wait": True,
    })


# ══════════════════════════════════════════════════════════════════════
# Exploit Tools
# ══════════════════════════════════════════════════════════════════════

@tool("nuclei_exploit")
def nuclei_exploit(target: str) -> str:
    """Run nuclei with exploit templates to verify vulnerabilities. Input: full URL."""
    return _run_mcp_tool("nuclei_exploit", "run_nuclei", {
        "target": target, "severity": "critical,high", "tags": "cve,exploit,rce", "wait": True,
    }, category="exploit")


@tool("ffuf_fuzz")
def ffuf_fuzz(target: str) -> str:
    """Fuzz web endpoints for hidden parameters and paths. Input: base URL."""
    return _run_mcp_tool("ffuf_fuzz", "run_ffuf", {
        "target": target, "mode": "content", "wait": True,
    }, category="exploit")


@tool("nmap_vuln_scan")
def nmap_vuln_scan(target: str) -> str:
    """Run nmap with vulnerability scripts. Input: IP or hostname."""
    host = _host_only(target)
    port = _get_port(target)
    return _run_mcp_tool("nmap_vuln_scan", "run_nmap", {
        "target": host, "ports": port, "scan_type": "-sV --script=vuln", "wait": True,
    }, category="exploit")


# ══════════════════════════════════════════════════════════════════════
# SQL Injection Tools (sqlmap)
# ══════════════════════════════════════════════════════════════════════

@tool("sqlmap_detect")
def sqlmap_detect(target: str) -> str:
    """Crawl the target URL and detect SQL injection in any parameter or form.
    Input: full URL (e.g. http://victim:5000/login). Returns injectable params + DBMS fingerprint."""
    # raw_cap=8000 keeps enough of sqlmap's crawl log around for us to extract
    # the actual injectable form URL (not just the base target).
    out = _run_mcp_tool("sqlmap_detect", "run_sqlmap_detect", {
        "target": target, "level": 2, "risk": 2, "crawl": 2, "wait": True,
    }, category="scan", findings_cap=20, raw_cap=8000, return_cap=4000)
    cached = _RECENT_TOOL_RESULTS.get("sqlmap_detect", {}).get("result", {})
    _record_injectable(
        target,
        cached.get("findings", []),
        cached.get("raw_output", ""),
    )
    return out


@tool("sqlmap_dbs")
def sqlmap_dbs(target: str) -> str:
    """List databases on a SQLi-vulnerable URL. Run this AFTER sqlmap_detect confirms injection.
    Input: the same URL that was confirmed injectable."""
    return _run_mcp_tool("sqlmap_dbs", "run_sqlmap_dbs", {
        "target": target, "level": 2, "risk": 2, "wait": True,
    }, category="exploit", findings_cap=50, raw_cap=4000, return_cap=4000)


@tool("sqlmap_tables")
def sqlmap_tables(target: str, db: str) -> str:
    """List tables in a specific database. Inputs: URL, db name (from sqlmap_dbs output)."""
    return _run_mcp_tool("sqlmap_tables", "run_sqlmap_tables", {
        "target": target, "db": db, "level": 2, "risk": 2, "wait": True,
    }, category="exploit", findings_cap=100, raw_cap=4000, return_cap=4000)


@tool("sqlmap_dump")
def sqlmap_dump(target: str, db: str = "", table: str = "", dump_all: bool = False) -> str:
    """Dump table contents (exfiltrate data). Pass dump_all=True to dump every table in every non-system db.
    Inputs: URL, optional db name, optional table name, optional dump_all flag."""
    return _run_mcp_tool("sqlmap_dump", "run_sqlmap_dump", {
        "target": target,
        "db": db or None,
        "table": table or None,
        "dump_all": dump_all,
        "level": 2, "risk": 2, "wait": True,
    }, category="exploit", findings_cap=500, raw_cap=16000, return_cap=8000)
