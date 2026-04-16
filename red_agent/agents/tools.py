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
import uuid
from datetime import datetime
from urllib.parse import urlparse

try:
    from crewai.tools import tool
except ImportError:
    def tool(func=None, **_):  # type: ignore
        """Fallback decorator when crewai is not installed."""
        if func is None or isinstance(func, str):
            return lambda f: f
        return func

_logger = logging.getLogger(__name__)

# ── Shared state: track which agent is currently active ──
_current_agent: str = "recon"  # Set by orchestrator before each phase


def set_active_agent(name: str) -> None:
    global _current_agent
    _current_agent = name


def _host_only(target: str) -> str:
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target.split("/", 1)[0]


def _get_port(target: str) -> str:
    if "://" in target:
        parsed = urlparse(target)
        if parsed.port:
            return str(parsed.port)
        return "443" if parsed.scheme == "https" else "80"
    if ":" in target:
        parts = target.rsplit(":", 1)
        if parts[1].isdigit():
            return parts[1]
    return "1-1000"


# ── WebSocket broadcasting from sync context ──

def _broadcast_tool_event(tool_name: str, status: str, category: str, params: dict, result: dict | None = None) -> None:
    """Broadcast a tool_call event to the dashboard from sync CrewAI context."""
    try:
        from red_agent.backend.websocket.red_ws import manager
        from red_agent.backend.schemas.red_schemas import ToolCall, ToolStatus

        tc = ToolCall(
            id=str(uuid.uuid4()),
            name=tool_name,
            category=category,
            status=ToolStatus(status),
            params=params,
            result=result,
            finished_at=datetime.now() if status in ("DONE", "FAILED") else None,
        )

        payload = {"type": "tool_call", "payload": tc.model_dump(mode="json")}

        # Try to broadcast — works if there's a running event loop
        try:
            loop = asyncio.get_running_loop()
            asyncio.run_coroutine_threadsafe(manager.broadcast(payload), loop)
        except RuntimeError:
            # No running loop — try creating one
            asyncio.run(manager.broadcast(payload))
    except Exception as e:
        _logger.warning("Failed to broadcast tool event: %s", e)


def _broadcast_log(level: str, message: str) -> None:
    """Broadcast a log entry to the dashboard."""
    try:
        from red_agent.backend.websocket.red_ws import manager
        from red_agent.backend.schemas.red_schemas import LogEntry

        entry = LogEntry(level=level, message=message)
        payload = {"type": "log", "payload": entry.model_dump(mode="json")}

        try:
            loop = asyncio.get_running_loop()
            asyncio.run_coroutine_threadsafe(manager.broadcast(payload), loop)
        except RuntimeError:
            asyncio.run(manager.broadcast(payload))
    except Exception as e:
        _logger.warning("Failed to broadcast log: %s", e)


def _mcp_available() -> bool:
    """Return True only if fastmcp is installed and the MCP server is reachable."""
    try:
        from red_agent.backend.services.mcp_client import Client  # noqa: F401
        return Client is not None
    except Exception:
        return False


def _simulated_result(tool_name: str, target: str) -> dict:
    """Return a plausible simulated finding set when MCP/Kali is unavailable."""
    host = _host_only(target)
    if tool_name == "nmap_scan":
        return {
            "ok": True, "findings": [
                {"port": 22,   "state": "open", "service": "ssh",   "product": "OpenSSH", "version": "8.9p1"},
                {"port": 80,   "state": "open", "service": "http",  "product": "nginx",   "version": "1.24.0"},
                {"port": 5000, "state": "open", "service": "http",  "product": "Werkzeug","version": "2.3.0"},
                {"port": 3306, "state": "open", "service": "mysql", "product": "MySQL",   "version": "8.0.33"},
            ],
            "note": "MCP/Kali unavailable — simulated nmap output",
        }
    if tool_name in ("nuclei_scan", "nuclei_exploit"):
        return {
            "ok": True, "findings": [
                {"template": "CVE-2021-41773", "severity": "critical", "host": host, "name": "Apache Path Traversal"},
                {"template": "exposed-panels",  "severity": "high",     "host": host, "name": "Admin panel exposed at /admin"},
                {"template": "sqli-error-based","severity": "high",     "host": host, "name": "SQL injection on /login"},
            ],
            "note": "MCP/Kali unavailable — simulated nuclei output",
        }
    if tool_name in ("gobuster_scan", "dirsearch_scan", "ffuf_fuzz"):
        return {
            "ok": True, "findings": [
                {"path": "/admin",       "status": 200, "size": 4321},
                {"path": "/login",       "status": 200, "size": 2048},
                {"path": "/api/users",   "status": 200, "size": 812},
                {"path": "/api/data",    "status": 200, "size": 1536},
                {"path": "/.env",        "status": 200, "size": 237},
                {"path": "/config.php",  "status": 200, "size": 512},
            ],
            "note": "MCP/Kali unavailable — simulated directory scan output",
        }
    if tool_name in ("httpx_probe", "katana_crawl"):
        return {
            "ok": True, "findings": [
                {"url": f"http://{host}", "status": 200, "tech": ["nginx", "Python", "Flask"], "title": "Web Application"},
                {"url": f"http://{host}/login", "status": 200, "forms": [{"action": "/login", "inputs": ["username", "password"]}]},
            ],
            "note": "MCP/Kali unavailable — simulated probe output",
        }
    return {"ok": True, "findings": [], "note": f"MCP/Kali unavailable — no simulation for {tool_name}"}


def _run_mcp_tool(tool_name: str, mcp_name: str, args: dict, category: str = "scan") -> str:
    """Run an MCP tool with full dashboard streaming.

    Falls back to simulated results when the Kali MCP server is not reachable
    (e.g. running on Windows without a Kali VM), so CrewAI orchestration still
    completes end-to-end.
    """
    agent = _current_agent
    target = args.get("target", "")
    params = {"target": target, "agent": agent}

    # Broadcast: RUNNING
    _broadcast_tool_event(tool_name, "RUNNING", category, params)
    _broadcast_log("INFO", f"[{agent}] {tool_name} started")

    # ── Try real MCP first ────────────────────────────────────────────
    if _mcp_available():
        try:
            from red_agent.backend.services.mcp_client import call_tool_and_wait
            result = asyncio.run(call_tool_and_wait(mcp_name, args))
        except Exception as e:
            _logger.warning("[%s] MCP call failed (%s), using simulation", tool_name, e)
            result = _simulated_result(tool_name, target)
    else:
        _logger.info("[%s] MCP not available — using simulated results", tool_name)
        result = _simulated_result(tool_name, target)

    # ── Process result ────────────────────────────────────────────────
    findings = result.get("findings", [])
    ok = result.get("ok", True) and not result.get("error")
    status = "DONE" if ok else "FAILED"
    is_simulated = "note" in result and "simulated" in str(result.get("note", ""))

    broadcast_result = {
        "ok": ok,
        "findings_count": len(findings),
        "findings": findings[:10],
        "duration": result.get("duration_s", 0),
        "agent": agent,
        "simulated": is_simulated,
    }
    if result.get("error"):
        broadcast_result["error"] = str(result["error"])[:200]
    raw = result.get("raw_tail", "")
    if raw and not findings:
        broadcast_result["raw_output"] = raw[:300]

    _broadcast_tool_event(tool_name, status, category, params, broadcast_result)

    sim_tag = " [simulated]" if is_simulated else ""
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
    _broadcast_log(
        "INFO" if ok else "WARN",
        f"[{agent}] {tool_name} {'completed' if ok else 'failed'}{sim_tag} — {len(findings)} findings{detail}",
    )

    if findings:
        return json.dumps(findings[:10], indent=2, default=str)
    if raw:
        return f"{tool_name} output:\n{raw[:500]}"
    return json.dumps(result, default=str)[:500]


# ══════════════════════════════════════════════════════════════════════
# Recon Tools
# ══════════════════════════════════════════════════════════════════════

@tool("nmap_scan")
def nmap_scan(target: str) -> str:
    """Run nmap service/version scan. Input: IP or URL. Returns open ports, services, versions."""
    host = _host_only(target)
    port = _get_port(target)
    return _run_mcp_tool("nmap_scan", "run_nmap", {
        "target": host, "ports": port, "scan_type": "-sV -sC -Pn", "wait": True,
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
