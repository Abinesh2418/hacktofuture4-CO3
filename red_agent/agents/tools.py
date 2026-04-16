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

from crewai.tools import tool

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
            finished_at=datetime.utcnow() if status in ("DONE", "FAILED") else None,
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


def _run_mcp_tool(tool_name: str, mcp_name: str, args: dict, category: str = "scan") -> str:
    """Run an MCP tool with full dashboard streaming."""
    agent = _current_agent
    params = {"target": args.get("target", ""), "agent": agent}

    # Broadcast: RUNNING
    _broadcast_tool_event(tool_name, "RUNNING", category, params)
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
            "findings": findings[:10],
            "duration": result.get("duration_s", 0),
            "agent": agent,
        }
        # Add error info if failed
        if result.get("error"):
            broadcast_result["error"] = str(result["error"])[:200]
        # Add raw output snippet for context
        raw = result.get("raw_tail", "")
        if raw and not findings:
            broadcast_result["raw_output"] = raw[:300]

        _broadcast_tool_event(tool_name, status, category, params, broadcast_result)

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
        _broadcast_log(
            "INFO" if ok else "WARN",
            f"[{agent}] {tool_name} {'completed' if ok else 'failed'} — {len(findings)} findings{detail}",
        )

        # Return results for CrewAI agent
        if findings:
            return json.dumps(findings[:10], indent=2, default=str)
        raw = result.get("raw_tail", "")
        if raw:
            return f"{tool_name} output:\n{raw[:500]}"
        return json.dumps(result, default=str)[:500]

    except Exception as e:
        _broadcast_tool_event(tool_name, "FAILED", category, params, {"error": str(e), "agent": agent})
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
