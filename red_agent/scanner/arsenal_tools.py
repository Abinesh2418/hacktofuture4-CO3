"""CrewAI tool wrappers around the existing Red Arsenal tool impls.

The Arsenal tool impls (`red_agent.red_arsenal.tools.recon` / `.api`) are plain
async Python coroutines that already return normalized, parser-structured
dicts. We call them in-process instead of over HTTP — there is no REST layer
in front of the MCP server.

Each wrapper:
  * is a sync function (CrewAI tool interface),
  * runs the underlying coroutine via asyncio.run() in a worker thread
    (the CrewAI crew is itself driven from a thread executor, so a fresh
    event loop is safe),
  * catches every error and returns a short diagnostic string so the LLM
    can keep going,
  * truncates output to 500 chars to stay token-efficient.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Awaitable, Callable
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

MAX_TOOL_OUTPUT_CHARS = 400
MAX_FINDINGS_IN_SUMMARY = 5
DEFAULT_TOOL_TIMEOUT = int(os.getenv("RECON_TOOL_TIMEOUT", "120"))


# --- CrewAI tool decorator (graceful fallback) ------------------------------
try:
    from crewai.tools import tool as crewai_tool  # type: ignore
except Exception:  # pragma: no cover - crewai optional at import time
    def crewai_tool(name: str):  # type: ignore
        def _wrap(fn):
            fn.name = name
            return fn
        return _wrap


# --- Underlying Arsenal impls (import lazily to avoid hard failure) ---------
def _load_impls():
    from red_agent.red_arsenal.tools import api as api_tools
    from red_agent.red_arsenal.tools import recon as recon_tools
    return recon_tools, api_tools


def _host_only(target: str) -> str:
    """Strip URL scheme/path for tools that want a bare host (nmap)."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target.split("/", 1)[0]


def _run_coro(
    label: str,
    factory: Callable[[], Awaitable[dict]],
) -> str:
    """Execute a tool coroutine and return a short JSON-ish string."""
    try:
        result = asyncio.run(
            asyncio.wait_for(factory(), timeout=DEFAULT_TOOL_TIMEOUT)
        )
    except asyncio.TimeoutError:
        return f"{label} timed out after {DEFAULT_TOOL_TIMEOUT}s"
    except RuntimeError as exc:
        # Binary not installed or nested-loop issue
        return f"{label} unavailable: {str(exc)[:180]}"
    except Exception as exc:  # noqa: BLE001
        logger.warning("[arsenal_tools] %s failed: %s", label, exc)
        return f"{label} error: {str(exc)[:180]}"

    findings = result.get("findings") or []
    # For nmap, only surface ports with state="open" — this saves tokens AND
    # stops the LLM from reporting closed/filtered ports as open.
    if label == "nmap":
        findings = [
            f for f in findings
            if isinstance(f, dict) and f.get("state") == "open"
        ]

    # Drop noisy fields to save tokens (version strings, full URLs).
    trimmed: list[dict] = []
    for f in findings[:MAX_FINDINGS_IN_SUMMARY]:
        if isinstance(f, dict):
            trimmed.append(
                {
                    k: v
                    for k, v in f.items()
                    if k in (
                        "port", "state", "service", "product",
                        "status", "path", "url", "severity", "name", "host",
                    )
                    and v is not None
                }
            )
        else:
            trimmed.append({"value": str(f)[:60]})

    summary = {
        "tool": result.get("tool", label),
        "ok": result.get("ok"),
        "count": len(findings),
        "findings": trimmed,
    }
    err = result.get("error")
    if err:
        summary["error"] = str(err)[:80]
    try:
        text = json.dumps(summary, default=str)
    except Exception:  # noqa: BLE001
        text = str(summary)
    return text[:MAX_TOOL_OUTPUT_CHARS]


# --- CrewAI-facing tool functions ------------------------------------------

@crewai_tool("nmap_scanner")
def nmap_scan(target: str) -> str:
    """Run nmap service/version scan (`-sV -sC`) on top common ports.
    Use for: open ports and running services.
    Input: target URL, hostname, or IP (scheme will be stripped).
    """
    host = _host_only(target)
    recon, _ = _load_impls()
    return _run_coro("nmap", lambda: recon.nmap_impl(host))


@crewai_tool("nuclei_scanner")
def nuclei_scan(target: str) -> str:
    """Run nuclei vulnerability templates at critical+high severity.
    Use for: CVE detection with 4000+ templates.
    Input: target URL.
    """
    recon, _ = _load_impls()
    return _run_coro(
        "nuclei",
        lambda: recon.nuclei_impl(target, severity="critical,high"),
    )


@crewai_tool("katana_crawler")
def katana_crawl(target: str) -> str:
    """Headless web crawler, depth 3, JS crawling on.
    Use for: enumerating URLs, JS endpoints, site structure.
    Input: target URL.
    """
    recon, _ = _load_impls()
    return _run_coro("katana", lambda: recon.katana_impl(target))


@crewai_tool("gobuster_scanner")
def gobuster_scan(target: str) -> str:
    """Directory brute-forcer (gobuster dir mode, common wordlist).
    Use for: finding admin panels, hidden paths, config files.
    Input: target URL.
    """
    recon, _ = _load_impls()
    return _run_coro("gobuster", lambda: recon.gobuster_impl(target))


@crewai_tool("dirsearch_scanner")
def dirsearch_scan(target: str) -> str:
    """Directory / file brute-forcer (dirsearch).
    Use for: alternate content discovery when gobuster misses.
    Input: target URL.
    """
    recon, _ = _load_impls()
    return _run_coro("dirsearch", lambda: recon.dirsearch_impl(target))


@crewai_tool("gau_scanner")
def gau_scan(target: str) -> str:
    """Fetch historical URLs from OTX/Wayback/CommonCrawl (gau).
    Use for: passive URL discovery on a domain — expanding attack surface.
    Input: domain or URL.
    """
    recon, _ = _load_impls()
    return _run_coro("gau", lambda: recon.gau_impl(target))


@crewai_tool("ffuf_fuzzer")
def ffuf_scan(target: str) -> str:
    """Fast web fuzzer (ffuf content mode).
    Use for: hidden endpoints and parameters.
    Input: target URL (FUZZ injected by tool).
    """
    _, api = _load_impls()
    return _run_coro("ffuf", lambda: api.ffuf_impl(target))


ALL_RECON_TOOLS = [
    nmap_scan,
    nuclei_scan,
    katana_crawl,
    gobuster_scan,
    dirsearch_scan,
    gau_scan,
    ffuf_scan,
]
# httpx_probe is intentionally excluded: the Python `httpx` package ships a
# CLI with the same binary name, which shadows ProjectDiscovery's httpx in
# any venv that has `pip install httpx`. Re-add once PD httpx is resolvable.
