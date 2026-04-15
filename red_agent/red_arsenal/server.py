"""FastMCP server entry point.

Exposes every Kali tool wrapper as an MCP tool over SSE transport. All calls
are fire-and-forget: they return a `job_id` immediately unless the caller
passes `wait=True`.

Run on the Kali VM:

    python -m red_arsenal.server
"""

from __future__ import annotations

import asyncio
from typing import Any

import psutil
from fastmcp import FastMCP
from loguru import logger

from . import jobs
from .config import HOST, PORT, TOOLS
from .tools import api as api_tools
from .tools import network as net_tools
from .tools import recon as recon_tools
from .workflows import run_workflow

mcp = FastMCP(name="red-arsenal")


# ---------- Helper: submit-or-wait -------------------------------------

async def _submit(tool: str, coro, wait: bool) -> dict:
    if wait:
        try:
            return await coro
        except Exception as exc:
            logger.exception("{} inline call failed", tool)
            return {"tool": tool, "ok": False, "error": f"{type(exc).__name__}: {exc}"}
    job_id = jobs.submit(tool, coro)
    return {"job_id": job_id, "tool": tool, "status": "running"}


# ---------- Recon tools -------------------------------------------------

@mcp.tool()
async def run_nmap(
    target: str,
    scan_type: str = "-sV -sC",
    ports: str = "80,443,8080,8443",
    wait: bool = False,
) -> dict:
    """Service/version scan. Returns job_id unless wait=True."""
    return await _submit("nmap", recon_tools.nmap_impl(target, scan_type, ports), wait)


@mcp.tool()
async def run_httpx(
    target: str,
    probe: bool = True,
    tech_detect: bool = True,
    wait: bool = False,
) -> dict:
    """HTTP probing + tech fingerprinting (ProjectDiscovery httpx)."""
    return await _submit("httpx", recon_tools.httpx_impl(target, probe, tech_detect), wait)


@mcp.tool()
async def run_katana(
    target: str,
    depth: int = 3,
    js_crawl: bool = True,
    wait: bool = False,
) -> dict:
    """Headless web crawler."""
    return await _submit("katana", recon_tools.katana_impl(target, depth, js_crawl), wait)


@mcp.tool()
async def run_gau(target: str, include_subs: bool = True, wait: bool = False) -> dict:
    """Fetch known URLs from OTX/Wayback/Common Crawl."""
    return await _submit("gau", recon_tools.gau_impl(target, include_subs), wait)


@mcp.tool()
async def run_waybackurls(target: str, wait: bool = False) -> dict:
    """Fetch historic URLs from the Wayback Machine."""
    return await _submit("waybackurls", recon_tools.waybackurls_impl(target), wait)


@mcp.tool()
async def run_nuclei(
    target: str,
    severity: str = "critical,high",
    tags: str | None = None,
    wait: bool = False,
) -> dict:
    """Template-based vulnerability scanner."""
    return await _submit("nuclei", recon_tools.nuclei_impl(target, severity, tags), wait)


@mcp.tool()
async def run_dirsearch(
    target: str,
    extensions: str = "php,html,js,txt",
    threads: int = 30,
    wait: bool = False,
) -> dict:
    """Directory / file brute-forcer."""
    return await _submit("dirsearch", recon_tools.dirsearch_impl(target, extensions, threads), wait)


@mcp.tool()
async def run_gobuster(
    target: str,
    mode: str = "dir",
    extensions: str = "php,html,js,txt",
    wait: bool = False,
) -> dict:
    """Gobuster dir/dns/vhost mode."""
    return await _submit("gobuster", recon_tools.gobuster_impl(target, mode, extensions), wait)


# ---------- API tools ---------------------------------------------------

@mcp.tool()
async def run_arjun(
    target: str,
    method: str = "GET,POST",
    stable: bool = True,
    wait: bool = False,
) -> dict:
    """HTTP parameter discovery via arjun."""
    return await _submit("arjun", api_tools.arjun_impl(target, method, stable), wait)


@mcp.tool()
async def run_x8(
    target: str,
    method: str = "GET",
    wordlist: str | None = None,
    wait: bool = False,
) -> dict:
    """Hidden-parameter discovery via x8."""
    return await _submit("x8", api_tools.x8_impl(target, method, wordlist), wait)


@mcp.tool()
async def run_paramspider(target: str, level: int = 2, wait: bool = False) -> dict:
    """Mine URLs with parameters from archived sources."""
    return await _submit("paramspider", api_tools.paramspider_impl(target, level), wait)


@mcp.tool()
async def run_ffuf(
    target: str,
    mode: str = "content",
    method: str = "GET",
    wordlist: str | None = None,
    wait: bool = False,
) -> dict:
    """ffuf in content or parameter fuzzing mode."""
    return await _submit("ffuf", api_tools.ffuf_impl(target, mode, method, wordlist), wait)


# ---------- Network tools ----------------------------------------------

@mcp.tool()
async def run_arp_scan(
    cidr: str | None = None,
    local_network: bool = True,
    wait: bool = False,
) -> dict:
    """Layer-2 host discovery."""
    return await _submit("arp-scan", net_tools.arp_scan_impl(cidr, local_network), wait)


@mcp.tool()
async def run_rustscan(
    target: str,
    ulimit: int = 5000,
    scripts: bool = False,
    wait: bool = False,
) -> dict:
    """Fast full-port scanner."""
    return await _submit("rustscan", net_tools.rustscan_impl(target, ulimit, scripts), wait)


@mcp.tool()
async def run_nmap_advanced(
    target: str,
    scan_type: str = "-sS",
    os_detection: bool = True,
    version_detection: bool = True,
    wait: bool = False,
) -> dict:
    """SYN scan with OS + version detection."""
    return await _submit(
        "nmap-advanced",
        net_tools.nmap_advanced_impl(target, scan_type, os_detection, version_detection),
        wait,
    )


@mcp.tool()
async def run_masscan(
    target: str,
    rate: int = 1000,
    ports: str = "1-65535",
    banners: bool = True,
    wait: bool = False,
) -> dict:
    """Mass TCP port scan."""
    return await _submit("masscan", net_tools.masscan_impl(target, rate, ports, banners), wait)


@mcp.tool()
async def run_enum4linux_ng(
    target: str,
    shares: bool = True,
    users: bool = True,
    groups: bool = True,
    wait: bool = False,
) -> dict:
    """SMB/Active Directory enumeration."""
    return await _submit(
        "enum4linux-ng",
        net_tools.enum4linux_ng_impl(target, shares, users, groups),
        wait,
    )


@mcp.tool()
async def run_nbtscan(target: str, verbose: bool = True, wait: bool = False) -> dict:
    """NetBIOS host scanner."""
    return await _submit("nbtscan", net_tools.nbtscan_impl(target, verbose), wait)


@mcp.tool()
async def run_smbmap(target: str, recursive: bool = True, wait: bool = False) -> dict:
    """SMB share enumeration."""
    return await _submit("smbmap", net_tools.smbmap_impl(target, recursive), wait)


@mcp.tool()
async def run_rpcclient(
    target: str,
    commands: str = "enumdomusers;enumdomgroups;querydominfo",
    wait: bool = False,
) -> dict:
    """Run rpcclient commands against a target."""
    return await _submit("rpcclient", net_tools.rpcclient_impl(target, commands), wait)


# ---------- Workflows --------------------------------------------------

@mcp.tool()
async def web_reconnaissance(
    target: str,
    wait: bool = False,
    only: list[str] | None = None,
    skip: list[str] | None = None,
) -> dict:
    """Parallel fan-out: nmap, httpx, katana, gau, waybackurls, nuclei, dirsearch, gobuster."""
    return await run_workflow("web_reconnaissance", target, wait=wait, only=only, skip=skip)


@mcp.tool()
async def api_testing(
    target: str,
    wait: bool = False,
    only: list[str] | None = None,
    skip: list[str] | None = None,
) -> dict:
    """Parallel fan-out: httpx, arjun, x8, paramspider, nuclei(api tags), ffuf."""
    return await run_workflow("api_testing", target, wait=wait, only=only, skip=skip)


@mcp.tool()
async def network_discovery(
    cidr: str,
    wait: bool = False,
    only: list[str] | None = None,
    skip: list[str] | None = None,
) -> dict:
    """Parallel fan-out: arp-scan, rustscan, nmap-advanced, masscan, enum4linux-ng, nbtscan, smbmap, rpcclient."""
    return await run_workflow("network_discovery", cidr, wait=wait, only=only, skip=skip)


# ---------- Job control ------------------------------------------------

@mcp.tool()
async def job_status(job_id: str) -> dict:
    """Return {status, tool, started_at, finished_at, duration_s, error}."""
    record = jobs.get(job_id)
    if record is None:
        return {"ok": False, "error": f"unknown job_id {job_id}"}
    return record.to_status_dict()


@mcp.tool()
async def job_result(job_id: str, wait: bool = True, timeout: float = 600) -> dict:
    """Fetch the parsed result for a job. Blocks until done if wait=True."""
    record = jobs.get(job_id)
    if record is None:
        return {"ok": False, "error": f"unknown job_id {job_id}"}
    if record.task.done():
        return record.result or {"ok": False, "error": record.error or "no result"}
    if not wait:
        return {"job_id": job_id, "status": "running", "tool": record.tool}
    return await jobs.await_result(job_id, timeout=timeout)


@mcp.tool()
async def job_cancel(job_id: str) -> dict:
    """Cancel a running job (kills the Kali process group)."""
    ok = jobs.cancel(job_id)
    return {"job_id": job_id, "cancelled": ok}


@mcp.tool()
async def list_jobs(status: str | None = None) -> dict:
    """Enumerate in-memory jobs. Optional filter: running | done | error."""
    return {"jobs": jobs.list_jobs(status)}


# ---------- Server introspection ---------------------------------------

@mcp.tool()
async def list_tools() -> dict:
    """Return installed Kali binaries (by `shutil.which` resolution)."""
    return {
        "tools": {
            name: {
                "installed": spec.installed,
                "path": spec.resolve(),
                "default_timeout": spec.default_timeout,
            }
            for name, spec in TOOLS.items()
        },
        "workflows": ["web_reconnaissance", "api_testing", "network_discovery"],
    }


@mcp.tool()
async def server_stats() -> dict:
    """Live view of load + running jobs. Purely informational."""
    vm = psutil.virtual_memory()
    try:
        load = psutil.getloadavg()
    except (AttributeError, OSError):
        load = (0.0, 0.0, 0.0)
    return {
        "running_jobs": jobs.running_count(),
        "per_tool": jobs.running_per_tool(),
        "load_avg": list(load),
        "mem_free_mb": vm.available // (1024 * 1024),
        "mem_percent": vm.percent,
        "cpu_percent": psutil.cpu_percent(interval=None),
    }


# ---------- Lifecycle --------------------------------------------------

@mcp.tool()
async def ping() -> dict:
    """Liveness check."""
    return {"ok": True, "service": "red-arsenal"}


def main() -> None:
    logger.info("red-arsenal starting on {}:{}", HOST, PORT)
    mcp.run(transport="sse", host=HOST, port=PORT)


if __name__ == "__main__":
    main()
