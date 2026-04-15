"""Parallel fan-out playbooks.

A workflow is a convenience multiplexer: it spawns one independent job per
member tool via `jobs.submit()` and returns the list of job handles. No
sequential chaining, no cross-step data flow, no result summarization —
the agent polls each job and decides what to do next.

`wait=True` gathers all jobs and returns raw results in one response.
"""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

from loguru import logger

from . import jobs
from .tools import api as api_tools
from .tools import network as net_tools
from .tools import recon as recon_tools

ToolCoro = Callable[..., Awaitable[dict]]


def _web_members(target: str) -> dict[str, ToolCoro]:
    return {
        "nmap":        lambda: recon_tools.nmap_impl(target),
        "httpx":       lambda: recon_tools.httpx_impl(target),
        "katana":      lambda: recon_tools.katana_impl(target),
        "gau":         lambda: recon_tools.gau_impl(target),
        "waybackurls": lambda: recon_tools.waybackurls_impl(target),
        "nuclei":      lambda: recon_tools.nuclei_impl(target, tags="tech"),
        "dirsearch":   lambda: recon_tools.dirsearch_impl(target),
        "gobuster":    lambda: recon_tools.gobuster_impl(target),
    }


def _api_members(target: str) -> dict[str, ToolCoro]:
    return {
        "httpx":       lambda: recon_tools.httpx_impl(target),
        "arjun":       lambda: api_tools.arjun_impl(target),
        "x8":          lambda: api_tools.x8_impl(target),
        "paramspider": lambda: api_tools.paramspider_impl(target),
        "nuclei":      lambda: recon_tools.nuclei_impl(target, tags="api,graphql,jwt"),
        "ffuf":        lambda: api_tools.ffuf_impl(target, mode="parameter", method="POST"),
    }


def _network_members(cidr: str) -> dict[str, ToolCoro]:
    return {
        "arp-scan":      lambda: net_tools.arp_scan_impl(cidr=cidr),
        "rustscan":      lambda: net_tools.rustscan_impl(cidr),
        "nmap-advanced": lambda: net_tools.nmap_advanced_impl(cidr),
        "masscan":       lambda: net_tools.masscan_impl(cidr),
        "enum4linux-ng": lambda: net_tools.enum4linux_ng_impl(cidr),
        "nbtscan":       lambda: net_tools.nbtscan_impl(cidr),
        "smbmap":        lambda: net_tools.smbmap_impl(cidr),
        "rpcclient":     lambda: net_tools.rpcclient_impl(cidr),
    }


WORKFLOW_REGISTRY: dict[str, Callable[[str], dict[str, ToolCoro]]] = {
    "web_reconnaissance": _web_members,
    "api_testing":        _api_members,
    "network_discovery":  _network_members,
}


def _filter(members: dict[str, ToolCoro],
            only: list[str] | None,
            skip: list[str] | None) -> dict[str, ToolCoro]:
    if only:
        members = {k: v for k, v in members.items() if k in set(only)}
    if skip:
        members = {k: v for k, v in members.items() if k not in set(skip)}
    return members


async def run_workflow(
    name: str,
    target: str,
    *,
    wait: bool = False,
    only: list[str] | None = None,
    skip: list[str] | None = None,
) -> dict:
    if name not in WORKFLOW_REGISTRY:
        return {"ok": False, "error": f"unknown workflow {name}"}
    members = _filter(WORKFLOW_REGISTRY[name](target), only, skip)
    logger.info("workflow {} target={} members={}", name, target, list(members))

    if wait:
        coros = [_safe_call(tool_name, factory) for tool_name, factory in members.items()]
        results = await asyncio.gather(*coros)
        return {
            "workflow": name,
            "target": target,
            "results": results,
        }

    submitted = []
    for tool_name, factory in members.items():
        job_id = jobs.submit(tool_name, factory(), extra={"workflow": name})
        submitted.append({"tool": tool_name, "job_id": job_id})
    return {
        "workflow": name,
        "target": target,
        "jobs": submitted,
    }


async def _safe_call(tool_name: str, factory: ToolCoro) -> dict:
    try:
        return await factory()
    except Exception as exc:
        logger.exception("workflow member {} failed", tool_name)
        return {
            "tool": tool_name,
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
