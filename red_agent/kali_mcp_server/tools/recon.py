"""Web reconnaissance tool wrappers.

Each `*_impl` is a pure coroutine that spawns the binary, parses output, and
returns the normalized dict. The MCP-facing layer in `server.py` wraps these
in `jobs.submit()` so they run as independent tasks.
"""

from __future__ import annotations

from loguru import logger

from .. import parsers
from ..config import DEFAULT_WORDLISTS, TOOLS
from ..runner import run


def _binary(name: str) -> str:
    spec = TOOLS[name]
    resolved = spec.resolve()
    if not resolved:
        raise RuntimeError(f"{name} not installed (run install.sh)")
    return resolved


async def nmap_impl(
    target: str,
    scan_type: str = "-sV -sC",
    ports: str = "80,443,8080,8443",
) -> dict:
    cmd = [_binary("nmap"), *scan_type.split(), "-p", ports, "-oX", "-", target]
    raw = await run(cmd, timeout=TOOLS["nmap"].default_timeout)
    return parsers.parse_nmap(raw, target)


async def httpx_impl(
    target: str,
    probe: bool = True,
    tech_detect: bool = True,
) -> dict:
    cmd = [_binary("httpx"), "-u", target, "-json", "-silent"]
    if probe:
        cmd.append("-probe")
    if tech_detect:
        cmd.append("-tech-detect")
    cmd += ["-status-code", "-title", "-web-server", "-content-length"]
    raw = await run(cmd, timeout=TOOLS["httpx"].default_timeout)
    return parsers.parse_httpx(raw, target)


async def katana_impl(
    target: str,
    depth: int = 3,
    js_crawl: bool = True,
) -> dict:
    cmd = [_binary("katana"), "-u", target, "-d", str(depth), "-jsonl", "-silent"]
    if js_crawl:
        cmd.append("-jc")
    raw = await run(cmd, timeout=TOOLS["katana"].default_timeout)
    return parsers.parse_katana(raw, target)


async def gau_impl(target: str, include_subs: bool = True) -> dict:
    cmd = [_binary("gau"), target]
    if include_subs:
        cmd.append("--subs")
    raw = await run(cmd, timeout=TOOLS["gau"].default_timeout)
    return parsers.parse_gau(raw, target)


async def waybackurls_impl(target: str) -> dict:
    cmd = [_binary("waybackurls"), target]
    raw = await run(cmd, timeout=TOOLS["waybackurls"].default_timeout)
    return parsers.parse_waybackurls(raw, target)


async def nuclei_impl(
    target: str,
    severity: str = "critical,high",
    tags: str | None = None,
) -> dict:
    cmd = [
        _binary("nuclei"), "-u", target, "-jsonl", "-silent",
        "-severity", severity,
    ]
    if tags:
        cmd += ["-tags", tags]
    raw = await run(cmd, timeout=TOOLS["nuclei"].default_timeout)
    return parsers.parse_nuclei(raw, target)


async def dirsearch_impl(
    target: str,
    extensions: str = "php,html,js,txt",
    threads: int = 30,
) -> dict:
    cmd = [
        _binary("dirsearch"), "-u", target,
        "-e", extensions, "-t", str(threads), "--quiet",
        "--format=plain",
    ]
    wordlist = DEFAULT_WORDLISTS.get("dirsearch")
    if wordlist:
        cmd += ["-w", wordlist]
    raw = await run(cmd, timeout=TOOLS["dirsearch"].default_timeout)
    return parsers.parse_dirsearch(raw, target)


async def gobuster_impl(
    target: str,
    mode: str = "dir",
    extensions: str = "php,html,js,txt",
) -> dict:
    wordlist = DEFAULT_WORDLISTS.get("gobuster", "/usr/share/wordlists/dirb/common.txt")
    cmd = [
        _binary("gobuster"), mode,
        "-u", target,
        "-w", wordlist,
        "-x", extensions,
        "-q", "--no-error",
    ]
    raw = await run(cmd, timeout=TOOLS["gobuster"].default_timeout)
    return parsers.parse_gobuster(raw, target)
