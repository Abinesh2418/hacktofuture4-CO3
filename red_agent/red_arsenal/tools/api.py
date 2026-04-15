"""API testing tool wrappers: arjun, x8, paramspider, ffuf."""

from __future__ import annotations

import os
import tempfile

from .. import parsers
from ..config import DEFAULT_WORDLISTS, TOOLS
from ..runner import run


def _binary(name: str) -> str:
    spec = TOOLS[name]
    resolved = spec.resolve()
    if not resolved:
        raise RuntimeError(f"{name} not installed (run install.sh)")
    return resolved


async def arjun_impl(
    target: str,
    method: str = "GET,POST",
    stable: bool = True,
) -> dict:
    # arjun writes JSON to a file; we read it back for parsing.
    with tempfile.NamedTemporaryFile(
        prefix="arjun-", suffix=".json", delete=False
    ) as tf:
        out_path = tf.name
    try:
        cmd = [_binary("arjun"), "-u", target, "-m", method, "-oJ", out_path]
        if stable:
            cmd.append("--stable")
        raw = await run(cmd, timeout=TOOLS["arjun"].default_timeout)
        try:
            with open(out_path, "rb") as fh:
                raw.stdout = fh.read()
        except FileNotFoundError:
            pass
        return parsers.parse_arjun(raw, target)
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


async def x8_impl(
    target: str,
    method: str = "GET",
    wordlist: str | None = None,
) -> dict:
    wl = wordlist or DEFAULT_WORDLISTS.get("x8", "/usr/share/wordlists/x8/params.txt")
    cmd = [
        _binary("x8"),
        "-u", target,
        "-X", method,
        "-w", wl,
        "--output-format", "json",
    ]
    raw = await run(cmd, timeout=TOOLS["x8"].default_timeout)
    return parsers.parse_x8(raw, target)


async def paramspider_impl(target: str, level: int = 2) -> dict:
    # paramspider ignores stdout and writes to results/ by default; use
    # --quiet --output to pipe a file we can read.
    with tempfile.NamedTemporaryFile(
        prefix="ps-", suffix=".txt", delete=False
    ) as tf:
        out_path = tf.name
    try:
        cmd = [
            _binary("paramspider"),
            "-d", target,
            "-l", str(level),
            "-o", out_path,
            "--quiet",
        ]
        raw = await run(cmd, timeout=TOOLS["paramspider"].default_timeout)
        try:
            with open(out_path, "rb") as fh:
                raw.stdout = fh.read()
        except FileNotFoundError:
            pass
        return parsers.parse_paramspider(raw, target)
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


async def ffuf_impl(
    target: str,
    mode: str = "content",
    method: str = "GET",
    wordlist: str | None = None,
) -> dict:
    """mode: 'content' (FUZZ in URL) or 'parameter' (FUZZ as POST body)."""
    wl = wordlist or DEFAULT_WORDLISTS.get("ffuf", "/usr/share/seclists/Discovery/Web-Content/common.txt")
    if mode == "parameter":
        cmd = [
            _binary("ffuf"),
            "-u", target,
            "-X", method,
            "-d", "FUZZ=test",
            "-w", wl,
            "-mc", "200,204,301,302,307,401,403",
            "-of", "json", "-o", "-",
        ]
    else:
        url = target if "FUZZ" in target else target.rstrip("/") + "/FUZZ"
        cmd = [
            _binary("ffuf"),
            "-u", url,
            "-w", wl,
            "-of", "json", "-o", "-",
            "-mc", "200,204,301,302,307,401,403",
        ]
    raw = await run(cmd, timeout=TOOLS["ffuf"].default_timeout)
    return parsers.parse_ffuf(raw, target)
