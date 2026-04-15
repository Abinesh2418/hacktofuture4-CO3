"""Async subprocess launcher.

Every tool wrapper calls `run()`. It spawns an independent Kali process, with
no semaphore or queue — parallelism is bounded only by the OS scheduler.
"""

from __future__ import annotations

import asyncio
import os
import signal
import time
from dataclasses import dataclass, field

from loguru import logger

from .config import DEFAULT_TIMEOUT


@dataclass
class RunResult:
    cmd: list[str]
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_s: float
    pid: int | None
    timed_out: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def text_out(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")

    def text_err(self) -> str:
        return self.stderr.decode("utf-8", errors="replace")


async def run(
    cmd: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
    stdin: bytes | None = None,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> RunResult:
    """Spawn `cmd` as an independent subprocess and return its RunResult.

    Uses start_new_session=True so the entire process group can be killed on
    timeout or cancellation without leaking child scanners.
    """
    start = time.monotonic()
    logger.debug("spawn {}", " ".join(cmd))

    # On POSIX we create a new session for killpg. On Windows (tests), fall
    # back to plain subprocess — the server only runs on Kali anyway.
    kwargs = dict(
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={**os.environ, **(env or {})},
        cwd=cwd,
    )
    if os.name == "posix":
        kwargs["start_new_session"] = True

    proc = await asyncio.create_subprocess_exec(cmd[0], *cmd[1:], **kwargs)
    pid = proc.pid
    timed_out = False

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin), timeout=timeout
        )
    except asyncio.TimeoutError:
        timed_out = True
        logger.warning("timeout pid={} cmd={}", pid, cmd[0])
        _kill(proc, pid)
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
        except asyncio.TimeoutError:
            stdout, stderr = b"", b""
    except asyncio.CancelledError:
        logger.info("cancelled pid={} cmd={}", pid, cmd[0])
        _kill(proc, pid)
        raise
    finally:
        if proc.returncode is None:
            _kill(proc, pid)
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except asyncio.TimeoutError:
                pass

    duration = time.monotonic() - start
    return RunResult(
        cmd=cmd,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout or b"",
        stderr=stderr or b"",
        duration_s=round(duration, 3),
        pid=pid,
        timed_out=timed_out,
    )


def _kill(proc: asyncio.subprocess.Process, pid: int) -> None:
    """Kill the whole process group on POSIX, single proc elsewhere."""
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError):
        pass
