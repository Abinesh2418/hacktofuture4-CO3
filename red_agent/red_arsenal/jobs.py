"""In-memory job registry for fire-and-forget tool execution.

Each submitted coroutine becomes an `asyncio.Task` keyed by job_id. The
registry never blocks — `submit()` returns immediately. A periodic GC task
drops completed jobs after JOB_RETENTION_S seconds.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from loguru import logger

from .config import JOB_RETENTION_S


@dataclass
class JobRecord:
    id: str
    tool: str
    task: asyncio.Task
    started_at: float
    finished_at: float | None = None
    result: dict | None = None
    error: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def status(self) -> str:
        if not self.task.done():
            return "running"
        if self.error is not None:
            return "error"
        return "done"

    def to_status_dict(self) -> dict:
        return {
            "job_id": self.id,
            "tool": self.tool,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": (
                round((self.finished_at or time.time()) - self.started_at, 3)
            ),
            "error": self.error,
        }


_jobs: dict[str, JobRecord] = {}
_gc_task: asyncio.Task | None = None


def submit(tool: str, coro: Awaitable[dict], extra: dict | None = None) -> str:
    """Schedule `coro` to run, return its job_id immediately."""
    _ensure_gc()
    job_id = uuid.uuid4().hex[:12]
    record = JobRecord(
        id=job_id,
        tool=tool,
        task=asyncio.create_task(_wrap(job_id, coro), name=f"{tool}:{job_id}"),
        started_at=time.time(),
        extra=extra or {},
    )
    _jobs[job_id] = record
    logger.info("job submit id={} tool={}", job_id, tool)
    return job_id


async def _wrap(job_id: str, coro: Awaitable[dict]) -> dict:
    """Run the coro, capture result or exception onto the JobRecord."""
    record = _jobs[job_id]
    try:
        result = await coro
        record.result = result
        return result
    except asyncio.CancelledError:
        record.error = "cancelled"
        raise
    except Exception as exc:
        logger.exception("job error id={} tool={}", job_id, record.tool)
        record.error = f"{type(exc).__name__}: {exc}"
        record.result = {"tool": record.tool, "ok": False, "error": record.error}
        return record.result
    finally:
        record.finished_at = time.time()


def get(job_id: str) -> JobRecord | None:
    return _jobs.get(job_id)


async def await_result(job_id: str, timeout: float | None = None) -> dict:
    record = _jobs.get(job_id)
    if record is None:
        return {"ok": False, "error": f"unknown job_id {job_id}"}
    try:
        return await asyncio.wait_for(asyncio.shield(record.task), timeout=timeout)
    except asyncio.TimeoutError:
        return {"job_id": job_id, "status": "running", "tool": record.tool}


def cancel(job_id: str) -> bool:
    record = _jobs.get(job_id)
    if record is None or record.task.done():
        return False
    record.task.cancel()
    return True


def list_jobs(status: str | None = None) -> list[dict]:
    out = [r.to_status_dict() for r in _jobs.values()]
    if status:
        out = [r for r in out if r["status"] == status]
    return out


def running_count() -> int:
    return sum(1 for r in _jobs.values() if not r.task.done())


def running_per_tool() -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in _jobs.values():
        if not r.task.done():
            counts[r.tool] = counts.get(r.tool, 0) + 1
    return counts


async def _gc_loop() -> None:
    while True:
        await asyncio.sleep(60)
        now = time.time()
        stale = [
            jid for jid, r in _jobs.items()
            if r.finished_at and (now - r.finished_at) > JOB_RETENTION_S
        ]
        for jid in stale:
            _jobs.pop(jid, None)
        if stale:
            logger.debug("job gc dropped {} stale", len(stale))


def _ensure_gc() -> None:
    """Lazily start the GC loop on the first submit (needs a running loop)."""
    global _gc_task
    if _gc_task is not None and not _gc_task.done():
        return
    try:
        _gc_task = asyncio.create_task(_gc_loop(), name="jobs-gc")
    except RuntimeError:
        # No running loop — caller is not inside async context yet.
        _gc_task = None
