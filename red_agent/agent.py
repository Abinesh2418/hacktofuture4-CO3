"""Single Red Team Agent — one LLM brain, all Kali tools, parallel execution.

Architecture:
  - Memory: structured store of all tool results the agent has collected
  - Parallel execution: when the LLM returns multiple tool_calls, they run
    concurrently via asyncio.gather on the Kali VM
  - Reasoning from memory: each LLM iteration sees the full memory and
    decides what to do next based on accumulated findings

Usage:
    agent = RedTeamAgent(target="http://172.25.8.172:5000")
    result = await agent.run()
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

import httpx
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# ── LLM Config ──────────────────────────────────────────────────────

AZURE_API_KEY = os.environ.get("AZURE_API_KEY", "")
AZURE_ENDPOINT = os.environ.get("AZURE_ENDPOINT", "").rstrip("/")
AZURE_MODEL = "gpt-4o"
AZURE_API_VERSION = "2024-10-21"
AZURE_URL = f"{AZURE_ENDPOINT}/openai/deployments/{AZURE_MODEL}/chat/completions?api-version={AZURE_API_VERSION}"

MAX_ITERATIONS = 15


# ── MCP tool caller ─────────────────────────────────────────────────

async def _mcp_call(tool_name: str, args: dict, timeout: float = 600) -> dict:
    """Execute an MCP tool on the Kali VM."""
    from red_agent.backend.services.mcp_client import call_tool_and_wait
    try:
        return await asyncio.wait_for(
            call_tool_and_wait(tool_name, {**args, "wait": True}),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return {"tool": tool_name, "ok": False, "error": f"timeout after {timeout}s"}
    except Exception as exc:
        return {"tool": tool_name, "ok": False, "error": str(exc)[:200]}


# ── LLM caller ──────────────────────────────────────────────────────

async def _llm_call(messages: list[dict], tools: list[dict]) -> dict:
    """Single Azure GPT-4o call with function calling.
    Supports parallel tool calls — GPT-4o can return multiple tool_calls."""
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(
            AZURE_URL,
            headers={"api-key": AZURE_API_KEY, "Content-Type": "application/json"},
            json={
                "model": AZURE_MODEL,
                "messages": messages,
                "tools": tools,
                "tool_choice": "auto",
                "parallel_tool_calls": True,
                "max_tokens": 4096,
                "temperature": 0,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        choices = data.get("choices", [])
        if not choices:
            return {"role": "assistant", "content": "No response from LLM."}
        return choices[0].get("message", {})


# ── Tool schemas ────────────────────────────────────────────────────

TOOL_SCHEMAS = [
    # ── Recon ──
    {"type": "function", "function": {
        "name": "nmap_scan",
        "description": "Port scan and service detection. Use FIRST to discover open ports. Input: hostname or IP (no http://).",
        "parameters": {"type": "object", "properties": {
            "target": {"type": "string", "description": "Hostname or IP"},
            "ports": {"type": "string", "description": "Port range", "default": "22,80,443,3306,5000,8080,8443"},
        }, "required": ["target"]},
    }},
    {"type": "function", "function": {
        "name": "gobuster_scan",
        "description": "Brute-force directories and files on a web server.",
        "parameters": {"type": "object", "properties": {
            "target": {"type": "string", "description": "Full URL"},
        }, "required": ["target"]},
    }},
    {"type": "function", "function": {
        "name": "nuclei_scan",
        "description": "Vulnerability scanner with 4000+ templates. Detects CVEs, misconfigs, exposed panels.",
        "parameters": {"type": "object", "properties": {
            "target": {"type": "string", "description": "Full URL"},
            "severity": {"type": "string", "default": "critical,high,medium"},
        }, "required": ["target"]},
    }},
    {"type": "function", "function": {
        "name": "httpx_probe",
        "description": "Probe web server for status codes, headers, technology stack.",
        "parameters": {"type": "object", "properties": {
            "target": {"type": "string"},
        }, "required": ["target"]},
    }},
    {"type": "function", "function": {
        "name": "ffuf_fuzz",
        "description": "Fuzz web endpoints for hidden parameters and paths.",
        "parameters": {"type": "object", "properties": {
            "target": {"type": "string"},
        }, "required": ["target"]},
    }},
    # ── Exploit ──
    {"type": "function", "function": {
        "name": "sqlmap_get_databases",
        "description": "Discover databases via SQL injection. Use when you find a login page or form.",
        "parameters": {"type": "object", "properties": {
            "target_url": {"type": "string", "description": "URL with vulnerable form"},
        }, "required": ["target_url"]},
    }},
    {"type": "function", "function": {
        "name": "sqlmap_get_tables",
        "description": "List tables in a database. Use after sqlmap_get_databases.",
        "parameters": {"type": "object", "properties": {
            "target_url": {"type": "string"},
            "database": {"type": "string"},
        }, "required": ["target_url", "database"]},
    }},
    {"type": "function", "function": {
        "name": "sqlmap_dump_table",
        "description": "Dump rows from a table. Use on sensitive tables (users, credentials).",
        "parameters": {"type": "object", "properties": {
            "target_url": {"type": "string"},
            "database": {"type": "string"},
            "table": {"type": "string"},
        }, "required": ["target_url", "database", "table"]},
    }},
    {"type": "function", "function": {
        "name": "hydra_bruteforce",
        "description": "Brute-force a login form. Use when login found but NO SQLi.",
        "parameters": {"type": "object", "properties": {
            "target_url": {"type": "string"},
            "username": {"type": "string", "default": "admin"},
            "username_field": {"type": "string", "default": "username"},
            "password_field": {"type": "string", "default": "password"},
            "fail_message": {"type": "string", "default": "Invalid"},
        }, "required": ["target_url"]},
    }},
    {"type": "function", "function": {
        "name": "curl_lfi_test",
        "description": "Test for Local File Inclusion via path traversal.",
        "parameters": {"type": "object", "properties": {
            "target_url": {"type": "string"},
            "parameter": {"type": "string", "default": "file"},
        }, "required": ["target_url"]},
    }},
    {"type": "function", "function": {
        "name": "curl_cmd_injection",
        "description": "Test for OS command injection.",
        "parameters": {"type": "object", "properties": {
            "target_url": {"type": "string"},
            "parameter": {"type": "string", "default": "ip"},
        }, "required": ["target_url"]},
    }},
    # ── Report ──
    {"type": "function", "function": {
        "name": "submit_report",
        "description": "Submit the final penetration test report. Call once at the end.",
        "parameters": {"type": "object", "properties": {
            "vulnerabilities": {"type": "array", "items": {"type": "object", "properties": {
                "type": {"type": "string"},
                "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                "location": {"type": "string"},
                "parameter": {"type": "string"},
                "evidence": {"type": "string"},
                "exploited": {"type": "boolean"},
            }}},
            "credentials_found": {"type": "array", "items": {"type": "object", "properties": {
                "username": {"type": "string"},
                "password": {"type": "string"},
            }}},
            "databases_found": {"type": "array", "items": {"type": "string"}},
            "dbms": {"type": "string"},
            "open_ports": {"type": "array", "items": {"type": "integer"}},
            "tech_stack": {"type": "array", "items": {"type": "string"}},
            "risk_score": {"type": "number", "description": "0-10"},
        }, "required": ["vulnerabilities", "risk_score"]},
    }},
]

# ── Tool name → MCP name mapping ────────────────────────────────────

_TOOL_MAP = {
    "nmap_scan": "run_nmap",
    "gobuster_scan": "run_gobuster",
    "nuclei_scan": "run_nuclei",
    "httpx_probe": "run_httpx",
    "ffuf_fuzz": "run_ffuf",
    "sqlmap_get_databases": "run_sqlmap_dbs",
    "sqlmap_get_tables": "run_sqlmap_tables",
    "sqlmap_dump_table": "run_sqlmap_dump",
    "hydra_bruteforce": "run_hydra",
    "curl_lfi_test": "run_curl_lfi",
    "curl_cmd_injection": "run_curl_cmdi",
}


def _map_args(fn_name: str, args: dict) -> dict:
    """Translate agent function args to MCP tool args."""
    if fn_name == "nmap_scan":
        target = args.get("target", "")
        if "://" in target:
            from urllib.parse import urlparse
            target = urlparse(target).hostname or target
        return {"target": target, "ports": args.get("ports", "22,80,443,3306,5000,8080,8443"), "scan_type": "-sV -sC -Pn"}
    if fn_name in ("gobuster_scan", "nuclei_scan", "httpx_probe", "ffuf_fuzz"):
        return {"target": args.get("target", "")}
    if fn_name == "sqlmap_get_databases":
        return {"target_url": args.get("target_url", ""), "forms": True}
    if fn_name == "sqlmap_get_tables":
        return {"target_url": args.get("target_url", ""), "database": args.get("database", ""), "forms": True}
    if fn_name == "sqlmap_dump_table":
        return {"target_url": args.get("target_url", ""), "database": args.get("database", ""), "table": args.get("table", ""), "forms": True}
    return {k: v for k, v in args.items()}


def _is_sqlmap_noise(val: str) -> bool:
    """Check if a string is sqlmap ASCII art/banner noise."""
    noise_markers = ["sqlmap.org", "___|", "_|V", "[.]", "[)]", "['|", "__|", "http"]
    return any(m in val for m in noise_markers) or val.startswith("_") or "@" in val


def _clean_sqlmap_list(items: list) -> list:
    """Remove sqlmap ASCII art noise from a list of strings."""
    return [x for x in items if isinstance(x, str) and not _is_sqlmap_noise(x)]


def _compact_result(result: dict) -> str:
    """Compact tool result for the LLM context."""
    findings = result.get("findings") or []
    out: dict[str, Any] = {
        "ok": result.get("ok"),
        "findings_count": len(findings),
        "findings": findings[:10],
    }
    for key in ("databases", "dbms", "injectable", "tables", "columns",
                "rows_dumped", "sample_rows", "credentials_found",
                "files_read", "summary"):
        if key in result and result[key]:
            val = result[key]
            # Clean sqlmap noise from lists
            if key in ("databases", "tables") and isinstance(val, list):
                val = _clean_sqlmap_list(val)
            out[key] = val
    err = result.get("error")
    if err:
        out["error"] = str(err)[:100]
    return json.dumps(out, default=str)[:1500]


# ── System prompt ───────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an autonomous penetration testing agent operating in an AUTHORIZED
lab/CTF environment. Before acting, confirm the target matches the scope
provided in your task input. If it does not, stop and report the mismatch.

## OPERATING PRINCIPLES

Think before you scan. Each tool call costs time and signal — plan the next
step based on what you've actually learned, not a fixed checklist. State a
one-line hypothesis before each tool call ("testing whether /login is
backed by a SQL DB") and update it from the output.

Prefer the least invasive check that answers the question. Enumerate before
you exploit; confirm a vulnerability exists before dumping data from it.
When a finding is already proven, move on — don't re-confirm with heavier
tools.

## PARALLELISM

You can call MULTIPLE tools in a single response. They will execute
concurrently on the Kali VM. Use this to save time:
- Recon: call nmap_scan + httpx_probe together
- After nmap finds web ports: call gobuster_scan + nuclei_scan together
- Exploit multiple surfaces: test SQLi on /login while testing CMDi on /cmd

Only parallelize tools that are INDEPENDENT. Don't call sqlmap_get_tables
before sqlmap_get_databases returns — you need the database name first.

## MEMORY

All tool results are stored in your conversation memory. You can reference
any previous result to inform your next decision. Don't re-run a tool just
because you forgot the output — it's in the history.

## WORKFLOW (adapt, don't follow blindly)

**Recon.** Start with nmap_scan for service discovery. For any web service,
follow with gobuster_scan for directory enumeration and nuclei_scan for
known vulnerabilities. These can run in PARALLEL. Note tech stack, versions,
and anything unusual.

**Exploitation.** Choose techniques based on what recon actually revealed:
- Auth forms or query parameters reaching a DB → sqlmap_get_databases to
  test for SQLi. If confirmed, sqlmap_get_tables then sqlmap_dump_table on
  tables relevant to the engagement goal. Don't dump every table you find.
- Endpoints that look like they shell out → curl_cmd_injection
- File path parameters → curl_lfi_test
- Login forms with no injection surface → hydra_bruteforce

Skip steps that don't apply. A failed exploit attempt is a finding.

**Reporting.** Call submit_report once, at the end, with:
- Confirmed vulnerabilities with evidence
- Credentials or sensitive data recovered
- Severity assessment per finding
- Open ports, tech stack, and databases discovered

## RULES

- Findings must come from real tool output. Never invent data.
- Don't repeat a tool call with identical arguments.
- Treat recovered credentials as sensitive.
- If you encounter production data or out-of-scope hosts, stop and report.
- Destructive actions require explicit authorization.
- You MUST call submit_report before finishing.
"""


# ── Memory ──────────────────────────────────────────────────────────

@dataclass
class ToolMemoryEntry:
    """A single tool execution stored in memory."""
    tool: str
    args: dict
    result: dict
    ok: bool
    findings_count: int
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def summary(self) -> str:
        """One-line summary for quick reference."""
        status = "OK" if self.ok else "FAIL"
        extra = ""
        if self.result.get("databases"):
            extra = f" dbs={self.result['databases']}"
        if self.result.get("credentials_found"):
            extra = f" creds={len(self.result['credentials_found'])}"
        if self.result.get("tables"):
            extra = f" tables={self.result['tables']}"
        return f"[{status}] {self.tool}({json.dumps(self.args, default=str)[:60]}) → {self.findings_count} findings{extra}"


class AgentMemory:
    """Structured memory store for the agent's tool results."""

    def __init__(self) -> None:
        self.entries: list[ToolMemoryEntry] = []
        self.tools_called: dict[str, list[str]] = {}  # tool_name → [serialized_args...]

    def store(self, tool: str, args: dict, result: dict) -> ToolMemoryEntry:
        """Store a tool result and return the memory entry."""
        entry = ToolMemoryEntry(
            tool=tool,
            args=args,
            result=result,
            ok=result.get("ok", False),
            findings_count=len(result.get("findings") or []),
        )
        self.entries.append(entry)

        # Track called args for dedup
        args_key = json.dumps(args, sort_keys=True, default=str)
        self.tools_called.setdefault(tool, []).append(args_key)

        return entry

    def was_called_with(self, tool: str, args: dict) -> bool:
        """Check if this exact tool+args combo was already called."""
        args_key = json.dumps(args, sort_keys=True, default=str)
        return args_key in self.tools_called.get(tool, [])

    def get_results_for(self, tool: str) -> list[ToolMemoryEntry]:
        """Get all results for a specific tool."""
        return [e for e in self.entries if e.tool == tool]

    def snapshot(self) -> str:
        """Human-readable snapshot of all memory for the LLM."""
        if not self.entries:
            return "No tools executed yet."
        lines = [f"## Agent Memory ({len(self.entries)} tool executions)\n"]
        for i, entry in enumerate(self.entries, 1):
            lines.append(f"{i}. {entry.summary()}")
        return "\n".join(lines)

    def all_findings(self) -> list[dict]:
        """Flatten all findings from all tool results."""
        out = []
        for entry in self.entries:
            out.extend(entry.result.get("findings") or [])
        return out

    def clear(self) -> None:
        """Reset memory."""
        self.entries.clear()
        self.tools_called.clear()


# ── Events ──────────────────────────────────────────────────────────

@dataclass
class AgentEvent:
    type: str  # "phase", "tool_start", "tool_done", "chat", "report", "error", "memory"
    data: dict
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class AgentResult:
    target: str
    status: str  # "complete", "partial", "failed"
    vulnerabilities: list[dict] = field(default_factory=list)
    credentials_found: list[dict] = field(default_factory=list)
    databases_found: list[str] = field(default_factory=list)
    dbms: str = ""
    open_ports: list[int] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    tools_run: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    memory_snapshot: str = ""
    events: list[AgentEvent] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "status": self.status,
            "vulnerabilities": self.vulnerabilities,
            "credentials_found": self.credentials_found,
            "databases_found": self.databases_found,
            "dbms": self.dbms,
            "open_ports": self.open_ports,
            "tech_stack": self.tech_stack,
            "risk_score": self.risk_score,
            "tools_run": self.tools_run,
            "duration_seconds": self.duration_seconds,
            "memory_snapshot": self.memory_snapshot,
            "error": self.error,
        }


# ── The Agent ───────────────────────────────────────────────────────

class RedTeamAgent:
    """Single agent with parallel tool execution and memory-based reasoning."""

    def __init__(
        self,
        target: str,
        on_event: Callable[[AgentEvent], Any] | None = None,
    ):
        self.target = target
        self.on_event = on_event
        self.id = str(uuid.uuid4())[:8]
        self.memory = AgentMemory()
        self._start: float = 0
        self._events: list[AgentEvent] = []

    def _emit(self, event_type: str, data: dict) -> None:
        event = AgentEvent(type=event_type, data=data)
        self._events.append(event)
        if self.on_event:
            try:
                result = self.on_event(event)
                if asyncio.iscoroutine(result):
                    asyncio.ensure_future(result)
            except Exception:
                pass

    async def _execute_tool(self, fn_name: str, fn_args: dict) -> dict:
        """Execute a single tool on Kali via MCP and store in memory."""
        mcp_name = _TOOL_MAP.get(fn_name)
        if not mcp_name:
            return {"ok": False, "error": f"Unknown tool: {fn_name}"}

        mcp_args = _map_args(fn_name, fn_args)

        phase = "EXPLOIT" if fn_name.startswith(("sqlmap", "hydra", "curl")) else "RECON"
        self._emit("tool_start", {"tool": fn_name, "phase": phase, "args": fn_args})

        result = await _mcp_call(mcp_name, mcp_args)

        # Store in memory
        entry = self.memory.store(fn_name, fn_args, result)

        ok = result.get("ok", False)
        findings_count = entry.findings_count

        self._emit("tool_done", {
            "tool": fn_name,
            "phase": phase,
            "ok": ok,
            "findings_count": findings_count,
        })

        # Chat summary
        summary = f"**{fn_name}** {'done' if ok else 'failed'} — {findings_count} finding(s)"
        if result.get("databases"):
            summary += f"\n  Databases: {_clean_sqlmap_list(result['databases'])}"
        if result.get("dbms"):
            summary += f"\n  DBMS: {result['dbms']}"
        if result.get("tables"):
            summary += f"\n  Tables: {_clean_sqlmap_list(result['tables'])}"
        if result.get("credentials_found"):
            creds = result["credentials_found"]
            summary += f"\n  **{len(creds)} credential(s) found!**"
            for c in creds[:3]:
                summary += f"\n  → `{c.get('username', '?')}` : `{c.get('password_hash', '?')}`"
        self._emit("chat", {"message": summary})

        # Emit memory update
        self._emit("memory", {"action": "store", "entry": entry.summary()})

        return result

    async def _execute_tools_parallel(self, tool_calls: list[dict]) -> list[tuple[str, dict, dict]]:
        """Execute multiple tool calls concurrently.
        Returns list of (tc_id, fn_name, result) tuples."""

        # Separate submit_report from actual tools
        actual_tools = []
        report_call = None

        for tc in tool_calls:
            fn = tc.get("function", {})
            fn_name = fn.get("name", "")
            tc_id = tc.get("id", "")
            try:
                fn_args = json.loads(fn.get("arguments", "{}"))
            except json.JSONDecodeError:
                fn_args = {}

            if fn_name == "submit_report":
                report_call = (tc_id, fn_name, fn_args)
            else:
                actual_tools.append((tc_id, fn_name, fn_args))

        # Log what we're running in parallel
        tool_names = [t[1] for t in actual_tools]
        if len(tool_names) > 1:
            self._emit("chat", {"message": f"Running **{len(tool_names)} tools in parallel**: {', '.join(tool_names)}"})
        elif len(tool_names) == 1:
            self._emit("chat", {"message": f"Running **{tool_names[0]}**..."})

        # Execute all tools concurrently
        async def _run_one(tc_id: str, fn_name: str, fn_args: dict) -> tuple[str, str, dict]:
            result = await self._execute_tool(fn_name, fn_args)
            return tc_id, fn_name, result

        tasks = [_run_one(tc_id, fn_name, fn_args) for tc_id, fn_name, fn_args in actual_tools]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect results, handle exceptions
        completed = []
        for r in results:
            if isinstance(r, Exception):
                logger.error("[Agent:%s] parallel tool error: %s", self.id, r)
                completed.append(("error", "unknown", {"ok": False, "error": str(r)}))
            else:
                completed.append(r)

        return completed, report_call

    async def run(self) -> AgentResult:
        """Execute the full pentest pipeline with parallel tool execution."""
        self._start = asyncio.get_event_loop().time()
        logger.info("[Agent:%s] starting against %s", self.id, self.target)

        self._emit("phase", {"phase": "STARTING", "target": self.target})
        self._emit("chat", {"message": f"Starting penetration test against **{self.target}**"})

        messages: list[dict] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": (
                f"Target: {self.target}\n"
                f"Scope: {self.target} — all ports, full exploitation authorized.\n\n"
                f"Begin the penetration test."
            )},
        ]

        for iteration in range(MAX_ITERATIONS):
            logger.info("[Agent:%s] iteration %d/%d (memory: %d entries)",
                        self.id, iteration + 1, MAX_ITERATIONS, len(self.memory.entries))

            # Call the LLM
            try:
                response = await _llm_call(messages, TOOL_SCHEMAS)
            except Exception as exc:
                logger.error("[Agent:%s] LLM error: %s", self.id, exc)
                self._emit("error", {"error": f"LLM call failed: {exc}"})
                await asyncio.sleep(2)
                try:
                    response = await _llm_call(messages, TOOL_SCHEMAS)
                except Exception:
                    break

            messages.append(response)

            # If LLM speaks (no tool calls), emit and finish
            tool_calls = response.get("tool_calls") or []
            if not tool_calls:
                content = response.get("content", "")
                if content:
                    self._emit("chat", {"message": content})
                logger.info("[Agent:%s] no tool calls, agent finished", self.id)
                break

            # Execute ALL tool calls in parallel
            completed, report_call = await self._execute_tools_parallel(tool_calls)

            # Append tool results back to messages for the LLM
            for tc_id, fn_name, result in completed:
                compact = _compact_result(result)
                messages.append({"role": "tool", "tool_call_id": tc_id, "content": compact})

            # Handle submit_report if it was in this batch
            if report_call:
                tc_id, fn_name, fn_args = report_call
                self._emit("phase", {"phase": "REPORT"})
                self._emit("chat", {"message": "Generating final report..."})
                messages.append({"role": "tool", "tool_call_id": tc_id, "content": "Report received."})
                return self._build_result(fn_args)

            # Emit memory snapshot after each iteration
            self._emit("memory", {
                "action": "snapshot",
                "total_entries": len(self.memory.entries),
                "tools_run": [e.tool for e in self.memory.entries],
            })

        # Exhausted iterations
        duration = asyncio.get_event_loop().time() - self._start
        logger.warning("[Agent:%s] exhausted %d iterations without report", self.id, MAX_ITERATIONS)
        self._emit("chat", {"message": "Max iterations reached. Compiling report from memory."})

        return AgentResult(
            target=self.target,
            status="partial",
            tools_run=[e.tool for e in self.memory.entries],
            duration_seconds=round(duration, 2),
            memory_snapshot=self.memory.snapshot(),
            events=self._events,
        )

    def _build_result(self, report_data: dict) -> AgentResult:
        duration = asyncio.get_event_loop().time() - self._start
        return AgentResult(
            target=self.target,
            status="complete",
            vulnerabilities=report_data.get("vulnerabilities", []),
            credentials_found=report_data.get("credentials_found", []),
            databases_found=report_data.get("databases_found", []),
            dbms=report_data.get("dbms", ""),
            open_ports=report_data.get("open_ports", []),
            tech_stack=report_data.get("tech_stack", []),
            risk_score=float(report_data.get("risk_score", 0)),
            tools_run=[e.tool for e in self.memory.entries],
            duration_seconds=round(duration, 2),
            memory_snapshot=self.memory.snapshot(),
            events=self._events,
        )

    def reset(self) -> None:
        """Clear all agent state — memory, events, tools."""
        self.memory.clear()
        self._events.clear()
