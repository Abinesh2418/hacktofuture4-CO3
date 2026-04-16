"""Autonomous Red Team Recon Agent — Groq function-calling agent loop.

Architecture (same pattern as PentAGI)
--------------------------------------
1. Fetch CVE intel (NVD) if context warrants it.
2. Agent loop (Groq SDK with function calling):
   - LLM receives target + CVE context
   - LLM DECIDES which tool to call (not hardcoded)
   - Tool executes, result fed back to LLM
   - LLM decides next tool or produces final assessment
   - Max 4 iterations to stay within free-tier token budget
3. Incremental updates pushed to session store (live polling).
4. Final ReconResult published via EventBus → Blue Agent notified.

The LLM is the BRAIN — it picks tools based on what it discovers.
E.g., if a CVE targets Apache, the LLM will run nmap first, see Apache
is running, then run nuclei with relevant templates. It won't waste time
on gobuster if the CVE is about SSH.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv

from core.event_bus import event_bus
from red_agent.scanner.cve_fetcher import CVEFetcher

load_dotenv()
logger = logging.getLogger(__name__)

MAX_AGENT_ITERATIONS = int(os.getenv("MAX_AGENT_ITERATIONS", "5"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_session_id() -> str:
    return datetime.now(timezone.utc).strftime("recon_%Y%m%d_%H%M%S_%f")


def _host_only(target: str) -> str:
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target.split("/", 1)[0]


# ---------- Result dataclass ------------------------------------------------

@dataclass
class ReconResult:
    session_id: str
    target: str
    context: str
    status: str
    cves_fetched: int
    attack_vectors: list[dict]
    tech_stack: list[str]
    open_ports: list[int]
    risk_score: float
    recommended_exploits: list[str]
    raw_crew_output: str
    duration_seconds: float
    tools_run: list[str] = field(default_factory=list)
    error: Optional[str] = None
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------- Tool registry for function calling ------------------------------

def _find_wordlist() -> str | None:
    """Find the best available wordlist — prefer Kali native ones."""
    candidates = [
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",  # Kali (23k words)
        "/usr/share/wordlists/dirb/common.txt",                          # Kali (4.6k words)
        "/usr/share/seclists/Discovery/Web-Content/common.txt",          # SecLists
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "wordlists", "common.txt",
        ),  # project-local fallback
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


_WORDLIST_PATH = _find_wordlist()


def _get_available_tools() -> list[str]:
    """Return names of Arsenal tools that are actually installed."""
    import shutil
    available = []
    try:
        from red_agent.red_arsenal.config import TOOLS
        for name in ("nmap", "nuclei", "katana", "gobuster", "gau", "ffuf"):
            if TOOLS.get(name) and TOOLS[name].installed:
                available.append(name)
    except Exception:
        pass
    # sqlmap is not in red_arsenal config but is standard on Kali
    if shutil.which("sqlmap"):
        available.append("sqlmap")
    return available


# Groq function-calling tool schemas
def _build_tool_schemas(available: list[str]) -> list[dict]:
    all_schemas = {
        "nmap_scan": {
            "type": "function",
            "function": {
                "name": "nmap_scan",
                "description": "Run nmap service/version scan. Use FIRST to discover open ports and services. Input: hostname or IP (no http://).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Hostname or IP to scan"},
                        "ports": {"type": "string", "description": "Port range, e.g. '22,80,443,8080,8888' or '1-1000'", "default": "22,80,443,3306,5432,8000,8080,8443,8888,9090"},
                    },
                    "required": ["target"],
                },
            },
        },
        "nuclei_scan": {
            "type": "function",
            "function": {
                "name": "nuclei_scan",
                "description": "Run nuclei vulnerability scanner with 4000+ templates. Use after nmap finds a web service. Detects CVEs, misconfigs, exposed panels.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Full URL, e.g. http://192.168.1.1:8080"},
                        "severity": {"type": "string", "description": "Severity filter", "default": "critical,high"},
                    },
                    "required": ["target"],
                },
            },
        },
        "gobuster_scan": {
            "type": "function",
            "function": {
                "name": "gobuster_scan",
                "description": "Brute-force directories and files on a web server. Use when port 80/443/8080 is open.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Full URL with port"},
                    },
                    "required": ["target"],
                },
            },
        },
        "ffuf_scan": {
            "type": "function",
            "function": {
                "name": "ffuf_scan",
                "description": "Fast web fuzzer for hidden endpoints and parameters. Use on web servers.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Base URL"},
                    },
                    "required": ["target"],
                },
            },
        },
        "katana_crawl": {
            "type": "function",
            "function": {
                "name": "katana_crawl",
                "description": "Headless web crawler. Discovers JS endpoints, forms, and site structure.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "URL to crawl"},
                    },
                    "required": ["target"],
                },
            },
        },
        "gau_scan": {
            "type": "function",
            "function": {
                "name": "gau_scan",
                "description": "Fetch historical URLs from Wayback Machine and OTX. Use for passive recon on domains.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Domain name"},
                    },
                    "required": ["target"],
                },
            },
        },
        "sqlmap_scan": {
            "type": "function",
            "function": {
                "name": "sqlmap_scan",
                "description": "Test a URL for SQL injection vulnerabilities. Use when you find a login page, form, or URL with parameters (e.g. ?id=1). Automatically detects SQLi, extracts DB info.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "URL with parameter to test, e.g. http://target/login.php or http://target/page?id=1"},
                        "forms": {"type": "boolean", "description": "Auto-detect and test HTML forms (login pages)", "default": True},
                    },
                    "required": ["target"],
                },
            },
        },
        "submit_assessment": {
            "type": "function",
            "function": {
                "name": "submit_assessment",
                "description": "Submit your final security assessment. Call this when you have enough data OR after using 3 tools.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "attack_vectors": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "path": {"type": "string"},
                                    "type": {"type": "string"},
                                    "priority": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                                    "evidence": {"type": "string"},
                                    "mitre_technique": {"type": "string"},
                                    "recommended_tool": {"type": "string"},
                                },
                            },
                        },
                        "tech_stack": {"type": "array", "items": {"type": "string"}},
                        "open_ports": {"type": "array", "items": {"type": "integer"}},
                        "risk_score": {"type": "number"},
                        "recommended_exploits": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["attack_vectors", "tech_stack", "open_ports", "risk_score"],
                },
            },
        },
    }

    # Tool name mapping: schema name → arsenal name
    tool_map = {
        "nmap_scan": "nmap", "nuclei_scan": "nuclei", "katana_crawl": "katana",
        "gobuster_scan": "gobuster", "gau_scan": "gau", "ffuf_scan": "ffuf",
        "sqlmap_scan": "sqlmap",
    }

    schemas = []
    for schema_name, schema in all_schemas.items():
        arsenal_name = tool_map.get(schema_name)
        if arsenal_name is None or arsenal_name in available:
            schemas.append(schema)
    return schemas


# ---------- Tool execution --------------------------------------------------

async def _run_arsenal_tool(name: str, args: dict, timeout: float) -> dict:
    """Execute a single Arsenal tool and return its parsed result."""
    try:
        from red_agent.red_arsenal.config import TOOLS
        from red_agent.red_arsenal.tools import api as api_tools
        from red_agent.red_arsenal.tools import recon as recon_tools
        from red_agent.red_arsenal.runner import run as run_cmd
        from red_agent.red_arsenal import parsers

        target = args.get("target", "")
        wordlist = _WORDLIST_PATH if os.path.isfile(_WORDLIST_PATH) else None

        if name == "nmap_scan":
            host = _host_only(target)
            ports = args.get("ports", "22,80,443,3306,5432,8000,8080,8443,8888,9090")
            result = await asyncio.wait_for(
                recon_tools.nmap_impl(host, scan_type="-sV -sC -Pn", ports=ports),
                timeout=timeout,
            )
            findings = result.get("findings") or []
            result["findings"] = [f for f in findings if isinstance(f, dict) and f.get("state") == "open"]
            return result

        elif name == "nuclei_scan":
            severity = args.get("severity", "critical,high")
            return await asyncio.wait_for(
                recon_tools.nuclei_impl(target, severity=severity),
                timeout=timeout,
            )

        elif name == "gobuster_scan":
            if wordlist:
                binary = TOOLS["gobuster"].resolve()
                cmd = [binary, "dir", "-u", target, "-w", wordlist, "-x", "php,html,js,txt,py,asp,aspx,jsp", "-q", "--no-error"]
                raw = await asyncio.wait_for(run_cmd(cmd, timeout=TOOLS["gobuster"].default_timeout), timeout=timeout)
                return parsers.parse_gobuster(raw, target)
            return await asyncio.wait_for(recon_tools.gobuster_impl(target), timeout=timeout)

        elif name == "ffuf_scan":
            if wordlist:
                import tempfile
                binary = TOOLS["ffuf"].resolve()
                tmpf = tempfile.NamedTemporaryFile(prefix="ffuf-", suffix=".json", delete=False)
                tmpf.close()
                fuzz_url = target.rstrip("/") + "/FUZZ"
                cmd = [binary, "-u", fuzz_url, "-w", wordlist, "-of", "json", "-o", tmpf.name,
                       "-mc", "200,204,301,302,307,401,403", "-s"]
                raw = await asyncio.wait_for(run_cmd(cmd, timeout=TOOLS["ffuf"].default_timeout), timeout=timeout)
                try:
                    with open(tmpf.name) as f:
                        data = json.load(f)
                    parsed = parsers._base("ffuf", target, raw)
                    for row in data.get("results") or []:
                        parsed["findings"].append({"url": row.get("url"), "status": row.get("status"), "length": row.get("length")})
                    return parsed
                except Exception:
                    return parsers.parse_ffuf(raw, target)
                finally:
                    os.unlink(tmpf.name)
            return await asyncio.wait_for(api_tools.ffuf_impl(target), timeout=timeout)

        elif name == "katana_crawl":
            return await asyncio.wait_for(recon_tools.katana_impl(target), timeout=timeout)

        elif name == "gau_scan":
            host = _host_only(target)
            return await asyncio.wait_for(recon_tools.gau_impl(host), timeout=timeout)

        elif name == "sqlmap_scan":
            return await asyncio.wait_for(
                _run_sqlmap(target, args.get("forms", True), run_cmd),
                timeout=timeout,
            )

        else:
            return {"tool": name, "ok": False, "error": f"unknown tool {name}", "findings": []}

    except asyncio.TimeoutError:
        return {"tool": name, "ok": False, "error": f"timeout after {timeout}s", "findings": []}
    except asyncio.CancelledError:
        return {"tool": name, "ok": False, "error": "cancelled", "findings": []}
    except Exception as exc:
        return {"tool": name, "ok": False, "error": f"{type(exc).__name__}: {str(exc)[:150]}", "findings": []}


async def _run_sqlmap(target: str, forms: bool, run_cmd) -> dict:
    """Run sqlmap in detection mode — finds SQLi without exploiting."""
    import shutil
    binary = shutil.which("sqlmap")
    if not binary:
        return {"tool": "sqlmap", "ok": False, "error": "sqlmap not installed", "findings": []}

    cmd = [
        binary, "-u", target,
        "--batch",
        "--level=2",
        "--risk=2",
        "--smart",
        "--output-dir=/tmp/sqlmap-output",
    ]
    if forms:
        cmd.append("--forms")
    cmd.extend(["--threads=4", "--timeout=30"])

    raw = await run_cmd(cmd, timeout=180)
    text = raw.text_out()

    findings: list[dict] = []
    injectable = False
    current_param = ""

    for line in text.splitlines():
        line = line.strip()
        if "is vulnerable" in line.lower() or "injectable" in line.lower():
            injectable = True
            findings.append({
                "type": "sqli_confirmed",
                "evidence": line[:200],
                "vulnerable": True,
            })
        elif "Parameter:" in line:
            current_param = line.split("Parameter:")[-1].strip()
        elif "Type:" in line and current_param:
            sqli_type = line.split("Type:")[-1].strip()
            findings.append({
                "type": "sqli_detail",
                "parameter": current_param,
                "sqli_type": sqli_type,
            })
        elif "back-end DBMS" in line.lower():
            findings.append({
                "type": "dbms_detected",
                "evidence": line[:150],
            })
        elif "available databases" in line.lower() or "[*]" in line:
            if line.startswith("[*]"):
                findings.append({"type": "database", "name": line.replace("[*]", "").strip()})

    return {
        "tool": "sqlmap",
        "target": target,
        "ok": raw.ok or injectable,
        "duration_s": raw.duration_s,
        "findings": findings,
        "raw_tail": text[-500:] if text else "",
        "error": None if (raw.ok or injectable) else raw.text_err()[-200:],
    }


def _compact_tool_result(result: dict) -> str:
    """Compact a tool result for the LLM context — keep under 300 chars."""
    findings = result.get("findings") or []
    summary = {
        "tool": result.get("tool"),
        "ok": result.get("ok"),
        "count": len(findings),
        "findings": findings[:8],
    }
    err = result.get("error")
    if err:
        summary["error"] = str(err)[:80]
    text = json.dumps(summary, default=str)
    return text[:400]


# ---------- Agent system prompt ---------------------------------------------

_AGENT_SYSTEM_PROMPT = """You are an autonomous Red Team Recon Agent. Your job is to discover attack surfaces on the given target.

WORKFLOW:
1. Always start with nmap_scan to discover open ports and services.
2. If web server found (port 80/443/5000/8080/8888):
   - Run gobuster_scan to discover pages and directories
   - If login page or forms found → run sqlmap_scan to test for SQL injection
   - Run nuclei_scan LAST — it benefits from knowing discovered endpoints
3. If only SSH found → skip web tools, submit assessment.
4. After running 3-4 tools total, call submit_assessment.

TOOL ORDER (important):
  nmap → gobuster/ffuf (find pages) → sqlmap (test forms) → nuclei (LAST)
  Nuclei should always be the LAST tool you call.

IMPORTANT for SQL injection targets:
- If context mentions SQL injection, your priority is: nmap → gobuster (find /login) → sqlmap (test it)
- sqlmap will automatically detect injectable parameters and report the DBMS type
- Report each SQLi finding as a critical attack_vector with mitre_technique T1190

RULES:
- NEVER call the same tool twice.
- If a tool returns an error or "unavailable", skip it and try another.
- Base your assessment ONLY on real tool output. Never invent findings.
- Call submit_assessment when you have enough data OR after 3 tool calls.
- Every attack_vector MUST have a non-empty mitre_technique and recommended_tool.
- If no real vulnerabilities found, submit empty attack_vectors with risk_score 0.0.
"""


# ---------- Main agent with function-calling loop ---------------------------

class ReconAgent:
    """Groq function-calling agent — LLM decides which tools to run."""

    def __init__(self, target: str, context: str | None = None) -> None:
        self.target = target
        self.context = context or "general security assessment"
        self.session_id = generate_session_id()
        self.fetcher = CVEFetcher()
        self._start_monotonic: float | None = None
        self._tool_timeout = float(os.getenv("RECON_TOOL_TIMEOUT", "180"))

    async def run(self) -> ReconResult:
        self._start_monotonic = asyncio.get_event_loop().time()
        logger.info("[ReconAgent:%s] starting on %s", self.session_id, self.target)

        await event_bus.publish(
            "recon.started",
            {"session_id": self.session_id, "target": self.target, "timestamp": utc_now()},
        )

        cves: list[dict] = []
        tool_outputs: list[dict] = []
        try:
            cves = await self._fetch_intel()
            assessment, tool_outputs = await self._agent_loop(cves)

            result = self._build_result(assessment, cves, tool_outputs, "complete")

            await event_bus.publish("recon.complete", result.to_dict())
            await self._notify_blue_agent(result)

            logger.info(
                "[ReconAgent:%s] complete tools=%s vectors=%d risk=%s",
                self.session_id, result.tools_run,
                len(result.attack_vectors), result.risk_score,
            )
            return result

        except Exception as exc:
            logger.exception("[ReconAgent:%s] failed", self.session_id)
            await event_bus.publish(
                "recon.failed", {"session_id": self.session_id, "error": str(exc)},
            )
            return self._build_result("{}", cves, tool_outputs, "failed", error=str(exc))

    async def _fetch_intel(self) -> list[dict]:
        if not self.fetcher._is_cve_context(self.context):
            logger.info("[ReconAgent:%s] general recon mode", self.session_id)
            return []

        logger.info("[ReconAgent:%s] fetching NVD CVEs", self.session_id)
        cves = await self.fetcher.fetch_recent()
        logger.info("[ReconAgent:%s] %d CVEs fetched", self.session_id, len(cves))
        await event_bus.publish(
            "recon.cve_fetched",
            {"session_id": self.session_id, "cve_count": len(cves), "cves": cves},
        )
        return cves

    async def _agent_loop(self, cves: list[dict]) -> tuple[str, list[dict]]:
        """Core agent loop: LLM decides tools via function calling."""
        from groq import AsyncGroq

        available_tools = _get_available_tools()
        tool_schemas = _build_tool_schemas(available_tools)

        logger.info(
            "[ReconAgent:%s] available tools: %s",
            self.session_id, available_tools,
        )

        cve_context = ""
        if cves:
            cve_context = f"\n\nCVE Intelligence:\n{json.dumps(cves[:5], indent=2)}"

        messages = [
            {"role": "system", "content": _AGENT_SYSTEM_PROMPT},
            {"role": "user", "content": (
                f"Target: {self.target}\n"
                f"Context: {self.context}\n"
                f"Available tools: {', '.join(available_tools)}"
                f"{cve_context}"
            )},
        ]

        model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
        if model.startswith("groq/"):
            model = model.split("/", 1)[1]

        client = AsyncGroq(api_key=os.getenv("GROQ_API_KEY"), timeout=60.0)
        tool_outputs: list[dict] = []
        tools_called: set[str] = set()
        final_assessment = "{}"

        for iteration in range(MAX_AGENT_ITERATIONS):
            logger.info(
                "[ReconAgent:%s] agent iteration %d/%d",
                self.session_id, iteration + 1, MAX_AGENT_ITERATIONS,
            )

            resp = await client.chat.completions.create(
                model=model,
                temperature=0,
                max_tokens=2048,
                messages=messages,
                tools=tool_schemas,
                tool_choice="auto",
            )

            choice = resp.choices[0]
            message = choice.message

            # Add assistant message to history
            messages.append(message.model_dump(exclude_none=True))

            # No tool calls → LLM is done, extract final text
            if not message.tool_calls:
                logger.info("[ReconAgent:%s] agent finished (no more tool calls)", self.session_id)
                final_assessment = message.content or "{}"
                break

            # Process each tool call
            for tool_call in message.tool_calls:
                fn_name = tool_call.function.name
                try:
                    fn_args = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError:
                    fn_args = {}

                logger.info(
                    "[ReconAgent:%s] LLM decided: %s(%s)",
                    self.session_id, fn_name, json.dumps(fn_args)[:100],
                )

                # Handle submit_assessment (final answer)
                if fn_name == "submit_assessment":
                    logger.info("[ReconAgent:%s] agent submitted assessment", self.session_id)
                    final_assessment = json.dumps(fn_args)
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": "Assessment received.",
                    })
                    return final_assessment, tool_outputs

                # Prevent duplicate tool calls
                if fn_name in tools_called:
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": f"Already called {fn_name}. Pick a different tool or call submit_assessment.",
                    })
                    continue

                tools_called.add(fn_name)

                # Execute the tool
                result = await _run_arsenal_tool(fn_name, fn_args, self._tool_timeout)
                tool_outputs.append(result)

                tool_name = result.get("tool") or fn_name
                findings_count = len(result.get("findings") or [])
                logger.info(
                    "[ReconAgent:%s] tool=%s ok=%s findings=%d",
                    self.session_id, tool_name, result.get("ok"), findings_count,
                )

                await event_bus.publish(
                    "recon.tool_done",
                    {
                        "session_id": self.session_id,
                        "tool": tool_name,
                        "ok": result.get("ok"),
                        "finding_count": findings_count,
                    },
                )

                # Update session with partial results
                self._update_session_partial(tool_outputs)

                # Feed result back to LLM
                compact = _compact_tool_result(result)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": compact,
                })

        return final_assessment, tool_outputs

    def _update_session_partial(self, tool_outputs: list[dict]) -> None:
        duration = (
            asyncio.get_event_loop().time() - self._start_monotonic
            if self._start_monotonic is not None
            else 0.0
        )

        open_ports: list[int] = []
        tech_stack: list[str] = []
        tools_run: list[str] = []
        all_findings_count = 0

        for out in tool_outputs:
            tools_run.append(out.get("tool") or "unknown")
            for f in out.get("findings") or []:
                if not isinstance(f, dict):
                    continue
                all_findings_count += 1
                if f.get("state") == "open" and f.get("port"):
                    try:
                        open_ports.append(int(f["port"]))
                    except (TypeError, ValueError):
                        pass
                    svc = " ".join(filter(None, [f.get("product"), f.get("version")]))
                    if svc and svc not in tech_stack:
                        tech_stack.append(svc)

        partial = ReconResult(
            session_id=self.session_id,
            target=self.target,
            context=self.context,
            status="running",
            cves_fetched=0,
            attack_vectors=[],
            tech_stack=tech_stack,
            open_ports=open_ports,
            risk_score=0.0,
            recommended_exploits=[],
            raw_crew_output=f"Agent thinking... {all_findings_count} findings from {len(tools_run)} tools",
            duration_seconds=round(duration, 2),
            tools_run=tools_run,
        )
        _sessions[self.session_id] = partial

    def _build_result(
        self, assessment: str, cves: list[dict],
        tool_outputs: list[dict], status: str, error: str | None = None,
    ) -> ReconResult:
        duration = (
            asyncio.get_event_loop().time() - self._start_monotonic
            if self._start_monotonic is not None
            else 0.0
        )
        intelligence = self._extract_json(assessment)

        raw_vectors = intelligence.get("attack_vectors", []) or []
        vectors = [
            v for v in raw_vectors
            if isinstance(v, dict) and any(str(x).strip() for x in v.values())
        ]

        raw_ports = intelligence.get("open_ports", []) or []
        ports: list[int] = []
        for p in raw_ports:
            try:
                ports.append(int(p))
            except (TypeError, ValueError):
                continue

        tools_run = [out.get("tool") or "unknown" for out in tool_outputs]

        return ReconResult(
            session_id=self.session_id,
            target=self.target,
            context=self.context,
            status=status,
            cves_fetched=len(cves),
            attack_vectors=vectors,
            tech_stack=intelligence.get("tech_stack", []) or [],
            open_ports=ports,
            risk_score=float(intelligence.get("risk_score", 0.0) or 0.0),
            recommended_exploits=intelligence.get("recommended_exploits", []) or [],
            raw_crew_output=(assessment or "")[:1500],
            duration_seconds=round(duration, 2),
            tools_run=tools_run,
            error=error,
        )

    def _extract_json(self, text: str) -> dict:
        if not text:
            return {}
        try:
            return json.loads(text)
        except Exception:
            pass
        try:
            cleaned = text.replace("```json", "").replace("```", "").strip()
            return json.loads(cleaned)
        except Exception:
            pass
        try:
            start = text.find("{")
            end = text.rfind("}") + 1
            if 0 <= start < end:
                return json.loads(text[start:end])
        except Exception:
            pass
        logger.warning("[ReconAgent:%s] could not parse assessment as JSON", self.session_id)
        return {}

    async def _notify_blue_agent(self, result: ReconResult) -> None:
        blue_port = os.getenv("BLUE_AGENT_PORT", "8002")
        url = f"http://localhost:{blue_port}/defense/threat-intel"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(url, json=result.to_dict())
            logger.info("[ReconAgent:%s] blue agent notified", self.session_id)
        except Exception as exc:
            logger.warning("[ReconAgent:%s] blue notify failed: %s", self.session_id, exc)


# ---------- In-memory session store -----------------------------------------

_sessions: dict[str, ReconResult | None] = {}


async def run_recon_session(target: str, context: str | None = None) -> str:
    agent = ReconAgent(target, context)
    session_id = agent.session_id
    _sessions[session_id] = None

    async def _runner() -> None:
        try:
            result = await agent.run()
        except Exception as exc:
            logger.exception("[run_recon_session] runner crashed")
            result = ReconResult(
                session_id=session_id, target=target, context=context or "",
                status="failed", cves_fetched=0, attack_vectors=[], tech_stack=[],
                open_ports=[], risk_score=0.0, recommended_exploits=[],
                raw_crew_output="", duration_seconds=0.0, tools_run=[], error=str(exc),
            )
        _sessions[session_id] = result

    asyncio.create_task(_runner())
    return session_id


def get_session_result(session_id: str) -> ReconResult | None:
    return _sessions.get(session_id)


def has_session(session_id: str) -> bool:
    return session_id in _sessions


def list_sessions() -> list[dict]:
    out: list[dict] = []
    for sid, r in _sessions.items():
        if r is None:
            out.append({"session_id": sid, "status": "running", "target": None, "risk_score": 0.0})
        else:
            out.append({"session_id": sid, "status": r.status, "target": r.target, "risk_score": r.risk_score})
    return out
