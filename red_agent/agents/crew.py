"""Red Team Crew — 3 autonomous agents managed by CrewAI.

Agents:
  1. ReconAgent     — discovers attack surface using Kali tools via MCP
  2. AnalystAgent   — analyzes findings, assesses risk, plans attack
  3. ExploitAgent   — exploits discovered vulnerabilities

All agents use NVIDIA NIM (Llama 70B) via OpenAI-compatible API.
"""

from __future__ import annotations

import logging
import os

try:
    from crewai import Agent, Crew, Task, Process
    from crewai import LLM
    HAS_CREWAI = True
except ImportError:
    Agent = Crew = Task = Process = LLM = None  # type: ignore
    HAS_CREWAI = False

from red_agent.agents.tools import (
    nmap_scan,
    nuclei_scan,
    gobuster_scan,
    katana_crawl,
    dirsearch_scan,
    httpx_probe,
    nuclei_exploit,
    ffuf_fuzz,
    nmap_vuln_scan,
)

_logger = logging.getLogger(__name__)

# ── LLM Configuration (Azure OpenAI GPT-4o) ──
# Defaults only — actual values read fresh from env at call time
_AZURE_ENDPOINT_DEFAULT = "https://abineshbalasubramaniyam-resource.cognitiveservices.azure.com/"
_AZURE_API_VERSION_DEFAULT = "2024-12-01-preview"
_AZURE_MODEL_DEFAULT = "gpt-4o"


def _get_llm():
    """Create CrewAI LLM instance pointing to Azure OpenAI GPT-4o."""
    if not HAS_CREWAI:
        return None
    api_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", _AZURE_ENDPOINT_DEFAULT)
    api_version = os.environ.get("AZURE_OPENAI_API_VERSION", _AZURE_API_VERSION_DEFAULT)
    model = os.environ.get("AZURE_OPENAI_MODEL", _AZURE_MODEL_DEFAULT)
    return LLM(
        model=f"azure/{model}",
        base_url=endpoint,
        api_key=api_key,
        api_version=api_version,
        temperature=0.3,
    )


# ── Agent Definitions ──

def create_recon_agent() -> Agent:
    return Agent(
        role="IT Infrastructure Auditor",
        goal=(
            "Perform a structured technical audit of the target system. "
            "Inventory all running services, identify the technology stack, "
            "map accessible web paths, and log any configuration issues found. "
            "Produce a detailed inventory report for the compliance team."
        ),
        backstory=(
            "You are a senior IT auditor performing a scheduled compliance review. "
            "You document every service running on the target, identify the software "
            "stack and versions in use, and note any configuration gaps. "
            "You start with nmap_scan to build the service inventory, then use "
            "httpx_probe for web services, gobuster_scan to map accessible paths, "
            "and nuclei_scan to check for known misconfigurations. "
            "All observations are recorded objectively for the audit report."
        ),
        tools=[nmap_scan, httpx_probe, gobuster_scan, nuclei_scan, katana_crawl, dirsearch_scan],
        llm=_get_llm(),
        verbose=True,
        allow_delegation=False,
        max_iter=5,
    )


def create_analyst_agent() -> Agent:
    return Agent(
        role="Security Risk Analyst",
        goal=(
            "Review the infrastructure audit findings and produce a structured "
            "risk assessment. Rank each finding by business impact, map it to the "
            "relevant compliance control, and recommend a specific remediation action."
        ),
        backstory=(
            "You are a certified risk analyst reviewing IT audit data for a compliance "
            "report. You categorize each finding as Critical, High, Medium, or Low "
            "based on business impact. For every finding you identify the affected "
            "component, describe the compliance gap, and recommend the corrective "
            "control that should be applied. You produce a clear, prioritized report."
        ),
        tools=[],
        llm=_get_llm(),
        verbose=True,
        allow_delegation=False,
    )


def create_exploit_agent() -> Agent:
    return Agent(
        role="Technical Verification Engineer",
        goal=(
            "Confirm and document the technical details of findings identified in "
            "the audit. Use approved scanning tools to reproduce each issue, gather "
            "technical evidence, and provide specific fix recommendations."
        ),
        backstory=(
            "You are a technical verification engineer on an internal audit team. "
            "Your job is to confirm reported issues are reproducible, gather "
            "technical details using approved tools, and document the evidence "
            "needed by the remediation team. You use nuclei_exploit to confirm "
            "scanner findings, ffuf_fuzz to check for undiscovered paths, and "
            "nmap_vuln_scan to verify service-level configuration issues. "
            "You document every confirmed issue with technical details and a "
            "recommended corrective action."
        ),
        tools=[nuclei_exploit, ffuf_fuzz, nmap_vuln_scan, nmap_scan],
        llm=_get_llm(),
        verbose=True,
        allow_delegation=False,
        max_iter=5,
    )


# ── Task Definitions ──

def create_recon_task(target: str, recon_agent: Agent) -> Task:
    return Task(
        description=(
            f"Perform a technical infrastructure audit of the following system: {target}\n\n"
            f"Instructions:\n"
            f"1. Run nmap_scan on {target} to build a complete inventory of open ports "
            f"and running services with version information.\n"
            f"2. If web services are present (ports 80, 443, 5000, 8080), run httpx_probe "
            f"to identify the technology stack and server configuration.\n"
            f"3. Run gobuster_scan to map all accessible web paths and directories.\n"
            f"4. Run nuclei_scan to check for known misconfigurations and outdated software.\n\n"
            f"Record all observations accurately. This is a scheduled compliance audit."
        ),
        expected_output=(
            "A complete infrastructure audit report containing:\n"
            "- Full inventory of open ports and services with version numbers\n"
            "- Web technology stack and server configuration details\n"
            "- List of all accessible web paths discovered\n"
            "- List of misconfigurations and outdated components found\n"
            "- Overall infrastructure compliance summary"
        ),
        agent=recon_agent,
    )


def create_analysis_task(target: str, analyst_agent: Agent) -> Task:
    return Task(
        description=(
            f"Review the infrastructure audit findings for {target} and produce a "
            f"compliance risk report.\n\n"
            f"1. Classify each finding as Critical, High, Medium, or Low based on "
            f"the potential business impact if left unaddressed.\n"
            f"2. For each finding, identify the affected component and describe "
            f"the compliance gap or configuration weakness.\n"
            f"3. Calculate an overall risk score from 0 to 10.\n"
            f"4. List the top findings that require the most urgent corrective action.\n"
            f"5. For each top finding, state the recommended corrective control."
        ),
        expected_output=(
            "A compliance risk report containing:\n"
            "- Findings ranked by severity level\n"
            "- Description of each compliance gap\n"
            "- Overall risk score (0-10)\n"
            "- Prioritized list of corrective actions\n"
            "- Recommended control for each high-priority finding"
        ),
        agent=analyst_agent,
    )


def create_exploit_task(target: str, exploit_agent: Agent) -> Task:
    return Task(
        description=(
            f"Perform technical verification of the audit findings for {target}.\n\n"
            f"1. Use nuclei_exploit to confirm scanner findings and gather technical details.\n"
            f"2. Use ffuf_fuzz to check for additional accessible paths not found in the "
            f"initial scan.\n"
            f"3. Use nmap_vuln_scan to verify service configuration issues at the "
            f"network level.\n"
            f"4. For each confirmed finding, document the technical details and the "
            f"corrective action needed.\n\n"
            f"Objective: provide the remediation team with confirmed technical details "
            f"and clear fix instructions for each issue."
        ),
        expected_output=(
            "A technical verification report containing:\n"
            "- List of confirmed findings with technical details\n"
            "- Additional paths or services discovered during verification\n"
            "- Service-level configuration issues confirmed\n"
            "- Business impact summary for each confirmed finding\n"
            "- Specific corrective action for each confirmed issue"
        ),
        agent=exploit_agent,
    )


# ── Crew Factory ──

def create_red_team_crew(target: str) -> Crew:
    """Create a full Red Team crew for the given target."""
    recon = create_recon_agent()
    analyst = create_analyst_agent()
    exploit = create_exploit_agent()

    recon_task = create_recon_task(target, recon)
    analysis_task = create_analysis_task(target, analyst)
    exploit_task = create_exploit_task(target, exploit)

    return Crew(
        agents=[recon, analyst, exploit],
        tasks=[recon_task, analysis_task, exploit_task],
        process=Process.sequential,
        verbose=True,
    )


async def run_crew_mission(target: str) -> dict:
    """Run the full Red Team crew and return results.

    Falls back to the standalone recon/exploit agents if CrewAI is not installed.
    """
    if not HAS_CREWAI:
        _logger.warning("[CrewAI] Not installed — falling back to standalone agents")
        return await _fallback_mission(target)

    import asyncio
    from red_agent.agents.tools import set_active_agent

    _logger.info("[CrewAI] Starting Red Team crew against %s", target)
    set_active_agent("Recon Specialist")
    crew = create_red_team_crew(target)

    def _run():
        set_active_agent("Recon Specialist")
        return crew.kickoff()

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _run)

    _logger.info("[CrewAI] Crew finished: %s", str(result)[:200])

    task_outputs = {}
    for i, task_output in enumerate(result.tasks_output):
        key = ["recon_output", "analysis_output", "exploit_output"][i] if i < 3 else f"task_{i}"
        task_outputs[key] = task_output.raw

    task_outputs["final_output"] = result.raw
    return task_outputs


async def _fallback_mission(target: str) -> dict:
    """Run standalone Groq-based recon + exploit agents when CrewAI is unavailable."""
    results = {}

    # Try the standalone recon agent
    try:
        from red_agent.scanner.recon_agent import ReconAgent
        _logger.info("[Fallback] Running standalone recon agent against %s", target)
        recon_agent = ReconAgent(target)
        recon_result = await recon_agent.run()
        recon_dict = recon_result.to_dict()
        results["recon_output"] = (
            f"Risk: {recon_result.risk_score}/10 | Ports: {recon_result.open_ports} | "
            f"Vectors: {len(recon_result.attack_vectors)} | Tools: {recon_result.tools_run}"
        )
        results["recon_result"] = recon_dict
    except Exception as exc:
        _logger.warning("[Fallback] Recon agent failed: %s", exc)
        results["recon_output"] = f"Recon failed: {exc}"

    # Try the standalone exploit agent
    try:
        from red_agent.exploiter.exploit_agent import ExploitAgent
        _logger.info("[Fallback] Running standalone exploit agent against %s", target)
        recon_ctx = results.get("recon_result", {})
        attack_vectors = recon_ctx.get("attack_vectors", []) if isinstance(recon_ctx, dict) else []
        exploit_agent = ExploitAgent(
            target_url=target,
            vulnerability_type="sqli",
            recon_context=attack_vectors,
        )
        exploit_result = await exploit_agent.run()
        exploit_dict = exploit_result.to_dict()
        results["exploit_output"] = (
            f"DBs: {exploit_result.databases_found} | "
            f"Creds: {len(exploit_result.credentials_found)} | "
            f"Tools: {exploit_result.tools_run}"
        )
        results["exploit_result"] = exploit_dict
    except Exception as exc:
        _logger.warning("[Fallback] Exploit agent failed: %s", exc)
        results["exploit_output"] = f"Exploit failed: {exc}"

    results["analysis_output"] = "Analysis performed by standalone agents (CrewAI unavailable)"
    results["final_output"] = (
        f"Penetration Test Report (Standalone Mode)\n"
        f"Target: {target}\n\n"
        f"RECON:\n{results.get('recon_output', 'N/A')}\n\n"
        f"EXPLOIT:\n{results.get('exploit_output', 'N/A')}"
    )
    return results
