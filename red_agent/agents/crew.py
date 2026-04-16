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

from crewai import Agent, Crew, Task, Process
from crewai import LLM

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

# ── LLM Configuration (NVIDIA NIM via OpenAI-compatible API) ──

NVIDIA_API_KEY = os.environ.get(
    "NVIDIA_API_KEY",
    "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",
)


def _get_llm() -> LLM:
    """Create CrewAI LLM instance pointing to NVIDIA NIM via OpenAI-compatible API."""
    return LLM(
        model="openai/meta/llama-3.1-70b-instruct",
        base_url="https://integrate.api.nvidia.com/v1",
        api_key=NVIDIA_API_KEY,
        temperature=0.3,
    )


# ── Agent Definitions ──

def create_recon_agent() -> Agent:
    return Agent(
        role="Reconnaissance Specialist",
        goal="Discover the complete attack surface of the target — open ports, "
             "services, technologies, directories, and potential vulnerabilities.",
        backstory=(
            "You are a senior penetration tester specializing in reconnaissance. "
            "You methodically enumerate targets starting with port scanning, then "
            "web technology fingerprinting, directory discovery, and vulnerability "
            "detection. You always start with nmap, then use web tools if HTTP "
            "services are found."
        ),
        tools=[nmap_scan, httpx_probe, gobuster_scan, nuclei_scan, katana_crawl, dirsearch_scan],
        llm=_get_llm(),
        verbose=True,
        allow_delegation=False,
        max_iter=5,
    )


def create_analyst_agent() -> Agent:
    return Agent(
        role="Security Analyst",
        goal="Analyze reconnaissance data to identify critical vulnerabilities, "
             "assess risk levels, and create a prioritized attack plan.",
        backstory=(
            "You are a cybersecurity analyst who reviews recon data and identifies "
            "the most exploitable weaknesses. You prioritize findings by severity "
            "(critical > high > medium > low) and recommend specific exploitation "
            "techniques. You always produce a structured risk assessment."
        ),
        tools=[],
        llm=_get_llm(),
        verbose=True,
        allow_delegation=False,
    )


def create_exploit_agent() -> Agent:
    return Agent(
        role="Exploitation Specialist",
        goal="Exploit discovered vulnerabilities to demonstrate impact — extract "
             "data, credentials, and prove unauthorized access.",
        backstory=(
            "You are an offensive security expert who turns vulnerability findings "
            "into proven exploits. You verify vulnerabilities using nuclei exploit "
            "templates, fuzz for hidden parameters, and run vulnerability-specific "
            "nmap scripts. You document all evidence of exploitation."
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
            f"Perform full reconnaissance on target: {target}\n\n"
            f"Steps:\n"
            f"1. Run nmap_scan on {target} to discover open ports and services\n"
            f"2. If web ports found (80/443/5000/8080), run httpx_probe\n"
            f"3. Run gobuster_scan to discover directories and hidden files\n"
            f"4. Run nuclei_scan to detect vulnerabilities\n\n"
            f"Report ALL findings: open ports, services, technologies, directories, "
            f"and any vulnerabilities detected."
        ),
        expected_output=(
            "A structured recon report with:\n"
            "- Open ports and services\n"
            "- Web technologies detected\n"
            "- Discovered directories and files\n"
            "- Vulnerability findings from nuclei\n"
            "- Overall attack surface assessment"
        ),
        agent=recon_agent,
    )


def create_analysis_task(target: str, analyst_agent: Agent) -> Task:
    return Task(
        description=(
            f"Analyze the reconnaissance results for {target} from the previous task.\n\n"
            f"1. Identify all critical and high severity findings\n"
            f"2. Map vulnerabilities to MITRE ATT&CK techniques\n"
            f"3. Assess overall risk level (Critical/High/Medium/Low)\n"
            f"4. Recommend top 3-5 exploitation targets in priority order\n"
            f"5. Suggest specific tools and techniques for each exploitation target"
        ),
        expected_output=(
            "A risk assessment report with:\n"
            "- Severity-ranked vulnerability list\n"
            "- MITRE ATT&CK mapping\n"
            "- Risk score (0-10)\n"
            "- Prioritized exploitation plan\n"
            "- Recommended tools per vulnerability"
        ),
        agent=analyst_agent,
    )


def create_exploit_task(target: str, exploit_agent: Agent) -> Task:
    return Task(
        description=(
            f"Exploit the vulnerabilities found in {target} based on the analysis.\n\n"
            f"1. Use nuclei_exploit to verify and exploit critical vulnerabilities\n"
            f"2. Use ffuf_fuzz to discover hidden parameters or endpoints\n"
            f"3. Use nmap_vuln_scan for service-specific vulnerability checks\n"
            f"4. Document all successful exploits with evidence\n\n"
            f"Focus on proving IMPACT — data extraction, unauthorized access, etc."
        ),
        expected_output=(
            "An exploitation report with:\n"
            "- Confirmed vulnerabilities with evidence\n"
            "- Data/credentials extracted (if any)\n"
            "- Proof of exploitation\n"
            "- Impact assessment\n"
            "- Recommendations for remediation"
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

    Sets the active agent name before kickoff so tool wrappers can
    tag their WebSocket events with the correct agent name.
    """
    import asyncio
    from red_agent.agents.tools import set_active_agent

    _logger.info("[CrewAI] Starting Red Team crew against %s", target)

    # Set initial agent
    set_active_agent("Recon Specialist")

    crew = create_red_team_crew(target)

    # CrewAI kickoff is sync — run in executor
    # The agent transitions happen inside CrewAI, we track via tool calls
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
