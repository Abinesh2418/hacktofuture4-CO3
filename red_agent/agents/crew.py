"""Red Team Crew — 3 autonomous agents with PROACTIVE dashboard streaming.

Every agent thought, tool call, and decision is streamed to the frontend
in real-time via WebSocket. The user never has to ask "what's happening."
"""

from __future__ import annotations

import logging
import os

from crewai import Agent, Crew, Task, Process
from crewai import LLM

from red_agent.agents.tools import (
    nmap_scan, nuclei_scan, gobuster_scan, katana_crawl,
    dirsearch_scan, httpx_probe, nuclei_exploit, ffuf_fuzz,
    nmap_vuln_scan, set_active_agent, _broadcast_log, _broadcast_chat,
)

_logger = logging.getLogger(__name__)

# Force litellm to use sync httpx (avoids deadlock inside uvicorn executor)
os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
os.environ["OPENAI_API_BASE"] = ""  # Prevent litellm from picking up wrong base

NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "")


def _get_llm() -> LLM:
    return LLM(
        model="openai/meta/llama-3.1-70b-instruct",
        base_url="https://integrate.api.nvidia.com/v1",
        api_key=NVIDIA_API_KEY,
        temperature=0.3,
    )


# ── Proactive Callbacks — stream agent reasoning to dashboard ──

def _make_step_callback(agent_name: str):
    """Called on EVERY agent step — streams thought/action to chat."""
    def callback(step_output):
        set_active_agent(agent_name)
        try:
            text = str(step_output).encode("ascii", "replace").decode()
            # Limit length and clean up
            if len(text) > 400:
                text = text[:400] + "..."
            _broadcast_chat(f"**[{agent_name}]** {text}")
            _broadcast_log("INFO", f"[{agent_name}] step: {text[:150]}")
        except Exception as e:
            _logger.warning("step_callback error: %s", e)
    return callback


def _make_task_callback(task_name: str):
    """Called when a task completes — streams result summary to chat."""
    def callback(task_output):
        try:
            raw = str(task_output.raw).encode("ascii", "replace").decode()
            if len(raw) > 500:
                raw = raw[:500] + "..."
            _broadcast_chat(f"**{task_name} Complete**\n\n{raw}")
            _broadcast_log("INFO", f"{task_name} finished")
        except Exception as e:
            _logger.warning("task_callback error: %s", e)
    return callback


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
        step_callback=_make_step_callback("Recon Specialist"),
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
        step_callback=_make_step_callback("Security Analyst"),
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
        step_callback=_make_step_callback("Exploit Specialist"),
    )


# ── Task Definitions ──

def create_recon_task(target: str, recon_agent: Agent) -> Task:
    return Task(
        description=(
            f"Perform full reconnaissance on target: {target}\n\n"
            f"1. Run nmap_scan on {target} to discover open ports and services\n"
            f"2. If web ports found (80/443/5000/8080), run httpx_probe\n"
            f"3. Run gobuster_scan to discover directories and hidden files\n"
            f"4. Run nuclei_scan to detect vulnerabilities\n\n"
            f"Report ALL findings."
        ),
        expected_output="Structured recon report: open ports, services, directories, vulnerabilities.",
        agent=recon_agent,
        callback=_make_task_callback("Recon Phase"),
    )


def create_analysis_task(target: str, analyst_agent: Agent) -> Task:
    return Task(
        description=(
            f"Analyze recon results for {target}.\n"
            f"1. Identify critical/high severity findings\n"
            f"2. Map to MITRE ATT&CK\n"
            f"3. Risk level (Critical/High/Medium/Low)\n"
            f"4. Prioritized exploitation plan"
        ),
        expected_output="Risk assessment: ranked vulns, MITRE mapping, risk score, exploitation plan.",
        agent=analyst_agent,
        callback=_make_task_callback("Analysis Phase"),
    )


def create_exploit_task(target: str, exploit_agent: Agent) -> Task:
    return Task(
        description=(
            f"Exploit vulnerabilities in {target} based on analysis.\n"
            f"1. nuclei_exploit to verify critical vulns\n"
            f"2. ffuf_fuzz for hidden params\n"
            f"3. nmap_vuln_scan for service vulns\n"
            f"4. Document all exploits with evidence"
        ),
        expected_output="Exploitation report: confirmed vulns, extracted data, impact, remediation.",
        agent=exploit_agent,
        callback=_make_task_callback("Exploit Phase"),
    )


# ── Crew Factory ──

def create_red_team_crew(target: str) -> Crew:
    recon = create_recon_agent()
    analyst = create_analyst_agent()
    exploit = create_exploit_agent()

    return Crew(
        agents=[recon, analyst, exploit],
        tasks=[
            create_recon_task(target, recon),
            create_analysis_task(target, analyst),
            create_exploit_task(target, exploit),
        ],
        process=Process.sequential,
        verbose=True,
        step_callback=lambda step: _broadcast_log("INFO", f"[Crew] {str(step)[:100]}"),
        task_callback=lambda output: _broadcast_log("INFO", f"[Crew] Task done"),
    )


async def run_crew_mission(target: str) -> dict:
    import asyncio
    import concurrent.futures

    _logger.info("[CrewAI] Starting Red Team crew against %s", target)
    set_active_agent("Recon Specialist")

    def _run_in_clean_thread():
        """Run crew in a completely isolated thread with no parent event loop."""
        set_active_agent("Recon Specialist")
        crew = create_red_team_crew(target)
        return crew.kickoff()

    # Use a dedicated thread pool (not uvicorn's executor) to avoid event loop conflicts
    with concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="crewai") as pool:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(pool, _run_in_clean_thread)

    _logger.info("[CrewAI] Crew finished")

    task_outputs = {}
    for i, task_output in enumerate(result.tasks_output):
        key = ["recon_output", "analysis_output", "exploit_output"][i] if i < 3 else f"task_{i}"
        task_outputs[key] = task_output.raw
    task_outputs["final_output"] = result.raw
    return task_outputs
