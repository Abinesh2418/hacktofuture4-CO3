"""Tests for the autonomous Red Team recon agent.

All external dependencies (NVD, CrewAI, the arsenal impls, the Blue agent
HTTP endpoint) are mocked so these tests are hermetic and fast.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from red_agent.scanner.cve_fetcher import CVEFetcher
from red_agent.scanner.recon_agent import ReconAgent, ReconResult


# ---------- helpers ---------------------------------------------------------

def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture
def fresh_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        yield loop
    finally:
        loop.close()


# ---------- 1. CVE fetcher structure ----------------------------------------

def test_cve_fetcher_returns_structured(fresh_loop):
    fake_payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-12345",
                    "descriptions": [
                        {"lang": "en", "value": "X" * 400}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8}}
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "criteria": (
                                                "cpe:2.3:a:apache:httpd:2.4.49:*:*:*"
                                            )
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }

    fake_resp = SimpleNamespace(status_code=200, json=lambda: fake_payload)

    class _DummyClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, params=None):
            return fake_resp

    with patch("red_agent.scanner.cve_fetcher.httpx.AsyncClient", _DummyClient):
        fetcher = CVEFetcher()
        result = fresh_loop.run_until_complete(fetcher.fetch_recent())

    assert len(result) == 1
    item = result[0]
    assert item["id"] == "CVE-2024-12345"
    assert len(item["description"]) <= 150
    assert item["cvss_score"] == 9.8
    assert any("apache" in p for p in item["affected_products"])


# ---------- 2. CVE context detection ----------------------------------------

def test_cve_context_detection():
    fetcher = CVEFetcher()
    assert fetcher._is_cve_context("CVE-2024-1234 dropped") is True
    assert fetcher._is_cve_context("scan this website") is False
    assert fetcher._is_cve_context("critical rce in apache") is True
    assert fetcher._is_cve_context(None) is False
    assert fetcher._is_cve_context("") is False


# ---------- 3. Arsenal tool wrapper calls underlying impl -------------------

def test_arsenal_tool_calls_existing_impl(fresh_loop):
    from red_agent.scanner import arsenal_tools

    fake_result = {
        "tool": "nmap",
        "ok": True,
        "duration_s": 1.23,
        "findings": [{"port": 80, "service": "http"}],
        "error": None,
    }

    async def fake_nmap_impl(target, *a, **kw):
        # nmap_scan strips the URL scheme before invoking the impl
        assert target == "target.com"
        return fake_result

    fake_recon = SimpleNamespace(nmap_impl=fake_nmap_impl)
    fake_api = SimpleNamespace()

    # When crewai is installed, @tool returns a Tool object — call the
    # underlying callable via .func. When it isn't, the fallback decorator
    # leaves the plain function in place.
    nmap_callable = getattr(arsenal_tools.nmap_scan, "func", arsenal_tools.nmap_scan)

    with patch.object(
        arsenal_tools, "_load_impls", return_value=(fake_recon, fake_api)
    ):
        out = nmap_callable("http://target.com")

    assert isinstance(out, str)
    assert len(out) <= arsenal_tools.MAX_TOOL_OUTPUT_CHARS
    assert "nmap" in out
    assert '"count"' in out


# ---------- 4. ReconAgent.run() returns ReconResult -------------------------

def test_recon_agent_run_returns_result(fresh_loop):
    agent = ReconAgent("http://localhost", "general scan")

    json_payload = json.dumps(
        {
            "attack_vectors": [
                {
                    "path": "/",
                    "type": "info",
                    "priority": "low",
                    "evidence": "open",
                    "mitre_technique": "T1595",
                    "recommended_tool": "nmap",
                }
            ],
            "tech_stack": ["nginx"],
            "open_ports": [80],
            "waf_detected": False,
            "subdomains": [],
            "risk_score": 4.2,
            "recommended_exploits": ["nmap"],
        }
    )

    fake_tool_outputs = [
        {
            "tool": "nmap",
            "ok": True,
            "duration_s": 1.0,
            "findings": [{"port": 80, "state": "open", "service": "http"}],
        }
    ]

    async def fake_agent_loop(self_, cves):
        return json_payload, fake_tool_outputs

    async def fake_notify_blue(self_, result):
        return None

    with patch.object(
        CVEFetcher, "fetch_recent", new=AsyncMock(return_value=[])
    ), patch.object(
        ReconAgent, "_agent_loop", new=fake_agent_loop
    ), patch.object(
        ReconAgent, "_notify_blue_agent", new=fake_notify_blue
    ):
        result = fresh_loop.run_until_complete(agent.run())

    assert isinstance(result, ReconResult)
    assert result.status == "complete"
    assert result.session_id.startswith("recon_")
    assert result.risk_score == 4.2
    assert len(result.attack_vectors) == 1
    assert "nginx" in result.tech_stack
    assert result.tools_run == ["nmap"]


# ---------- 5. Agent handles synthesis failure gracefully ------------------

def test_recon_agent_handles_crew_failure(fresh_loop):
    agent = ReconAgent("http://localhost")

    async def boom(self_, cves):
        raise RuntimeError("groq exploded")

    async def fake_notify(self_, result):
        return None

    with patch.object(
        ReconAgent, "_agent_loop", new=boom
    ), patch.object(
        ReconAgent, "_notify_blue_agent", new=fake_notify
    ):
        result = fresh_loop.run_until_complete(agent.run())

    assert isinstance(result, ReconResult)
    assert result.status == "failed"
    assert result.error and "groq exploded" in result.error


# ---------- 6. JSON extraction from crew output -----------------------------

def test_json_extraction_from_crew_output():
    agent = ReconAgent("http://localhost")

    clean = '{"risk_score": 7.5, "tech_stack": ["Apache"]}'
    assert agent._extract_json(clean)["risk_score"] == 7.5

    fenced = "Here is the report:\n```json\n{\"open_ports\": [22, 80]}\n```\n"
    assert agent._extract_json(fenced)["open_ports"] == [22, 80]

    embedded = (
        "Final answer follows:\n"
        '{"attack_vectors": [], "risk_score": 1.0}\n'
        "End of response."
    )
    assert agent._extract_json(embedded)["risk_score"] == 1.0

    assert agent._extract_json("complete garbage no json here") == {}
    assert agent._extract_json("") == {}
