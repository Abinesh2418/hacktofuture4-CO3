"""Unified NVIDIA NIM LLM client for all three agents.

Provides:
- chat()          → text response (orchestrator chat/analyze/report)
- chat_json()     → parsed JSON response (orchestrator planning)
- tool_call()     → function-calling loop (ReconAgent + ExploitAgent)
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()

_logger = logging.getLogger(__name__)

NVIDIA_API_URL = os.environ.get(
    "LLM_API_URL",
    "https://integrate.api.nvidia.com/v1/chat/completions",
)
NVIDIA_API_KEY = os.environ.get(
    "NVIDIA_API_KEY",
    "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",
)
LLM_MODEL = os.environ.get("LLM_MODEL", "meta/llama-3.1-70b-instruct")

# Red team system prompt for general chat/analysis
RED_AGENT_SYSTEM_PROMPT = """You are an autonomous red team AI agent specializing in offensive security.
Your role is to analyze reconnaissance data, identify vulnerabilities, plan attack strategies, and generate security assessment reports.
Think step-by-step and provide actionable, structured output. Be concise and technical."""


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {NVIDIA_API_KEY}",
        "Content-Type": "application/json",
    }


def _strip_thinking(text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


# ── Simple chat (text response) ──

async def chat(
    prompt: str,
    *,
    system: str = RED_AGENT_SYSTEM_PROMPT,
    temperature: float = 0.6,
    max_tokens: int = 4096,
) -> str:
    payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
        "top_p": 0.95,
        "stream": False,
    }

    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(NVIDIA_API_URL, headers=_headers(), json=payload)
        resp.raise_for_status()
        data = resp.json()
        choices = data.get("choices", [])
        if choices:
            content = choices[0].get("message", {}).get("content", "")
            return _strip_thinking(content).strip()
        return ""


# ── JSON chat (parsed response) ──

async def chat_json(
    prompt: str,
    *,
    system: str = RED_AGENT_SYSTEM_PROMPT,
    temperature: float = 0.4,
    max_tokens: int = 4096,
) -> dict[str, Any]:
    json_prompt = prompt + "\n\nRespond ONLY with valid JSON. No markdown, no code fences."
    text = await chat(json_prompt, system=system, temperature=temperature, max_tokens=max_tokens)
    try:
        cleaned = text
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0]
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0]
        return json.loads(cleaned.strip())
    except (json.JSONDecodeError, IndexError):
        return {"raw_response": text}


# ── Function-calling loop (for ReconAgent + ExploitAgent) ──

async def tool_call(
    messages: list[dict],
    tools: list[dict],
    *,
    model: str | None = None,
    temperature: float = 0,
    max_tokens: int = 2048,
) -> dict:
    """Single LLM call with function-calling tools.

    Returns the full response choice message (may contain tool_calls).
    NVIDIA NIM uses the OpenAI-compatible format for function calling.
    """
    payload = {
        "model": model or LLM_MODEL,
        "messages": messages,
        "tools": tools,
        "tool_choice": "auto",
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": False,
    }

    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(NVIDIA_API_URL, headers=_headers(), json=payload)
        resp.raise_for_status()
        data = resp.json()

        choices = data.get("choices", [])
        if not choices:
            return {"role": "assistant", "content": "No response from LLM."}

        message = choices[0].get("message", {})
        # Clean thinking tags from content
        if message.get("content"):
            message["content"] = _strip_thinking(message["content"])

        return message
