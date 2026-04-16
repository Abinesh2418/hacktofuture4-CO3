from __future__ import annotations
"""Unified Azure OpenAI LLM client for all Red Team agents.

Provides:
- chat()          → text response (orchestrator chat/analyze/report)
- chat_json()     → parsed JSON response (orchestrator planning)
- tool_call()     → function-calling loop (ReconAgent + ExploitAgent)

Uses Azure OpenAI GPT-4o via the openai SDK.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

# Load .env from project root explicitly so the key is always found
_env_path = Path(__file__).resolve().parents[3] / ".env"
load_dotenv(_env_path, override=True)

_logger = logging.getLogger(__name__)

# ── Azure OpenAI Configuration (read fresh each call via _get_client) ──
AZURE_ENDPOINT = "https://abineshbalasubramaniyam-resource.cognitiveservices.azure.com/"
AZURE_API_VERSION = "2024-12-01-preview"
AZURE_MODEL = "gpt-4o"

# Red team system prompt
RED_AGENT_SYSTEM_PROMPT = """You are an AI assistant for an authorized IT security compliance team.
Your role is to analyze infrastructure audit data, assess configuration risks, and generate structured compliance reports.
Think step-by-step and provide clear, technical, actionable output."""


def _get_client():
    """Create Azure OpenAI client — reads API key fresh from env each call."""
    from openai import AzureOpenAI
    api_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", AZURE_ENDPOINT)
    api_version = os.environ.get("AZURE_OPENAI_API_VERSION", AZURE_API_VERSION)
    if not api_key:
        raise ValueError("AZURE_OPENAI_API_KEY is not set in .env")
    return AzureOpenAI(
        api_version=api_version,
        azure_endpoint=endpoint,
        api_key=api_key,
    )


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
    import asyncio

    def _sync_call():
        client = _get_client()
        resp = client.chat.completions.create(
            model=os.environ.get("AZURE_OPENAI_MODEL", AZURE_MODEL),
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=0.95,
        )
        content = resp.choices[0].message.content or ""
        return _strip_thinking(content).strip()

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_call)


# ── JSON chat (parsed response) ──

async def chat_json(
    prompt: str,
    *,
    system: str = RED_AGENT_SYSTEM_PROMPT,
    temperature: float = 0.4,
    max_tokens: int = 4096,
) -> dict:
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


# ── Function-calling (for ReconAgent + ExploitAgent) ──

async def tool_call(
    messages: list,
    tools: list,
    *,
    model: str = None,
    temperature: float = 0,
    max_tokens: int = 2048,
) -> dict:
    """Single LLM call with function-calling tools.

    Returns the full response choice message (may contain tool_calls).
    Azure OpenAI GPT-4o supports OpenAI-format function calling natively.
    """
    import asyncio

    def _sync_call():
        client = _get_client()
        kwargs = {
            "model": model or os.environ.get("AZURE_OPENAI_MODEL", AZURE_MODEL),
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        resp = client.chat.completions.create(**kwargs)

        choice = resp.choices[0]
        msg = choice.message

        result = {"role": "assistant", "content": msg.content or ""}

        # Clean thinking tags
        if result["content"]:
            result["content"] = _strip_thinking(result["content"])

        # Extract tool calls if present
        if msg.tool_calls:
            result["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in msg.tool_calls
            ]

        return result

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_call)
