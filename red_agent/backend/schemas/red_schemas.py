from __future__ import annotations
"""Request / response models for the Red Agent backend."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ToolStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    DONE = "DONE"
    FAILED = "FAILED"


class ToolCall(BaseModel):
    """Represents a single tool invocation surfaced in the UI."""

    id: str
    name: str = Field(..., description="Tool name, e.g. nmap_scan, lookup_cve")
    category: str = Field(..., description="scan | exploit | strategy")
    status: ToolStatus = ToolStatus.PENDING
    params: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] | None = None
    started_at: datetime = Field(default_factory=datetime.now)
    finished_at: datetime | None = None


class LogEntry(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    level: str = "INFO"
    message: str
    tool_id: str | None = None


class ScanRequest(BaseModel):
    target: str = Field(..., examples=["192.168.1.100"])
    ports: list[int] | None = None
    options: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    tool_call: ToolCall
    open_ports: list[int] = Field(default_factory=list)
    services: dict[int, str] = Field(default_factory=dict)
    findings: list[str] = Field(default_factory=list)


class CVELookupRequest(BaseModel):
    service: str
    version: str | None = None


class CVELookupResult(BaseModel):
    tool_call: ToolCall
    cve_ids: list[str] = Field(default_factory=list)
    summaries: dict[str, str] = Field(default_factory=dict)


class ExploitRequest(BaseModel):
    target: str
    cve_id: str | None = None
    payload: str | None = None
    options: dict[str, Any] = Field(default_factory=dict)


class ExploitResult(BaseModel):
    tool_call: ToolCall
    success: bool = False
    foothold: str | None = None
    notes: str | None = None


class StrategyRequest(BaseModel):
    target: str
    intel: dict[str, Any] = Field(default_factory=dict)


class StrategyPlan(BaseModel):
    tool_call: ToolCall
    steps: list[str] = Field(default_factory=list)
    rationale: str | None = None


# ── Mission (orchestrator) ──


class MissionPhase(str, Enum):
    IDLE = "IDLE"
    RECON = "RECON"
    ANALYZE = "ANALYZE"
    PLAN = "PLAN"
    EXPLOIT = "EXPLOIT"
    REPORT = "REPORT"
    DONE = "DONE"
    FAILED = "FAILED"
    PAUSED = "PAUSED"


class MissionStartRequest(BaseModel):
    target: str = Field(..., examples=["192.168.1.100"])


class MissionStatus(BaseModel):
    id: str
    target: str
    phase: MissionPhase = MissionPhase.IDLE
    created_at: datetime = Field(default_factory=datetime.now)
    error: str | None = None
