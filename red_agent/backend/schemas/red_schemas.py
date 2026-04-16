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
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None


class LogEntry(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
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
    created_at: datetime = Field(default_factory=datetime.utcnow)
    error: str | None = None


# ── Auto-pwn (deterministic SQLi pipeline, no LLM) ──


class AutoPwnStepKind(str, Enum):
    CURL_PROBE = "CURL_PROBE"
    SQLMAP_DBS = "SQLMAP_DBS"
    SQLMAP_TABLES = "SQLMAP_TABLES"
    SQLMAP_DUMP = "SQLMAP_DUMP"
    SQLMAP_DUMP_ALL = "SQLMAP_DUMP_ALL"


class AutoPwnStep(BaseModel):
    """A single deterministic step in the auto-SQLi exfiltration lane.

    Surfaced in its own dashboard panel — never touched by the LLM.
    """

    id: str
    mission_id: str | None = None
    target: str
    kind: AutoPwnStepKind
    status: ToolStatus = ToolStatus.RUNNING
    command: str = ""
    summary: str = ""
    db: str | None = None
    table: str | None = None
    items: list[str] = Field(default_factory=list)
    rows: list[list[str]] = Field(default_factory=list)
    # For consolidated dump cards: one section per (db, table) pair so the UI
    # renders all extracted rows under a single card with collapsible groups.
    sections: list[dict[str, Any]] = Field(default_factory=list)
    raw_tail: str = ""
    error: str | None = None
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None
