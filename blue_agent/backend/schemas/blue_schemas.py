"""Request / response models for the Blue Agent backend."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ToolStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    DONE = "DONE"
    FAILED = "FAILED"


class ToolCall(BaseModel):
    id: str
    name: str = Field(..., description="Tool name, e.g. close_port, verify_fix")
    category: str = Field(..., description="defend | patch | strategy | scan | environment | evolution")
    status: ToolStatus = ToolStatus.PENDING
    params: Dict[str, Any] = Field(default_factory=dict)
    result: Optional[Dict[str, Any]] = None
    started_at: datetime = Field(default_factory=datetime.now)
    finished_at: Optional[datetime] = None


class LogEntry(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    level: str = "INFO"
    message: str
    tool_id: Optional[str] = None


# ── Defense ──────────────────────────────────────────────────────────

class ClosePortRequest(BaseModel):
    host: str
    port: int
    protocol: str = "tcp"


class HardenServiceRequest(BaseModel):
    host: str
    service: str
    options: Dict[str, Any] = Field(default_factory=dict)


class IsolateHostRequest(BaseModel):
    host: str
    reason: Optional[str] = None


class DefenseResult(BaseModel):
    tool_call: ToolCall
    success: bool = True
    detail: Optional[str] = None


# ── Patching ─────────────────────────────────────────────────────────

class PatchRequest(BaseModel):
    host: str
    cve_id: Optional[str] = None
    package: Optional[str] = None


class PatchResult(BaseModel):
    tool_call: ToolCall
    applied: bool = False
    notes: Optional[str] = None


class VerifyFixRequest(BaseModel):
    host: str
    cve_id: str


class VerifyFixResult(BaseModel):
    tool_call: ToolCall
    verified: bool = False
    evidence: Optional[str] = None


# ── Strategy ─────────────────────────────────────────────────────────

class StrategyRequest(BaseModel):
    host: str
    threat: Dict[str, Any] = Field(default_factory=dict)


class DefensePlan(BaseModel):
    tool_call: ToolCall
    steps: List[str] = Field(default_factory=list)
    rationale: Optional[str] = None


# ── Asset Scanning ───────────────────────────────────────────────────

class ScanRequest(BaseModel):
    environment: Optional[str] = None  # cloud, onprem, hybrid, or None for all


class AssetInfo(BaseModel):
    asset_id: str
    host: str
    port: int
    service: str
    environment: str
    layer: str
    version: Optional[str] = None
    banner: Optional[str] = None
    detection_method: Optional[str] = None
    cve_count: int = 0
    cves: List[Dict[str, Any]] = Field(default_factory=list)
    last_scanned: Optional[float] = None
    status: str = "discovered"


class ScanResult(BaseModel):
    tool_call: ToolCall
    assets: List[AssetInfo] = Field(default_factory=list)
    stats: Dict[str, Any] = Field(default_factory=dict)


class VulnerabilityInfo(BaseModel):
    cve_id: str
    severity: str
    cvss_score: float
    description: str
    affected_software: str
    affected_version: str
    fix: str
    host: Optional[str] = None
    port: Optional[int] = None


# ── Environment Monitoring ───────────────────────────────────────────

class EnvironmentAlertInfo(BaseModel):
    alert_id: str
    environment: str
    category: str
    severity: str
    title: str
    description: str
    resource: str
    recommendation: str
    timestamp: float


class EnvironmentStats(BaseModel):
    total_alerts: int = 0
    by_environment: Dict[str, int] = Field(default_factory=dict)
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_category: Dict[str, int] = Field(default_factory=dict)
    monitoring_active: bool = False


# ── Evolution ────────────────────────────────────────────────────────

class EvolutionMetrics(BaseModel):
    evolution_count: int = 0
    round_count: int = 0
    avg_response_time_ms: float = 0.0
    response_accuracy_pct: float = 0.0
    improvement_pct: float = 0.0
    current_params: Dict[str, Any] = Field(default_factory=dict)
    top_attack_patterns: List[Dict[str, Any]] = Field(default_factory=list)
    total_patterns_tracked: int = 0


# ── SSH Scanning ─────────────────────────────────────────────────────

class SSHCredentials(BaseModel):
    host: str
    ssh_port: int = 22
    username: str = "root"
    password: str


class SSHScanResult(BaseModel):
    success: bool
    host: str
    error: Optional[str] = None
    os_info: Optional[str] = None
    listening_ports: List[Dict[str, Any]] = Field(default_factory=list)
    services: List[Dict[str, Any]] = Field(default_factory=list)
    total_services: int = 0
    total_cves: int = 0
    fixes_applied: int = 0
    elapsed_seconds: float = 0.0


# ── Full Status ──────────────────────────────────────────────────────

class BlueAgentStatus(BaseModel):
    running: bool = False
    detection_count: int = 0
    response_count: int = 0
    patch_count: int = 0
    cve_fix_count: int = 0
    isolation_count: int = 0
    scan_cycles: int = 0
    assets_discovered: int = 0
    vulnerable_assets: int = 0
    total_vulnerabilities: int = 0
    environment_alerts: int = 0
    evolution_rounds: int = 0
    defense_plans: int = 0
    remediation_findings: int = 0
    remediation_fixes: int = 0


# ── Red Report Ingestion ────────────────────────────────────────────

class RedReportRequest(BaseModel):
    """Structured Red team penetration test report."""
    target: str = Field(..., description="Target URL, e.g. http://172.25.8.172:5000")
    risk_score: float = Field(0.0, description="Overall risk score 0-10")
    recon: Dict[str, Any] = Field(default_factory=dict, description="Phase 1: Recon findings")
    exploit: Dict[str, Any] = Field(default_factory=dict, description="Phase 2: Exploit findings")
    recommendations: List[Dict[str, Any]] = Field(default_factory=list, description="Remediation recommendations")


class RemediationResult(BaseModel):
    """Result of the Blue Agent remediation pipeline."""
    target: str
    risk_score: float
    total_findings: int = 0
    fixes_applied: int = 0
    total_steps: int = 0
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    applied_fixes: List[Dict[str, Any]] = Field(default_factory=list)
    pending_fixes: List[Dict[str, Any]] = Field(default_factory=list)
    status: str = "complete"


class RemediationStatus(BaseModel):
    """Current status of the remediation engine."""
    findings_received: int = 0
    fixes_dispatched: int = 0
    total_steps: int = 0
    applied_fixes: List[Dict[str, Any]] = Field(default_factory=list)


# ── Approval Workflow ──────────────────────────────────────────────

class PendingFix(BaseModel):
    """A fix awaiting user approval before it is applied."""
    fix_id: str
    category: str
    severity: str
    description: str
    endpoint: Optional[str] = None
    status: str = "pending_approval"
    finding_details: Dict[str, Any] = Field(default_factory=dict)


class ApprovalResult(BaseModel):
    """Result of approving or rejecting a pending fix."""
    fix_id: str
    status: str  # "approved" or "rejected"
    fix_result: Optional[Dict[str, Any]] = None
