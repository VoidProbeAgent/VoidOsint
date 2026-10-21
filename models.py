"""
VoidOsint Pydantic Schemas & Data Models
========================================
Defines schemas for scan configurations, discoveries, system health,
trust metrics, graph structures, and real-time WebSocket events.

Conforms to Section 6 of hive/specs/osint-platform-spec.md.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator

# Re-export TrustGrade and TrustMetrics from trust_engine for consistency
try:
    from backend.trust_engine import TrustGrade, TrustMetrics
except ImportError:
    class TrustGrade(str, Enum):
        CONFIRMED = "CONFIRMED"
        HIGH = "HIGH"
        PROBABLE = "PROBABLE"
        SUSPICIOUS = "SUSPICIOUS"
        FALSE_POSITIVE = "FALSE_POSITIVE"

    class TrustMetrics(BaseModel):
        validity_score: float = Field(..., ge=0.0, le=1.0)
        accuracy_score: float = Field(..., ge=0.0, le=1.0)
        consensus_score: float = Field(..., ge=0.0, le=1.0)
        penalty: float = Field(default=0.0, ge=0.0, le=1.0)
        composite_score: float = Field(..., ge=0.0, le=100.0)
        grade: TrustGrade
        audit_trail: List[str] = Field(default_factory=list)


class TargetType(str, Enum):
    USERNAME = "username"
    HUMAN_NAME = "human_name"
    EMAIL = "email"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    PHONE_NUMBER = "phone_number"


class EngineType(str, Enum):
    MAIGRET = "maigret"
    SPIDERFOOT = "spiderfoot"
    GOOGLE_SEARCH = "google_search"
    DUCKDUCKGO = "duckduckgo"
    BING = "bing"
    GITHUB = "github"
    MULTI_ENGINE = "multi_engine"


class ScanDepth(str, Enum):
    FAST = "fast"
    STANDARD = "standard"
    DEEP = "deep"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    ABORTED = "aborted"
    FAILED = "failed"


class ScanConfig(BaseModel):
    """Configuration submitted to trigger an OSINT scan."""
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_name: Optional[str] = None
    target: str = Field(..., min_length=1, description="Target query string")
    target_type: TargetType = Field(default=TargetType.USERNAME)
    engines: List[str] = Field(
        default=["maigret", "spiderfoot", "google_search"],
        description="Engines to execute"
    )
    depth: ScanDepth = Field(default=ScanDepth.STANDARD)
    timeout_seconds: int = Field(default=60, ge=5, le=600)
    max_concurrent_connections: int = Field(default=50, ge=1, le=200)
    enable_trust_scoring: bool = Field(default=True)
    custom_keywords: List[str] = Field(default_factory=list)

    @field_validator("target")
    @classmethod
    def validate_target_string(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Target must not be empty.")
        clean = v.strip()
        from backend.security import DANGEROUS_CONTROL_CHARS_RE, DANGEROUS_SHELL_CHARS_RE
        if DANGEROUS_CONTROL_CHARS_RE.search(clean):
            raise ValueError("Target contains illegal control or null-byte characters.")
        if DANGEROUS_SHELL_CHARS_RE.search(clean):
            raise ValueError("Target contains forbidden shell metacharacters.")
        if clean.startswith("-"):
            raise ValueError("Target cannot begin with '-' or '--' (CLI flag injection prevented).")
        return clean


class DiscoveryItem(BaseModel):
    """Enriched discovery record found by an OSINT engine."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    target: str
    target_type: str
    engine: str
    entity_type: str = "social_profile"
    platform_name: Optional[str] = None
    url: Optional[str] = None
    title: Optional[str] = None
    snippet: Optional[str] = None
    http_status: Optional[int] = 200
    extracted_data: Dict[str, Any] = Field(default_factory=dict)
    trust_metrics: Optional[TrustMetrics] = None
    discovered_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ScanSummary(BaseModel):
    """High-level summary of an OSINT scan."""
    scan_id: str
    scan_name: Optional[str] = None
    target: str
    target_type: str
    status: ScanStatus = ScanStatus.PENDING
    depth: str = "standard"
    progress: int = Field(default=0, ge=0, le=100)
    engines: List[str] = Field(default_factory=list)
    engine_statuses: Dict[str, str] = Field(default_factory=dict)
    total_discoveries: int = 0
    confirmed_count: int = 0
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None


class CaseSummary(BaseModel):
    """Summarized investigation metadata for the Investigations Dashboard."""
    scan_id: str
    scan_name: Optional[str] = None
    target: str
    target_type: str
    status: str
    depth: str = "standard"
    progress: int = 0
    engines: List[str] = Field(default_factory=list)
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    total_discoveries: int = 0
    confirmed_count: int = 0
    high_count: int = 0
    suspicious_count: int = 0
    avg_trust_score: float = 0.0
    notes: Optional[str] = None


class InvestigationListResponse(BaseModel):
    """Paginated list of historical investigations."""
    total: int
    page: int = 1
    limit: int = 25
    cases: List[CaseSummary]


class UpdateCaseNotesRequest(BaseModel):
    """Payload to update notes on an investigation case."""
    notes: str = Field(..., max_length=5000)


class UserSettings(BaseModel):
    """User preferences stored locally and synchronized with the backend."""
    theme: str = Field(default="dark", pattern="^(dark|light)$")
    layout_width: str = Field(default="standard", pattern="^(standard|wide)$")
    typography_scale: str = Field(default="standard", pattern="^(standard|large)$")
    sidebar_collapsed: bool = Field(default=False)
    default_engines: List[str] = Field(
        default=["maigret", "spiderfoot", "google_search", "duckduckgo", "bing", "github"]
    )
    timeout_seconds: int = Field(default=60, ge=15, le=300)
    max_concurrent_connections: int = Field(default=50, ge=10, le=100)
    auto_launch_browser: bool = Field(default=True)


class GraphNode(BaseModel):
    """Graph node structure compatible with Vis.js and Cytoscape.js."""
    id: str
    label: str
    group: str = "discovery"
    title: Optional[str] = None
    url: Optional[str] = None
    score: Optional[float] = None
    grade: Optional[str] = None
    color: Optional[str] = None


class GraphEdge(BaseModel):
    """Graph edge connecting source and target nodes."""
    from_node: str = Field(..., alias="from")
    to_node: str = Field(..., alias="to")
    label: Optional[str] = None
    arrows: Optional[str] = "to"

    class Config:
        populate_by_name = True


class GraphData(BaseModel):
    """Full entity-relationship graph payload."""
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]


class SystemHealth(BaseModel):
    """System health and environment probe response."""
    status: str = "healthy"
    host: str
    port: int
    database_connected: bool
    database_path: str
    engines: Dict[str, Dict[str, Any]]
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class WSEventType(str, Enum):
    SCAN_STARTED = "scan_started"
    SCAN_PROGRESS = "scan_progress"
    ENGINE_LOG = "engine_log"
    DISCOVERY_FOUND = "discovery_found"
    SCAN_COMPLETED = "scan_completed"
    SCAN_ABORTED = "scan_aborted"
    SCAN_FAILED = "scan_failed"


class WSEvent(BaseModel):
    """Real-time WebSocket event published to connected frontends."""
    event: WSEventType
    scan_id: str
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    data: Dict[str, Any] = Field(default_factory=dict)
