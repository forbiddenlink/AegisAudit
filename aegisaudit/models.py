from datetime import datetime
from enum import Enum
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    id: str
    severity: Severity
    title: str
    description: str
    evidence: Optional[str] = None
    url: str
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class ScanArtifact(BaseModel):
    """Raw response data collected from a URL."""

    url: str
    final_url: str
    status_code: int
    headers: Dict[str, str]
    cookies: Dict[str, str]
    body_snippet: str  # Truncated body for analysis
    content_type: str
    timestamp: datetime = Field(default_factory=datetime.now)


class ScanSummary(BaseModel):
    counts_by_severity: Dict[str, int] = Field(default_factory=dict)
    category_scores: Dict[str, float] = Field(default_factory=dict)
    overall_score: float = 0.0

    @property
    def total_findings(self) -> int:
        """Total number of findings across all severities."""
        return sum(self.counts_by_severity.values())


class ScanResult(BaseModel):
    tool_name: str = "AegisAudit"
    tool_version: str = "0.1.0"
    started_at: datetime = Field(default_factory=datetime.now)
    finished_at: Optional[datetime] = None
    targets: List[str]
    findings: List[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    config_snapshot: Optional[Dict[str, Any]] = None
