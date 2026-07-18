"""
NovaSec Report Data Models.

All scan findings and reports are modelled as Pydantic v2 dataclasses.
These models are the primary data transfer objects (DTOs) flowing from
domain scanners to the reporting layer.
"""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Finding severity levels following the CVSS v3 severity scale."""

    CRITICAL = "CRITICAL"   # CVSS 9.0–10.0
    HIGH = "HIGH"           # CVSS 7.0–8.9
    MEDIUM = "MEDIUM"       # CVSS 4.0–6.9
    LOW = "LOW"             # CVSS 0.1–3.9
    INFO = "INFO"           # Informational — no CVSS score

    @property
    def cvss_range(self) -> tuple[float, float]:
        ranges = {
            "CRITICAL": (9.0, 10.0),
            "HIGH": (7.0, 8.9),
            "MEDIUM": (4.0, 6.9),
            "LOW": (0.1, 3.9),
            "INFO": (0.0, 0.0),
        }
        return ranges[self.value]

    @property
    def color(self) -> str:
        """Rich terminal color for this severity."""
        colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "cyan",
        }
        return colors[self.value]

    @property
    def sort_order(self) -> int:
        """Lower value = higher severity (for sorting)."""
        return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(self.value)


class Evidence(BaseModel):
    """A piece of evidence supporting a finding."""

    type: Literal["request", "response", "output", "screenshot", "log", "raw"]
    data: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    description: str = ""
    truncated: bool = False


class Finding(BaseModel):
    """A single security finding discovered by a scanner or plugin."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    severity: Severity
    description: str
    target: str
    plugin_source: str = ""

    # Vulnerability identification
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None

    # Contextual details
    impact: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    # Technical evidence
    evidence: list[Evidence] = Field(default_factory=list)

    # OWASP / compliance mapping
    owasp_category: str | None = None  # e.g. "A01:2021 - Broken Access Control"

    # Timestamps
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Port/service context (optional)
    port: int | None = None
    protocol: str | None = None
    service: str | None = None

    # Raw scanner output (optional)
    raw_output: str | None = None

    def add_evidence(
        self,
        type: str,  # noqa: A002
        data: str,
        description: str = "",
    ) -> None:
        """Append an evidence item to this finding."""
        self.evidence.append(Evidence(type=type, data=data, description=description))  # type: ignore[arg-type]

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class FindingSet(BaseModel):
    """A collection of findings from a single scan operation."""

    scan_id: str = Field(default_factory=lambda: f"ns-{uuid.uuid4().hex[:8]}")
    target: str = ""
    plugin_source: str = ""
    findings: list[Finding] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def add(self, finding: Finding) -> None:
        """Add a finding to this set."""
        self.findings.append(finding)

    def severity_summary(self) -> dict[str, int]:
        """Return count of findings per severity level."""
        counts: dict[str, int] = Counter(f.severity.value for f in self.findings)
        return {s: counts.get(s, 0) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}

    def by_severity(self) -> list[Finding]:
        """Return findings sorted by severity (most severe first)."""
        return sorted(self.findings, key=lambda f: f.severity.sort_order)

    def filter_severity(self, min_severity: Severity) -> "FindingSet":
        """Return a new FindingSet with only findings >= *min_severity*."""
        filtered = [
            f for f in self.findings
            if f.severity.sort_order <= min_severity.sort_order
        ]
        return FindingSet(
            scan_id=self.scan_id,
            target=self.target,
            findings=filtered,
        )

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def __len__(self) -> int:
        return len(self.findings)

    def __bool__(self) -> bool:
        return bool(self.findings)


class ScanMetadata(BaseModel):
    """Metadata about a scan run — stored alongside findings."""

    scan_id: str
    target: str
    started_at: datetime
    completed_at: datetime | None = None
    operator: str = ""
    profile: str = "default"
    plugins_used: list[str] = Field(default_factory=list)
    options: dict[str, Any] = Field(default_factory=dict)

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class Report(BaseModel):
    """The assembled report object passed to formatters."""

    title: str = "NovaSec Security Assessment Report"
    company_name: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: ScanMetadata
    findings: list[Finding] = Field(default_factory=list)
    executive_summary: str = ""
    risk_score: float = 0.0       # 0.0–10.0 overall risk score

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def severity_summary(self) -> dict[str, int]:
        counts: dict[str, int] = Counter(f.severity.value for f in self.findings)
        return {s: counts.get(s, 0) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}

    def findings_by_severity(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity.sort_order)

    def calculate_risk_score(self) -> float:
        """Compute a 0–10 overall risk score from finding severities."""
        if not self.findings:
            return 0.0
        weights = {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 1.0, "INFO": 0.0}
        total = sum(weights.get(f.severity.value, 0) for f in self.findings)
        # Normalize: cap at 10.0
        return min(10.0, round(total / max(len(self.findings), 1), 1))
