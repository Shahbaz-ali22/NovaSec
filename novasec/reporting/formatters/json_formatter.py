"""
NovaSec JSON Report Formatter.

Serialises a :class:`~novasec.reporting.models.Report` to a
machine-readable JSON file suitable for SIEM ingestion and automation.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from novasec.reporting.base import ReporterBase
from novasec.reporting.models import Report


class JSONFormatter(ReporterBase):
    """Formats scan reports as structured JSON."""

    @property
    def format_name(self) -> str:
        return "json"

    @property
    def file_extension(self) -> str:
        return ".json"

    def generate(self, report: Report) -> bytes:
        """Serialise *report* to JSON bytes."""
        data = self._build_json_structure(report)
        return json.dumps(data, indent=2, default=self._json_serializer).encode("utf-8")

    def _build_json_structure(self, report: Report) -> dict[str, Any]:
        """Build the JSON data structure for the report."""
        severity_summary = report.severity_summary()

        return {
            "novasec_report": {
                "version": "1.0",
                "generated_at": report.generated_at.isoformat(),
                "title": report.title,
                "company": report.company_name,
            },
            "scan_metadata": {
                "scan_id": report.metadata.scan_id,
                "target": report.metadata.target,
                "operator": report.metadata.operator,
                "profile": report.metadata.profile,
                "started_at": report.metadata.started_at.isoformat(),
                "completed_at": report.metadata.completed_at.isoformat() if report.metadata.completed_at else None,
                "duration_seconds": report.metadata.duration_seconds,
                "plugins_used": report.metadata.plugins_used,
            },
            "summary": {
                "total_findings": report.finding_count,
                "risk_score": report.risk_score,
                "severity_breakdown": severity_summary,
                "executive_summary": report.executive_summary,
            },
            "findings": [
                self._serialize_finding(f)
                for f in report.findings_by_severity()
            ],
        }

    def _serialize_finding(self, finding: Any) -> dict[str, Any]:
        """Serialise a single finding to a dict."""
        return {
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity.value,
            "cvss_score": finding.cvss_score,
            "cvss_vector": finding.cvss_vector,
            "target": finding.target,
            "description": finding.description,
            "impact": finding.impact,
            "remediation": finding.remediation,
            "cve_ids": finding.cve_ids,
            "cwe_ids": finding.cwe_ids,
            "owasp_category": finding.owasp_category,
            "port": finding.port,
            "protocol": finding.protocol,
            "service": finding.service,
            "plugin_source": finding.plugin_source,
            "tags": finding.tags,
            "references": finding.references,
            "discovered_at": finding.discovered_at.isoformat(),
            "evidence": [
                {
                    "type": e.type,
                    "description": e.description,
                    "data": e.data[:1000] if len(e.data) > 1000 else e.data,
                    "truncated": len(e.data) > 1000,
                }
                for e in finding.evidence
            ],
        }

    @staticmethod
    def _json_serializer(obj: Any) -> Any:
        """Handle non-serializable types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
