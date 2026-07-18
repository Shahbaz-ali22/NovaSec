"""
NovaSec JSON Reporting Unit Tests.
"""

from __future__ import annotations

import json
from datetime import datetime, UTC

from novasec.reporting.models import Report, ScanMetadata
from novasec.reporting.formatters.json_formatter import JSONFormatter


def test_json_report_generation(mock_findings) -> None:
    """Validate compilation of findings data structure to output JSON."""
    meta = ScanMetadata(
        scan_id="ns-test123",
        target="example.com",
        started_at=datetime.now(UTC),
    )
    report = Report(
        title="Test Security Assessment",
        metadata=meta,
        findings=mock_findings,
    )
    report.risk_score = report.calculate_risk_score()

    formatter = JSONFormatter()
    raw_bytes = formatter.generate(report)
    
    # Load back as Python dict to assert schema layout
    data = json.loads(raw_bytes.decode("utf-8"))
    
    assert data["novasec_report"]["title"] == "Test Security Assessment"
    assert data["scan_metadata"]["scan_id"] == "ns-test123"
    assert data["summary"]["total_findings"] == 2
    assert len(data["findings"]) == 2
    assert data["findings"][0]["title"] == "Critical SSL Expiry"
