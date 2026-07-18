"""
NovaSec CSV Report Formatter.

Generates comma-separated values (.csv) containing findings data.
"""

from __future__ import annotations

import csv
import io
from novasec.reporting.base import ReporterBase
from novasec.reporting.models import Report


class CSVFormatter(ReporterBase):
    """Formats scan findings into a flat CSV layout."""

    @property
    def format_name(self) -> str:
        return "csv"

    @property
    def file_extension(self) -> str:
        return ".csv"

    def generate(self, report: Report) -> bytes:
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header row
        writer.writerow([
            "Scan ID", "Target", "Severity", "Finding Title", "Plugin Source", 
            "CVE IDs", "CWE IDs", "CVSS Score", "Description", "Impact", "Remediation"
        ])
        
        for f in report.findings_by_severity():
            writer.writerow([
                report.metadata.scan_id,
                f.target,
                f.severity.value,
                f.title,
                f.plugin_source,
                ", ".join(f.cve_ids),
                ", ".join(f.cwe_ids),
                f.cvss_score or "",
                f.description,
                f.impact,
                f.remediation
            ])
            
        return output.getvalue().encode("utf-8")
