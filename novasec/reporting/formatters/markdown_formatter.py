"""
NovaSec Markdown Report Formatter.

Generates structured markdown files (.md) summarizing scan findings.
"""

from __future__ import annotations

from novasec.reporting.base import ReporterBase
from novasec.reporting.models import Report


class MarkdownFormatter(ReporterBase):
    """Formats scan reports as readable Markdown documents."""

    @property
    def format_name(self) -> str:
        return "markdown"

    @property
    def file_extension(self) -> str:
        return ".md"

    def generate(self, report: Report) -> bytes:
        lines = [
            f"# {report.title}",
            f"**Company:** {report.company_name or 'N/A'}",
            f"**Generated At:** {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "## Scan Metadata",
            f"- **Scan ID:** `{report.metadata.scan_id}`",
            f"- **Target:** `{report.metadata.target}`",
            f"- **Operator:** `{report.metadata.operator}`",
            f"- **Profile:** `{report.metadata.profile}`",
            f"- **Duration:** `{report.metadata.duration_seconds or 0:.2f} seconds`",
            f"- **Plugins Used:** {', '.join(report.metadata.plugins_used) or 'None'}",
            "",
            "## Risk Score",
            f"Overall Risk Score: **{report.risk_score}/10**",
            "",
            "## Severity Breakdown",
        ]

        for sev, count in report.severity_summary().items():
            lines.append(f"- **{sev}:** {count}")
        lines.append("")

        lines.append("## Findings")
        for finding in report.findings_by_severity():
            lines.extend([
                f"### [{finding.severity.value}] {finding.title}",
                f"- **Target:** `{finding.target}`",
                f"- **Source:** `{finding.plugin_source}`",
                f"- **CVEs:** {', '.join(finding.cve_ids) or 'None'}",
                f"- **CWEs:** {', '.join(finding.cwe_ids) or 'None'}",
                "",
                "#### Description",
                finding.description,
                "",
            ])
            if finding.impact:
                lines.extend(["#### Impact", finding.impact, ""])
            if finding.remediation:
                lines.extend(["#### Remediation", finding.remediation, ""])

            if finding.evidence:
                lines.extend(["#### Evidence", ""])
                for ev in finding.evidence:
                    lines.extend([
                        f"**Type: {ev.type}** - {ev.description}",
                        "```",
                        ev.data,
                        "```",
                        "",
                    ])

        return "\n".join(lines).encode("utf-8")
