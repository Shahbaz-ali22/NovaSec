"""
NovaSec Report Commands.

Defines the `novasec report` Typer commands.
"""

from __future__ import annotations

import json
from pathlib import Path
import typer
from rich.console import Console

from novasec.reporting.models import Report, ScanMetadata, Finding, Severity
from novasec.reporting.formatters.json_formatter import JSONFormatter
from novasec.reporting.formatters.html_formatter import HTMLFormatter
from novasec.reporting.formatters.markdown_formatter import MarkdownFormatter
from novasec.reporting.formatters.csv_formatter import CSVFormatter

report_app = typer.Typer(help="Generate reports from scan outputs.")
console = Console()


@report_app.command("generate")
def report_generate(
    input_file: Path = typer.Option(..., "--input", "-i", help="Path to findings.json or raw output."),
    output_file: Path = typer.Option(..., "--output", "-o", help="Path to write the generated report."),
    format_name: str = typer.Option("html", "--format", "-f", help="Output format: html, json, markdown, csv"),
    title: str = typer.Option("NovaSec Security Assessment", help="Report Title"),
) -> None:
    """Generate a formal report from a raw findings.json input file."""
    if not input_file.exists():
        console.print(f"[bold red]Input file not found:[/bold red] {input_file}")
        raise typer.Exit(code=1)

    try:
        raw_data = json.loads(input_file.read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[bold red]Failed to load input file as JSON:[/bold red] {e}")
        raise typer.Exit(code=1)

    # Reconstruct report objects from inputs
    metadata = ScanMetadata(
        scan_id=raw_data.get("scan_id", "imported"),
        target=raw_data.get("target", "unknown"),
        started_at=raw_data.get("scanned_at") or raw_data.get("started_at") or "2026-07-18T00:00:00Z",
        plugins_used=[raw_data.get("plugin_source", "imported")],
    )

    findings = []
    raw_findings = raw_data.get("findings", [])
    if isinstance(raw_data, list):
        raw_findings = raw_data

    for rf in raw_findings:
        findings.append(
            Finding(
                title=rf.get("title", "Discovered Vulnerability"),
                severity=Severity(rf.get("severity", "INFO")),
                description=rf.get("description", ""),
                target=rf.get("target", ""),
                plugin_source=rf.get("plugin_source", ""),
                remediation=rf.get("remediation", ""),
                impact=rf.get("impact", ""),
            )
        )

    report = Report(
        title=title,
        metadata=metadata,
        findings=findings,
    )
    report.risk_score = report.calculate_risk_score()

    # Formatter Factory selection
    format_lower = format_name.lower()
    if format_lower == "json":
        formatter = JSONFormatter()
    elif format_lower == "html":
        formatter = HTMLFormatter()
    elif format_lower == "markdown":
        formatter = MarkdownFormatter()
    elif format_lower == "csv":
        formatter = CSVFormatter()
    else:
        console.print(f"[bold red]Unsupported format name:[/bold red] {format_name}")
        raise typer.Exit(code=1)

    try:
        formatter.write_to_file(report, output_file)
        console.print(f"[bold green]Report successfully generated at:[/bold green] {output_file}")
    except Exception as e:
        console.print(f"[bold red]Failed to write report file:[/bold red] {e}")
        raise typer.Exit(code=1)
