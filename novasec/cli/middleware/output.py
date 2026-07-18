"""
NovaSec CLI Output Middleware.

Interprets the user-negotiated output configuration format
and presents the resulting findings inside the terminal.
"""

from __future__ import annotations

import json
from rich.console import Console
from rich.table import Table

from novasec.reporting.models import FindingSet
from novasec.core.context import ExecutionContext

console = Console()


def display_finding_set(finding_set: FindingSet, context: ExecutionContext) -> None:
    """Present findings to terminal in requested formats (rich, json, plain)."""
    fmt = context.output.format.lower()
    
    if fmt == "json":
        # Raw JSON output
        print(json.dumps(finding_set.model_dump(mode="json"), indent=2, default=str))
        return

    if fmt == "plain":
        # Simple plain-text listings
        for f in finding_set.findings:
            print(f"[{f.severity.value}] {f.title} - Target: {f.target}")
            if f.remediation:
                print(f"  Remediation: {f.remediation}")
        return

    # Default 'rich' layout formatting
    if not finding_set.findings:
        console.print("[bold green]No security vulnerabilities or warnings found![/bold green]")
        return

    table = Table(title=f"Scan Findings for {finding_set.target or 'Session'}")
    table.add_column("Severity", justify="center")
    table.add_column("Title", style="cyan")
    table.add_column("Target Exposed", style="magenta")
    table.add_column("Plugin Source", style="dim")
    
    # Sort findings by severity
    for f in finding_set.by_severity():
        sev_str = f.severity.value
        sev_color = f.severity.color
        table.add_row(
            f"[{sev_color}]{sev_str}[/{sev_color}]",
            f.title,
            f.target,
            f.plugin_source
        )

    console.print(table)
    
    # Optional summary block
    summary = finding_set.severity_summary()
    summary_str = ", ".join(f"{k}: {v}" for k, v in summary.items())
    console.print(f"\n[bold]Summary counts:[/bold] {summary_str}")
