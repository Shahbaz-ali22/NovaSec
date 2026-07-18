"""
NovaSec Scan Commands.

Defines the `novasec scan` Typer commands.
"""

from __future__ import annotations

import asyncio
import typer
from rich.console import Console

from novasec.core.context import ExecutionContext, OutputConfig
from novasec.core.registry import get_registry
from novasec.domain.recon.port import PortScanner
from novasec.domain.scan.ssl import SSLAnalyzer
from novasec.domain.scan.web import WebScanner
from novasec.cli.middleware.output import display_finding_set

scan_app = typer.Typer(help="Vulnerability and service scanners.")
console = Console()


@scan_app.command("port")
def scan_port(
    target: str = typer.Argument(..., help="IP address or host name."),
    ports: str = typer.Option("1-1024", "--ports", "-p", help="Port range (e.g. 80,443 or 1-65535)"),
    output_format: str = typer.Option("rich", "--format", "-f", help="Output format: rich, json, plain"),
) -> None:
    """Perform quick TCP connect port scan."""
    ctx = ExecutionContext(target=target, output=OutputConfig(format=output_format))
    console.print(f"[bold blue]Scanning ports for:[/bold blue] {target}")
    
    scanner = PortScanner()
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(scanner.scan(target, ports=ports))
    findings = loop.run_until_complete(scanner.to_findings(result, ctx))
    
    display_finding_set(findings, ctx)


@scan_app.command("ssl")
def scan_ssl(
    target: str = typer.Argument(..., help="Target hostname to check."),
    port: int = typer.Option(443, help="Port to query."),
    output_format: str = typer.Option("rich", "--format", "-f", help="Output format: rich, json, plain"),
) -> None:
    """Analyze SSL/TLS certificate health."""
    ctx = ExecutionContext(target=target, output=OutputConfig(format=output_format))
    console.print(f"[bold blue]Analyzing SSL/TLS Configuration for:[/bold blue] {target}:{port}")
    
    analyzer = SSLAnalyzer()
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(analyzer.analyze(target, port=port))
    findings = loop.run_until_complete(analyzer.to_findings(result, target, ctx))
    
    display_finding_set(findings, ctx)


@scan_app.command("web")
def scan_web(
    target: str = typer.Argument(..., help="Target URL (http/https)."),
    output_format: str = typer.Option("rich", "--format", "-f", help="Output format: rich, json, plain"),
) -> None:
    """Analyze HTTP response headers and methods."""
    ctx = ExecutionContext(target=target, output=OutputConfig(format=output_format))
    console.print(f"[bold blue]Scanning Web Headers for:[/bold blue] {target}")
    
    scanner = WebScanner()
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(scanner.scan(target))
    findings = loop.run_until_complete(scanner.to_findings(result, ctx))
    
    display_finding_set(findings, ctx)


@scan_app.command("plugin")
def scan_plugin(
    plugin_name: str = typer.Argument(..., help="Name of registered plugin scanner."),
    target: str = typer.Argument(..., help="Target host/URL."),
    output_format: str = typer.Option("rich", "--format", "-f", help="Output format: rich, json, plain"),
) -> None:
    """Execute a specific registered scanner plugin."""
    registry = get_registry()
    try:
        plugin = registry.get_plugin(plugin_name)
    except KeyError:
        console.print(f"[bold red]Plugin {plugin_name} not found in registry.[/bold red]")
        raise typer.Exit(code=1)

    ctx = ExecutionContext(target=target, output=OutputConfig(format=output_format))
    console.print(f"[bold blue]Running plugin {plugin_name} against:[/bold blue] {target}")

    loop = asyncio.get_event_loop()
    loop.run_until_complete(plugin.setup(ctx))
    findings = loop.run_until_complete(plugin.run(target, ctx))
    loop.run_until_complete(plugin.cleanup())

    display_finding_set(findings, ctx)
