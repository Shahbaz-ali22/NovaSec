"""
NovaSec Reconnaissance Commands.

Defines the `novasec recon` Typer commands.
"""

from __future__ import annotations

import asyncio
import typer
from rich.console import Console

from novasec.core.context import ExecutionContext, OutputConfig
from novasec.domain.recon.dns import DNSEnumerator
from novasec.domain.recon.subdomain import SubdomainEnumerator
from novasec.domain.recon.whois import WhoisLookup
from novasec.cli.middleware.output import display_finding_set

recon_app = typer.Typer(help="Passive and active target reconnaissance.")
console = Console()


@recon_app.command("dns")
def recon_dns(
    target: str = typer.Argument(..., help="Domain name or host to query."),
    output_format: str = typer.Option("rich", "--format", "-f", help="Output format: rich, json, plain"),
) -> None:
    """Perform comprehensive DNS enumeration."""
    ctx = ExecutionContext(target=target, output=OutputConfig(format=output_format))
    
    console.print(f"[bold blue]Starting DNS Recon against target:[/bold blue] {target}")
    
    enumerator = DNSEnumerator()
    
    # Run async function in event loop
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(enumerator.enumerate(target))
    findings = loop.run_until_complete(enumerator.to_findings(result, ctx))
    
    display_finding_set(findings, ctx)


@recon_app.command("subdomain")
def recon_subdomain(
    target: str = typer.Argument(..., help="Root domain to enumerate."),
    output_format: str = typer.Option("rich", "--format", "-f", help="Output format: rich, json, plain"),
) -> None:
    """Enumerate subdomains using built-in wordlist & crt.sh."""
    ctx = ExecutionContext(target=target, output=OutputConfig(format=output_format))
    console.print(f"[bold blue]Starting Subdomain Discovery against:[/bold blue] {target}")
    
    enumerator = SubdomainEnumerator()
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(enumerator.enumerate(target))
    findings = loop.run_until_complete(enumerator.to_findings(result, target, ctx))
    
    display_finding_set(findings, ctx)


@recon_app.command("whois")
def recon_whois(
    target: str = typer.Argument(..., help="Domain name or IP address."),
    output_format: str = typer.Option("rich", "--format", "-f", help="Output format: rich, json, plain"),
) -> None:
    """Execute WHOIS data lookup."""
    ctx = ExecutionContext(target=target, output=OutputConfig(format=output_format))
    console.print(f"[bold blue]Starting WHOIS Query against:[/bold blue] {target}")
    
    lookup = WhoisLookup()
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(lookup.query(target))
    findings = loop.run_until_complete(lookup.to_findings(result, ctx))
    
    display_finding_set(findings, ctx)
