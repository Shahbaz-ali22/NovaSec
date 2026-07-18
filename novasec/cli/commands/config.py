"""
NovaSec Configuration Commands.

Defines the `novasec config` Typer commands.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.syntax import Syntax

from novasec.config.loader import get_config

config_app = typer.Typer(help="View and validate configurations.")
console = Console()


@config_app.command("show")
def config_show() -> None:
    """Display the active configuration (resolved hierarchy & defaults)."""
    config = get_config()
    
    # Dump configuration back to YAML style layout
    import yaml
    dumped = yaml.dump(config.model_dump(mode="json"), default_flow_style=False)
    
    syntax = Syntax(dumped, "yaml", theme="monokai", line_numbers=True)
    console.print(syntax)


@config_app.command("validate")
def config_validate() -> None:
    """Run business validation rules against the current config."""
    config = get_config()
    
    from novasec.config.validator import validate_config
    try:
        warnings = validate_config(config)
        if warnings:
            console.print("[bold yellow]Configuration validated with warnings:[/bold yellow]")
            for w in warnings:
                console.print(f"- {w}")
        else:
            console.print("[bold green]Configuration is fully valid and optimized![/bold green]")
    except Exception as e:
        console.print(f"[bold red]Configuration validation failed: {e}[/bold red]")
        raise typer.Exit(code=1)
