"""
NovaSec Plugin Commands.

Defines the `novasec plugin` Typer commands.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from novasec.core.registry import get_registry

plugin_app = typer.Typer(help="Manage and inspect plugins.")
console = Console()


@plugin_app.command("list")
def plugin_list(
    category: str = typer.Option(None, "--category", "-c", help="Filter by category (scanner, recon, exploit, report)")
) -> None:
    """List all registered plugins."""
    registry = get_registry()
    plugins = registry.list_plugins(category=category)
    
    if not plugins:
        console.print("[yellow]No plugins registered matching criteria.[/yellow]")
        return
        
    table = Table(title="Registered Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Display Name", style="white")
    table.add_column("Version", style="magenta")
    table.add_column("Category", style="green")
    table.add_column("Description", style="dim")
    
    for p in plugins:
        table.add_row(
            p["name"],
            p["display_name"],
            p["version"],
            p["category"],
            p["description"][:60] + "..." if len(p["description"]) > 60 else p["description"]
        )
        
    console.print(table)


@plugin_app.command("info")
def plugin_info(
    name: str = typer.Argument(..., help="Name of the plugin to inspect.")
) -> None:
    """Display usage, permissions, and dependencies for a plugin."""
    registry = get_registry()
    try:
        plugin = registry.get_plugin(name)
    except KeyError:
        console.print(f"[bold red]Plugin '{name}' not found.[/bold red]")
        raise typer.Exit(code=1)
        
    console.print(plugin.get_help())
