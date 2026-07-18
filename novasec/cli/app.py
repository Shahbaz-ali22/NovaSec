"""
NovaSec CLI Core Application.

Assembles the root Typer CLI application, loads configuration,
setup logging, and dynamically registers all command groups.
"""

from __future__ import annotations

import logging
from pathlib import Path
import typer

from novasec import __version__
from novasec.config.loader import get_config
from novasec.logging.setup import setup_logging
from novasec.core.registry import get_registry
from novasec.plugins.loader import PluginLoader

logger = logging.getLogger(__name__)

# Root Typer App
app = typer.Typer(
    name="novasec",
    help="NovaSec 🛡️ — Modular, production-grade cybersecurity CLI framework.",
    no_args_is_help=True,
)


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"NovaSec Framework v{__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: bool = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True, help="Show version info."
    ),
    config_path: Path = typer.Option(
        None, "--config", "-c", help="Path to custom novasec.yaml configuration file."
    ),
    profile: str = typer.Option(
        None, "--profile", "-p", help="Scan profile preset (stealth, aggressive, bugbounty)."
    ),
) -> None:
    """
    NovaSec framework initialization. Loads config and initializes logs.
    """
    # 1. Load config
    config = get_config(config_path=config_path, profile=profile)

    # 2. Setup logging
    setup_logging(config.logging)
    logger.debug("Logging initialized successfully.")

    # 3. Load plugins into registry
    registry = get_registry()
    loader = PluginLoader(
        registry=registry,
        extra_dirs=config.plugins.extra_plugin_dirs,
        disabled_plugins=config.plugins.disabled_plugins,
    )
    loader.load_all()


# Import and register command groups
from novasec.cli.commands.recon import recon_app
from novasec.cli.commands.scan import scan_app
from novasec.cli.commands.report import report_app
from novasec.cli.commands.plugin import plugin_app
from novasec.cli.commands.config import config_app

app.add_typer(recon_app, name="recon")
app.add_typer(scan_app, name="scan")
app.add_typer(report_app, name="report")
app.add_typer(plugin_app, name="plugin")
app.add_typer(config_app, name="config")
