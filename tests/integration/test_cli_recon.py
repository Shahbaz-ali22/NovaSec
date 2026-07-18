"""
NovaSec CLI Integration Tests.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from novasec.cli.app import app

runner = CliRunner()


def test_cli_help() -> None:
    """Verify that root cli app prints help and exits normally."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Usage: novasec" in result.stdout
    assert "Passive and active target reconnaissance" in result.stdout


def test_cli_config_show() -> None:
    """Verify that config show displays current config settings."""
    result = runner.invoke(app, ["config", "show"])
    assert result.exit_code == 0
    assert "general:" in result.stdout
    assert "network:" in result.stdout


def test_cli_plugin_list() -> None:
    """Verify listing plugins is working."""
    result = runner.invoke(app, ["plugin", "list"])
    assert result.exit_code == 0
    assert "Registered Plugins" in result.stdout
    assert "nmap_wrapper" in result.stdout
