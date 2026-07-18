"""
NovaSec CLI entry point.

This module wires together the CLI application and initializes the framework
before handing control to Typer. It is the only file that should perform
startup side effects (config loading, logging init, DI container setup).
"""

from novasec.cli.app import app


def main() -> None:
    """Primary entry point invoked by the `novasec` console script."""
    app()


if __name__ == "__main__":
    main()
