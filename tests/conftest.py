"""
NovaSec Test Configuration and Fixtures.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from novasec.config.schema import NovaSECConfig
from novasec.core.context import ExecutionContext, OutputConfig
from novasec.reporting.models import Finding, Severity


@pytest.fixture
def mock_config() -> NovaSECConfig:
    """Return a default clean NovaSECConfig instance."""
    return NovaSECConfig()


@pytest.fixture
def mock_context() -> ExecutionContext:
    """Return a mock ExecutionContext for target testing."""
    return ExecutionContext(
        target="example.com",
        output=OutputConfig(format="plain"),
    )


@pytest.fixture
def mock_findings() -> list[Finding]:
    """Return a collection of findings for reporting tests."""
    return [
        Finding(
            title="Critical SSL Expiry",
            severity=Severity.CRITICAL,
            description="The SSL certificate has expired.",
            target="example.com:443",
            plugin_source="test_plugin",
        ),
        Finding(
            title="Exposed SMTP Banner",
            severity=Severity.INFO,
            description="Port 25 is open displaying software version.",
            target="1.2.3.4:25",
            plugin_source="test_plugin",
        )
    ]
