"""
NovaSec Configuration Unit Tests.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from novasec.config.schema import NovaSECConfig, GeneralConfig, NetworkConfig
from novasec.config.loader import load_config


def test_config_defaults(mock_config: NovaSECConfig) -> None:
    """Verify built-in validation defaults are mapped properly."""
    assert mock_config.general.max_threads == 10
    assert mock_config.network.timeout == 30
    assert mock_config.exploit.enabled is False
    assert mock_config.exploit.safe_mode is True


def test_invalid_thread_count() -> None:
    """Check constraints on max_threads range."""
    with pytest.raises(ValidationError):
        GeneralConfig(max_threads=0)  # ge=1 constraint

    with pytest.raises(ValidationError):
        GeneralConfig(max_threads=300)  # le=200 constraint


def test_invalid_proxy_url() -> None:
    """Verify validation rule for proxy URLs."""
    with pytest.raises(ValidationError):
        NetworkConfig(proxy="ftp://127.0.0.1:21")
