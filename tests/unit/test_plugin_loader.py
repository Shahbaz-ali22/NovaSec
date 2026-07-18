"""
NovaSec Plugin Loader Unit Tests.
"""

from __future__ import annotations

import pytest
from pathlib import Path

from novasec.core.registry import Registry
from novasec.plugins.loader import PluginLoader


def test_builtin_plugins_discovered() -> None:
    """Verify standard bundled plugins are indexed during startup scanning."""
    reg = Registry()
    loader = PluginLoader(registry=reg)
    
    # Run dynamic scanner
    count = loader.load_all()
    
    # We should have found at least nmap, nikto, ffuf, nuclei wrappers
    assert count >= 4
    assert reg.has_plugin("nmap_wrapper") is True
    assert reg.has_plugin("nikto_wrapper") is True
    assert reg.has_plugin("ffuf_wrapper") is True
    assert reg.has_plugin("nuclei_wrapper") is True
