"""
NovaSec Service & Plugin Registry Unit Tests.
"""

from __future__ import annotations

import pytest

from novasec.core.registry import Registry, get_registry
from novasec.core.exceptions import PluginNotFoundError


def test_registry_registration() -> None:
    """Verify scanning and lookup of items inside Registry."""
    reg = Registry()
    
    # Mock plugin scanner class
    class FakePlugin:
        @property
        def manifest(self):
            class Manifest:
                display_name = "Fake Scanner"
                version = "1.0.0"
                category = "scanner"
                description = "Just a test"
                author = "Tester"
            return Manifest()
            
    fake = FakePlugin()
    reg.register_plugin("fake", fake)
    
    assert reg.has_plugin("fake") is True
    assert reg.get_plugin("fake") == fake


def test_nonexistent_plugin() -> None:
    reg = Registry()
    with pytest.raises(PluginNotFoundError):
        reg.get_plugin("nonexistent")
