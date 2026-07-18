"""
NovaSec Plugin Base — PluginBase ABC and PluginManifest schema.

Every plugin must:
1. Provide a ``plugin.yaml`` manifest validated by :class:`PluginManifest`
2. Implement a class inheriting :class:`PluginBase`

The framework calls lifecycle methods in this order:
    setup → validate_target → run → cleanup
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from novasec.core.interfaces import IPlugin


class PluginManifest(BaseModel):
    """Pydantic model for the ``plugin.yaml`` manifest file."""

    manifest_version: str = "1"
    name: str = Field(..., pattern=r"^[a-z0-9_\-]+$", description="Unique plugin ID")
    display_name: str
    version: str = Field(..., pattern=r"^\d+\.\d+\.\d+$")
    author: str
    description: str
    category: Literal["scanner", "recon", "exploit", "report", "util"]
    tags: list[str] = Field(default_factory=list)
    entrypoint: str = Field(..., description="Module.ClassName relative to plugin package")
    min_framework_version: str = "1.0.0"
    kali_dependencies: list[str] = Field(default_factory=list)
    python_dependencies: list[str] = Field(default_factory=list)
    config_schema: str | None = None
    permissions: list[str] = Field(default_factory=list)


class PluginBase(IPlugin, ABC):
    """
    Abstract base class for all NovaSec plugins.

    Subclasses must implement ``run``. All other lifecycle methods have
    default no-op implementations that subclasses may override.
    """

    def __init__(self, manifest: PluginManifest) -> None:
        self._manifest = manifest

    @property
    def manifest(self) -> PluginManifest:
        return self._manifest

    @property
    def name(self) -> str:
        return self._manifest.name

    async def setup(self, context: Any) -> None:
        """Default: no setup required. Override to initialize resources."""

    def validate_target(self, target: str) -> bool:
        """Default: accept any non-empty target. Override for specific validation."""
        return bool(target.strip())

    @abstractmethod
    async def run(
        self,
        target: str,
        context: Any,
        **options: Any,
    ) -> Any:
        """Execute the plugin against *target* and return findings."""

    async def cleanup(self) -> None:
        """Default: no cleanup required. Override to release resources."""

    def get_help(self) -> str:
        m = self.manifest
        return (
            f"Plugin: {m.display_name} v{m.version}\n"
            f"Author: {m.author}\n"
            f"Category: {m.category}\n"
            f"Description: {m.description}\n"
            f"Kali deps: {', '.join(m.kali_dependencies) or 'none'}\n"
            f"Permissions: {', '.join(m.permissions) or 'none'}"
        )
