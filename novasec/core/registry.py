"""
NovaSec Plugin & Service Registry.

The ``Registry`` is the single authoritative catalog of all plugins, scanners,
and services registered with the framework. It is a lightweight service
locator — components announce themselves here during startup, and CLI commands
resolve them by name or category.

Thread Safety: The registry uses a simple lock-free design since all
registrations happen during the synchronous startup phase, before any async
scan operations begin. Do not register plugins from async contexts.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from novasec.core.exceptions import PluginNotFoundError

if TYPE_CHECKING:
    from novasec.core.interfaces import IPlugin, IReporter, IScanner

logger = logging.getLogger(__name__)


class Registry:
    """Central catalog for plugins, scanners, and reporters.

    Usage::

        registry = Registry()
        registry.register_plugin("nmap_wrapper", my_plugin_instance)
        plugin = registry.get_plugin("nmap_wrapper")
    """

    def __init__(self) -> None:
        self._plugins: dict[str, "IPlugin"] = {}
        self._scanners: dict[str, "IScanner"] = {}
        self._reporters: dict[str, "IReporter"] = {}

    # ------------------------------------------------------------------
    # Plugins
    # ------------------------------------------------------------------

    def register_plugin(self, name: str, plugin: "IPlugin") -> None:
        """Register a plugin instance under *name*."""
        if name in self._plugins:
            logger.warning("Plugin %r is being overwritten in the registry", name)
        self._plugins[name] = plugin
        logger.debug("Registered plugin: %s", name)

    def get_plugin(self, name: str) -> "IPlugin":
        """Return the plugin registered under *name*.

        Raises:
            PluginNotFoundError: If no plugin with *name* exists.
        """
        try:
            return self._plugins[name]
        except KeyError:
            raise PluginNotFoundError(
                f"No plugin named {name!r} is registered.",
                details={"available": list(self._plugins.keys())},
            )

    def list_plugins(
        self, category: str | None = None
    ) -> list[dict[str, Any]]:
        """Return a list of plugin info dicts, optionally filtered by *category*."""
        results = []
        for name, plugin in self._plugins.items():
            manifest = plugin.manifest
            if category is not None and manifest.category != category:
                continue
            results.append(
                {
                    "name": name,
                    "display_name": manifest.display_name,
                    "version": manifest.version,
                    "category": manifest.category,
                    "description": manifest.description,
                    "author": manifest.author,
                }
            )
        return results

    def has_plugin(self, name: str) -> bool:
        """Return True if a plugin with *name* is registered."""
        return name in self._plugins

    # ------------------------------------------------------------------
    # Scanners (domain-layer scanners, distinct from plugins)
    # ------------------------------------------------------------------

    def register_scanner(self, name: str, scanner: "IScanner") -> None:
        """Register a domain scanner under *name*."""
        self._scanners[name] = scanner
        logger.debug("Registered scanner: %s", name)

    def get_scanner(self, name: str) -> "IScanner":
        """Return the scanner registered under *name*.

        Raises:
            PluginNotFoundError: If no scanner with *name* exists.
        """
        try:
            return self._scanners[name]
        except KeyError:
            raise PluginNotFoundError(
                f"No scanner named {name!r} is registered.",
                details={"available": list(self._scanners.keys())},
            )

    def list_scanners(self) -> list[str]:
        """Return a list of all registered scanner names."""
        return list(self._scanners.keys())

    # ------------------------------------------------------------------
    # Reporters
    # ------------------------------------------------------------------

    def register_reporter(self, format_name: str, reporter: "IReporter") -> None:
        """Register a report formatter under *format_name* (e.g. 'html')."""
        self._reporters[format_name] = reporter
        logger.debug("Registered reporter: %s", format_name)

    def get_reporter(self, format_name: str) -> "IReporter":
        """Return the reporter for *format_name*.

        Raises:
            PluginNotFoundError: If no reporter for *format_name* exists.
        """
        try:
            return self._reporters[format_name]
        except KeyError:
            raise PluginNotFoundError(
                f"No reporter for format {format_name!r}.",
                details={"available": list(self._reporters.keys())},
            )

    def list_reporters(self) -> list[str]:
        """Return all registered report format names."""
        return list(self._reporters.keys())

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def summary(self) -> dict[str, int]:
        """Return a count summary of all registered components."""
        return {
            "plugins": len(self._plugins),
            "scanners": len(self._scanners),
            "reporters": len(self._reporters),
        }

    def __repr__(self) -> str:
        s = self.summary()
        return (
            f"Registry(plugins={s['plugins']}, "
            f"scanners={s['scanners']}, "
            f"reporters={s['reporters']})"
        )


# ---------------------------------------------------------------------------
# Module-level singleton — shared across the entire framework process
# ---------------------------------------------------------------------------

_registry: Registry | None = None


def get_registry() -> Registry:
    """Return the global Registry singleton."""
    global _registry
    if _registry is None:
        _registry = Registry()
    return _registry
