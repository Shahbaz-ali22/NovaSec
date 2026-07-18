"""
NovaSec Plugin Loader.

Discovers, validates, imports, and instantiates plugins from:
1. novasec/plugins/builtin/       (first-party)
2. plugins_external/              (community, configurable path)
3. ~/.novasec/plugins/            (user-installed)
4. config.plugins.extra_plugin_dirs

Each plugin directory must contain a ``plugin.yaml`` manifest file.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from pydantic import ValidationError

from novasec.core.exceptions import PluginLoadError, PluginValidationError
from novasec.plugins.base import PluginBase, PluginManifest
from novasec.plugins.validator import PluginSafetyValidator

if TYPE_CHECKING:
    from novasec.core.registry import Registry

logger = logging.getLogger(__name__)

# Built-in plugins directory (relative to this file)
BUILTIN_PLUGINS_DIR = Path(__file__).parent / "builtin"

# User plugin directory
USER_PLUGINS_DIR = Path("~/.novasec/plugins").expanduser()

# Repo-level external plugins directory
EXTERNAL_PLUGINS_DIR = Path(__file__).parent.parent.parent / "plugins_external"


class PluginLoader:
    """
    Discovers and loads NovaSec plugins from the file system.

    Usage::

        loader = PluginLoader(registry=get_registry())
        count = await loader.load_all()
        print(f"Loaded {count} plugins")
    """

    def __init__(
        self,
        registry: "Registry",
        extra_dirs: list[Path] | None = None,
        disabled_plugins: list[str] | None = None,
    ) -> None:
        self.registry = registry
        self.extra_dirs = extra_dirs or []
        self.disabled_plugins = set(disabled_plugins or [])
        self._validator = PluginSafetyValidator()

    def load_all(self, disabled: list[str] | None = None) -> int:
        """Discover and load all plugins from all configured directories.

        Returns:
            Number of successfully loaded plugins.
        """
        if disabled:
            self.disabled_plugins.update(disabled)

        search_dirs = [
            BUILTIN_PLUGINS_DIR,
            EXTERNAL_PLUGINS_DIR,
            USER_PLUGINS_DIR,
            *self.extra_dirs,
        ]

        loaded = 0
        for directory in search_dirs:
            if not directory.exists():
                continue
            loaded += self._load_from_directory(directory)

        logger.info("Plugin loading complete: %d plugins loaded", loaded)
        return loaded

    def _load_from_directory(self, directory: Path) -> int:
        """Scan *directory* for plugin subdirectories and load each one."""
        loaded = 0
        for plugin_dir in directory.iterdir():
            if not plugin_dir.is_dir():
                continue
            manifest_path = plugin_dir / "plugin.yaml"
            if not manifest_path.exists():
                continue
            try:
                self._load_plugin(plugin_dir, manifest_path)
                loaded += 1
            except (PluginLoadError, PluginValidationError) as e:
                logger.warning("Skipped plugin %s: %s", plugin_dir.name, e)
            except Exception as e:
                logger.error("Unexpected error loading plugin %s: %s", plugin_dir.name, e)
        return loaded

    def _load_plugin(self, plugin_dir: Path, manifest_path: Path) -> PluginBase:
        """Load a single plugin from *plugin_dir*.

        Steps:
            1. Parse and validate plugin.yaml → PluginManifest
            2. Check if plugin is disabled
            3. Run safety validation
            4. Import the entrypoint module
            5. Instantiate the plugin class
            6. Register in the registry
        """
        # Step 1: Parse manifest
        manifest = self._parse_manifest(manifest_path)

        # Step 2: Check if disabled
        if manifest.name in self.disabled_plugins:
            logger.debug("Skipping disabled plugin: %s", manifest.name)
            return  # type: ignore[return-value]

        # Step 3: Safety validation
        self._validator.validate(manifest, plugin_dir)

        # Step 4: Import entrypoint module
        module_name, class_name = manifest.entrypoint.rsplit(".", 1)
        plugin_module = self._import_module(plugin_dir, module_name)

        # Step 5: Instantiate
        if not hasattr(plugin_module, class_name):
            raise PluginLoadError(
                f"Class {class_name!r} not found in {module_name!r}",
                details={"plugin": manifest.name, "module": module_name},
            )
        plugin_class = getattr(plugin_module, class_name)
        plugin_instance: PluginBase = plugin_class(manifest)

        # Step 6: Register
        self.registry.register_plugin(manifest.name, plugin_instance)
        logger.info(
            "Loaded plugin: %s v%s [%s]",
            manifest.display_name, manifest.version, manifest.category,
        )
        return plugin_instance

    def _parse_manifest(self, manifest_path: Path) -> PluginManifest:
        """Parse and validate a plugin.yaml file."""
        try:
            with manifest_path.open("r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise PluginValidationError(
                f"Invalid YAML in {manifest_path}: {e}",
                details={"path": str(manifest_path)},
            )

        try:
            return PluginManifest(**raw)
        except ValidationError as e:
            raise PluginValidationError(
                f"Manifest validation failed for {manifest_path.parent.name}: {e}",
                details={"errors": e.errors()},
            )

    def _import_module(self, plugin_dir: Path, module_name: str) -> object:
        """Dynamically import *module_name* from *plugin_dir*."""
        module_path = plugin_dir / f"{module_name}.py"
        if not module_path.exists():
            raise PluginLoadError(
                f"Module file not found: {module_path}",
                details={"module": module_name, "plugin_dir": str(plugin_dir)},
            )

        spec = importlib.util.spec_from_file_location(
            f"novasec_plugin_{plugin_dir.name}.{module_name}",
            module_path,
        )
        if spec is None or spec.loader is None:
            raise PluginLoadError(f"Cannot create module spec for {module_path}")

        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except Exception as e:
            raise PluginLoadError(
                f"Module execution failed: {e}",
                details={"module": module_name, "error": str(e)},
            )
        return module
