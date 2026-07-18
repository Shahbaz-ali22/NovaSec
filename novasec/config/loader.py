"""
NovaSec Configuration Loader.

Implements the 6-level configuration hierarchy:

    1. CLI flags (applied by commands after loading)
    2. Environment variables   NOVASEC_<SECTION>__<KEY>=value
    3. Project config          ./novasec.yaml
    4. User config             ~/.novasec/config.yaml
    5. System config           /etc/novasec/config.yaml
    6. Built-in defaults       config/defaults.py

Levels 2–6 are handled here. Level 1 is applied by CLI commands using
:meth:`NovaSECConfig.model_copy(update=...)`.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from novasec.config.schema import NovaSECConfig
from novasec.core.exceptions import ConfigNotFoundError, ConfigValidationError

logger = logging.getLogger(__name__)

# Ordered list of config file search paths (lower index = higher precedence)
_CONFIG_SEARCH_PATHS: list[Path] = [
    Path("./novasec.yaml"),                      # Project-local
    Path("./novasec.yml"),
    Path("~/.novasec/config.yaml").expanduser(), # User
    Path("~/.novasec/config.yml").expanduser(),
    Path("/etc/novasec/config.yaml"),            # System
    Path("/etc/novasec/config.yml"),
]


def _load_yaml_file(path: Path) -> dict[str, Any]:
    """Load and parse a YAML file, returning an empty dict if not found."""
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        logger.debug("Loaded config from %s", path)
        return data
    except yaml.YAMLError as e:
        raise ConfigValidationError(
            f"Failed to parse YAML config at {path}: {e}",
            details={"path": str(path)},
        )


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge *override* into *base*, returning a new dict.

    Override values win. Nested dicts are merged recursively.
    """
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(
    config_path: Path | None = None,
    profile: str | None = None,
) -> NovaSECConfig:
    """Load and assemble the NovaSec configuration from all sources.

    Args:
        config_path: Explicit path to a YAML config file. If provided,
                     it takes precedence over the auto-discovered paths.
        profile: Name of a scan profile to apply (e.g. 'stealth').
                 Profile files are looked up in ``config/profiles/``.

    Returns:
        A fully validated :class:`~novasec.config.schema.NovaSECConfig`.

    Raises:
        ConfigNotFoundError: If *config_path* is provided but does not exist.
        ConfigValidationError: If the assembled config fails Pydantic validation.
    """
    # Collect YAML data from all sources (lowest precedence first)
    merged: dict[str, Any] = {}

    if config_path is not None:
        if not config_path.exists():
            raise ConfigNotFoundError(
                f"Specified config file not found: {config_path}",
                details={"path": str(config_path)},
            )
        merged = _deep_merge(merged, _load_yaml_file(config_path))
    else:
        # Auto-discover: search paths in reverse order (lowest prio first)
        for path in reversed(_CONFIG_SEARCH_PATHS):
            data = _load_yaml_file(path)
            if data:
                merged = _deep_merge(merged, data)

    # Apply profile overrides if requested
    if profile:
        profile_data = _load_profile(profile)
        merged = _deep_merge(merged, profile_data)

    # Build Pydantic model (env vars are applied automatically by BaseSettings)
    try:
        config = NovaSECConfig(**merged)
    except ValidationError as e:
        raise ConfigValidationError(
            "Configuration validation failed.",
            details={"errors": e.errors()},
        )

    logger.debug("Configuration loaded successfully (profile=%s)", profile or "default")
    return config


def _load_profile(profile_name: str) -> dict[str, Any]:
    """Load a named scan profile from the profiles directory."""
    # Search in: package-bundled profiles, user profiles
    search_dirs = [
        Path(__file__).parent.parent.parent / "config" / "profiles",
        Path("~/.novasec/profiles").expanduser(),
        Path("./config/profiles"),
    ]
    for directory in search_dirs:
        for ext in ("yaml", "yml"):
            path = directory / f"{profile_name}.{ext}"
            data = _load_yaml_file(path)
            if data:
                logger.info("Applied scan profile: %s (from %s)", profile_name, path)
                return data

    logger.warning("Scan profile '%s' not found — using base config", profile_name)
    return {}


# ---------------------------------------------------------------------------
# Module-level singleton — one config per process
# ---------------------------------------------------------------------------

_config: NovaSECConfig | None = None


def get_config(
    config_path: Path | None = None,
    profile: str | None = None,
    reload: bool = False,
) -> NovaSECConfig:
    """Return the global config singleton, loading it if necessary.

    Args:
        config_path: Optional explicit config file path.
        profile: Optional scan profile name.
        reload: Force re-loading the config even if already cached.
    """
    global _config
    if _config is None or reload:
        _config = load_config(config_path=config_path, profile=profile)
    return _config
