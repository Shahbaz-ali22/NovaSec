"""
NovaSec Configuration Validator.

Business-level configuration validation that goes beyond what Pydantic
field constraints can express. These checks are run after the Pydantic
model is constructed successfully.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from novasec.config.schema import NovaSECConfig
from novasec.core.exceptions import ConfigValidationError

logger = logging.getLogger(__name__)


def validate_config(config: NovaSECConfig) -> list[str]:
    """Run all business-level validation rules on *config*.

    Returns:
        A list of warning strings (non-fatal issues). Raises
        :class:`ConfigValidationError` for fatal issues.
    """
    warnings: list[str] = []

    _check_output_dir_writable(config, warnings)
    _check_api_keys_format(config, warnings)
    _check_rate_limit_sanity(config, warnings)
    _check_exploit_safety(config)

    return warnings


def _check_output_dir_writable(config: NovaSECConfig, warnings: list[str]) -> None:
    """Warn if the output directory cannot be created or written to."""
    output_dir = config.general.output_dir
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        warnings.append(
            f"Output directory {output_dir} is not writable. "
            "Scan results may not be saved."
        )


def _check_api_keys_format(config: NovaSECConfig, warnings: list[str]) -> None:
    """Warn if API keys look malformed (too short / obviously placeholder)."""
    placeholder_patterns = [
        r"^your[-_]",
        r"^xxx",
        r"^changeme",
        r"^placeholder",
        r"^<.*>$",
    ]

    def looks_like_placeholder(key: str) -> bool:
        key_lower = key.lower()
        return any(re.match(p, key_lower) for p in placeholder_patterns)

    apis = config.apis
    if apis.shodan_key:
        raw = apis.shodan_key.get_secret_value()
        if len(raw) < 10 or looks_like_placeholder(raw):
            warnings.append("Shodan API key looks invalid — Shodan features will fail.")

    if apis.virustotal_key:
        raw = apis.virustotal_key.get_secret_value()
        if len(raw) < 32 or looks_like_placeholder(raw):
            warnings.append("VirusTotal API key looks invalid (expected 64-char hex).")


def _check_rate_limit_sanity(config: NovaSECConfig, warnings: list[str]) -> None:
    """Warn if rate limit seems dangerously high for the active profile."""
    rate = config.network.rate_limit
    if config.scan.stealth_mode and rate > 5:
        warnings.append(
            f"Rate limit {rate} req/s may be too high for stealth mode. "
            "Consider setting network.rate_limit <= 5."
        )
    elif rate > 500:
        warnings.append(
            f"Rate limit of {rate} req/s is very high — ensure the target "
            "can handle this load and you have authorization."
        )


def _check_exploit_safety(config: NovaSECConfig) -> None:
    """Raise if exploit mode is enabled without safe_mode."""
    if config.exploit.enabled and not config.exploit.safe_mode:
        raise ConfigValidationError(
            "exploit.safe_mode cannot be disabled without explicit override. "
            "Enabling live exploit execution without safe mode is dangerous. "
            "Set exploit.safe_mode=false ONLY if you understand the implications.",
            details={"exploit_config": config.exploit.model_dump()},
        )
