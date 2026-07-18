"""
NovaSec Logging Setup.

Initializes structlog with:
- Rich console handler for interactive terminal use
- JSON file handler for machine-readable logs
- Separate append-only audit log for compliance

Call ``setup_logging()`` once during framework startup (in ``app.py``).
"""

from __future__ import annotations

import logging
import logging.config
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from novasec.config.schema import LoggingConfig


def setup_logging(config: "LoggingConfig") -> None:
    """Configure the NovaSec logging infrastructure.

    Must be called once at framework startup before any log calls are made.

    Args:
        config: The logging section of the NovaSec config.
    """
    log_level = getattr(logging, config.level.upper(), logging.INFO)

    # Shared processors for all renderers
    shared_processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    # Configure structlog
    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Build handlers
    handlers: dict[str, dict] = {
        "console": _build_console_handler(config),
    }

    if config.log_file:
        config.log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers["file"] = _build_file_handler(config)

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "console": {
                    "()": "novasec.logging.formatters.build_console_formatter",
                },
                "json": {
                    "()": "novasec.logging.formatters.JSONFormatter",
                },
            },
            "handlers": handlers,
            "root": {
                "handlers": list(handlers.keys()),
                "level": log_level,
            },
            "loggers": {
                # Silence noisy third-party loggers
                "httpx": {"level": "WARNING"},
                "httpcore": {"level": "WARNING"},
                "urllib3": {"level": "WARNING"},
            },
        }
    )


def _build_console_handler(config: "LoggingConfig") -> dict:
    """Build console handler config — Rich or plain based on format setting."""
    from novasec.logging.formatters import build_console_formatter

    return {
        "class": "logging.StreamHandler",
        "stream": "ext://sys.stderr",
        "formatter": "console",
    }


def _build_file_handler(config: "LoggingConfig") -> dict:
    """Build rotating JSON file handler config."""
    return {
        "class": "logging.handlers.RotatingFileHandler",
        "filename": str(config.log_file),
        "maxBytes": config.rotate_max_bytes,
        "backupCount": config.rotate_backup_count,
        "encoding": "utf-8",
        "formatter": "json",
    }
