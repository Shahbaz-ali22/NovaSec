"""NovaSec log formatters — Rich console and JSON file."""
from __future__ import annotations
import json
import logging
from datetime import datetime
from typing import Any


def build_console_formatter() -> logging.Formatter:
    """Return a Rich-aware log formatter for terminal output."""
    try:
        import structlog
        return structlog.stdlib.ProcessorFormatter(
            processor=structlog.dev.ConsoleRenderer(colors=True),
        )
    except ImportError:
        return logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter for machine-readable file output."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict[str, Any] = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        # Include any extra fields bound via structlog contextvars
        for key, value in record.__dict__.items():
            if key not in logging.LogRecord.__dict__ and not key.startswith("_"):
                log_obj[key] = value
        return json.dumps(log_obj, default=str)
