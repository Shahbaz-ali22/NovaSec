"""NovaSec custom log handlers."""
from __future__ import annotations
import logging
import logging.handlers
from pathlib import Path


def get_rotating_file_handler(
    log_path: Path,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
) -> logging.handlers.RotatingFileHandler:
    """Return a RotatingFileHandler writing JSON logs to *log_path*."""
    from novasec.logging.formatters import JSONFormatter

    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        filename=str(log_path),
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setFormatter(JSONFormatter())
    return handler
