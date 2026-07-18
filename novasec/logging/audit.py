"""
NovaSec Audit Trail Logger.

Records an immutable, append-only audit log of all scan operations.
Each entry captures WHO ran WHAT against WHICH target and WHEN.

The audit log is separate from the application log and is intended
for compliance, forensic replay, and accountability.

Format: JSON Lines (JSONL) — one JSON object per line.
"""

from __future__ import annotations

import getpass
import json
import logging
import platform
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from novasec.core.context import ExecutionContext
    from novasec.reporting.models import FindingSet

logger = logging.getLogger(__name__)

_DEFAULT_AUDIT_LOG = Path("~/.novasec/logs/audit.jsonl").expanduser()


class AuditLogger:
    """Append-only security audit trail.

    Writes structured JSONL records to the audit log file.
    The file is opened and closed for each write to ensure durability.
    """

    def __init__(self, log_path: Path = _DEFAULT_AUDIT_LOG) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        self._hostname = socket.gethostname()
        self._operator = getpass.getuser()
        self._platform = platform.system()

    def _write(self, record: dict[str, Any]) -> None:
        """Append a single JSON record to the audit log."""
        record["_ts"] = datetime.now(UTC).isoformat()
        record["_host"] = self._hostname
        record["_operator"] = self._operator
        record["_platform"] = self._platform

        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")

    def log_scan_started(self, context: "ExecutionContext") -> None:
        """Record the start of a scan operation."""
        self._write(
            {
                "event": "scan.started",
                "scan_id": context.scan_id,
                "target": context.target,
                "profile": context.profile,
                "options": context.options,
            }
        )

    def log_scan_completed(
        self,
        context: "ExecutionContext",
        findings: "FindingSet",
        duration_seconds: float,
    ) -> None:
        """Record the successful completion of a scan."""
        self._write(
            {
                "event": "scan.completed",
                "scan_id": context.scan_id,
                "target": context.target,
                "finding_count": len(findings.findings),
                "severity_summary": findings.severity_summary(),
                "duration_seconds": round(duration_seconds, 2),
            }
        )

    def log_scan_error(
        self,
        context: "ExecutionContext",
        error: Exception,
    ) -> None:
        """Record a scan operation failure."""
        self._write(
            {
                "event": "scan.error",
                "scan_id": context.scan_id,
                "target": context.target,
                "error_type": type(error).__name__,
                "error_message": str(error),
            }
        )

    def log_report_generated(
        self,
        scan_id: str,
        format_name: str,
        output_path: str,
    ) -> None:
        """Record the generation of a scan report."""
        self._write(
            {
                "event": "report.generated",
                "scan_id": scan_id,
                "format": format_name,
                "output_path": output_path,
            }
        )

    def log_config_loaded(self, config_path: str | None) -> None:
        """Record configuration loading."""
        self._write(
            {
                "event": "config.loaded",
                "config_path": config_path or "defaults",
            }
        )


# Module-level singleton
_audit_logger: AuditLogger | None = None


def get_audit_logger(log_path: Path | None = None) -> AuditLogger:
    """Return the global AuditLogger singleton."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(log_path or _DEFAULT_AUDIT_LOG)
    return _audit_logger
