"""
NovaSec Local File Storage — Infrastructure Layer.

Manages the workspace directory structure and scan result file I/O.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from novasec.core.exceptions import FileStorageError
from novasec.utils.file import ensure_dir, safe_filename

logger = logging.getLogger(__name__)


class LocalStorage:
    """
    Manages the NovaSec workspace directory and scan output files.

    Workspace structure::

        novasec_workspace/
        ├── ns-abc12345/          ← One dir per scan session
        │   ├── metadata.json
        │   ├── findings.json
        │   └── reports/
        │       ├── report.html
        │       └── report.pdf
        └── ...
    """

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        ensure_dir(base_dir)

    def get_session_dir(self, scan_id: str) -> Path:
        """Return (and create if needed) the directory for *scan_id*."""
        session_dir = self.base_dir / safe_filename(scan_id)
        ensure_dir(session_dir)
        return session_dir

    def save_findings_json(self, scan_id: str, data: list[dict[str, Any]]) -> Path:
        """Write findings as JSON to the session directory."""
        session_dir = self.get_session_dir(scan_id)
        output_path = session_dir / "findings.json"
        try:
            output_path.write_text(
                json.dumps(data, indent=2, default=str),
                encoding="utf-8",
            )
            logger.info("Saved %d findings to %s", len(data), output_path)
            return output_path
        except OSError as e:
            raise FileStorageError(
                f"Failed to write findings to {output_path}: {e}"
            )

    def save_report(self, scan_id: str, filename: str, content: bytes) -> Path:
        """Write a report file to the session's reports/ subdirectory."""
        reports_dir = self.get_session_dir(scan_id) / "reports"
        ensure_dir(reports_dir)
        output_path = reports_dir / filename
        try:
            output_path.write_bytes(content)
            logger.info("Saved report to %s", output_path)
            return output_path
        except OSError as e:
            raise FileStorageError(f"Failed to write report to {output_path}: {e}")

    def save_metadata(self, scan_id: str, metadata: dict[str, Any]) -> None:
        """Persist scan metadata as JSON."""
        session_dir = self.get_session_dir(scan_id)
        meta_path = session_dir / "metadata.json"
        metadata["_saved_at"] = datetime.now(UTC).isoformat()
        meta_path.write_text(json.dumps(metadata, indent=2, default=str), encoding="utf-8")

    def list_sessions(self) -> list[str]:
        """Return a list of all scan session IDs in the workspace."""
        return [
            d.name for d in self.base_dir.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        ]
