"""
NovaSec SQLite Session Database — Infrastructure Layer.

Persists scan sessions and findings using SQLModel (SQLAlchemy + Pydantic).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ScanDatabase:
    """
    SQLite-backed session persistence.

    Stores scan session metadata for later retrieval, reporting, and delta comparison.
    Uses raw JSON storage for maximum portability without requiring SQLModel at runtime.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database schema."""
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    operator TEXT,
                    profile TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    finding_count INTEGER DEFAULT 0,
                    data_json TEXT
                )
            """)
            conn.commit()

    def save_session(self, scan_id: str, target: str, data: dict[str, Any]) -> None:
        """Persist a scan session record."""
        import json
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_sessions
                (scan_id, target, operator, profile, started_at, completed_at, finding_count, data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    target,
                    data.get("operator", ""),
                    data.get("profile", "default"),
                    data.get("started_at", datetime.now(UTC).isoformat()),
                    data.get("completed_at"),
                    data.get("finding_count", 0),
                    json.dumps(data, default=str),
                ),
            )
            conn.commit()

    def get_sessions(self) -> list[dict[str, Any]]:
        """Return all scan session records."""
        import json
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM scan_sessions ORDER BY started_at DESC"
            ).fetchall()
            return [dict(row) for row in rows]

    def get_session(self, scan_id: str) -> dict[str, Any] | None:
        """Return a single session by scan_id."""
        import json
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM scan_sessions WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            return dict(row) if row else None
