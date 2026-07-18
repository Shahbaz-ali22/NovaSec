"""
NovaSec ReporterBase — Abstract base for all report formatters.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from novasec.reporting.models import Report


class ReporterBase(ABC):
    """Abstract base for all NovaSec report formatters."""

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Machine-readable format identifier (e.g. 'json', 'html', 'pdf')."""

    @property
    @abstractmethod
    def file_extension(self) -> str:
        """File extension including leading dot (e.g. '.json', '.html')."""

    @abstractmethod
    def generate(self, report: "Report") -> bytes:
        """Serialise *report* and return raw bytes."""

    def write_to_file(self, report: "Report", output_path: str | Path) -> Path:
        """Write report to *output_path* and return the written path."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.generate(report)
        path.write_bytes(data)
        return path
