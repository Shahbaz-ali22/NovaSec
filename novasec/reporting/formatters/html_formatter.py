"""
NovaSec HTML Report Formatter.

Renders a :class:`~novasec.reporting.models.Report` into an interactive,
visually polished HTML report using Jinja2 templates.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, TemplateError

from novasec.reporting.base import ReporterBase
from novasec.reporting.models import Report

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


class HTMLFormatter(ReporterBase):
    """Formats scan reports as responsive, dynamic HTML pages."""

    def __init__(self, template_dir: Path | None = None) -> None:
        self.template_dir = template_dir or TEMPLATE_DIR
        self._env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True,
        )
        # Register custom template filters
        self._env.filters["severity_color"] = self._filter_severity_color
        self._env.filters["datetime_format"] = self._filter_datetime_format

    @property
    def format_name(self) -> str:
        return "html"

    @property
    def file_extension(self) -> str:
        return ".html"

    def generate(self, report: Report) -> bytes:
        """Render the report to HTML string/bytes."""
        try:
            template = self._env.get_template("executive.html.j2")
            rendered = template.render(
                report=report,
                severity_summary=report.severity_summary(),
                findings=report.findings_by_severity(),
            )
            return rendered.encode("utf-8")
        except TemplateError as e:
            logger.error("Failed to render HTML report template: %s", e)
            raise

    @staticmethod
    def _filter_severity_color(severity: str) -> str:
        colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#0d6efd",
            "INFO": "#0dcaf0",
        }
        return colors.get(severity.upper(), "#6c757d")

    @staticmethod
    def _filter_datetime_format(value: Any, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except ValueError:
                return value
        if hasattr(value, "strftime"):
            return value.strftime(format_str)
        return str(value)
