"""
NovaSec PDF Report Formatter.

Converts HTML report bytes to PDF via WeasyPrint.
"""

from __future__ import annotations

import logging
from novasec.reporting.base import ReporterBase
from novasec.reporting.models import Report
from novasec.reporting.formatters.html_formatter import HTMLFormatter

logger = logging.getLogger(__name__)


class PDFFormatter(ReporterBase):
    """Formats scan reports as printable PDFs via HTML compilation."""

    @property
    def format_name(self) -> str:
        return "pdf"

    @property
    def file_extension(self) -> str:
        return ".pdf"

    def generate(self, report: Report) -> bytes:
        """Render the report to HTML first, then compile to PDF."""
        try:
            from weasyprint import HTML
        except ImportError:
            logger.error("weasyprint package not installed: pip install weasyprint")
            raise ImportError("weasyprint is required for PDF report generation.")

        html_formatter = HTMLFormatter()
        html_content = html_formatter.generate(report).decode("utf-8")
        
        # Compile HTML string to PDF bytes in memory
        pdf_bytes = HTML(string=html_content).write_pdf()
        return pdf_bytes
