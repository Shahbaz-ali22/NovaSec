"""String manipulation utilities."""
from __future__ import annotations
import re


def truncate(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate *text* to *max_length* characters, appending *suffix*."""
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from *text*."""
    ansi_escape = re.compile(r"\x1B[@-Z\\-_]|\x1B\[[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", text)


def normalize_url(url: str) -> str:
    """Ensure *url* has an http:// scheme if none is present."""
    if not url.startswith(("http://", "https://")):
        return f"http://{url}"
    return url


def slugify(text: str) -> str:
    """Convert *text* to a URL/filename-safe slug."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", "-", text)
    return text.strip("-")
