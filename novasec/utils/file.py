"""File path and I/O utility functions."""
from __future__ import annotations
import hashlib
from pathlib import Path


def ensure_dir(path: Path) -> Path:
    """Create *path* (and parents) if it doesn't exist. Return *path*."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def file_sha256(path: Path) -> str:
    """Compute SHA-256 hash of *path*'s contents."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_filename(name: str) -> str:
    """Sanitize *name* for use as a filename."""
    import re
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    return name.strip(". ")[:200] or "unnamed"
