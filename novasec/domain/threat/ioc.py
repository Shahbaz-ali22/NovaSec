"""
NovaSec IOC Extraction and Classification — Domain Layer.

Extracts and classifies Indicators of Compromise (IOCs) from raw text:
- IPv4/IPv6 addresses
- Domain names
- URLs
- File hashes (MD5, SHA1, SHA256)
- Email addresses
- CVE identifiers
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class IOCType(str, Enum):
    """IOC classification types."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    MD5_HASH = "md5_hash"
    SHA1_HASH = "sha1_hash"
    SHA256_HASH = "sha256_hash"
    EMAIL = "email"
    CVE = "cve"


@dataclass
class IOC:
    """A single extracted indicator of compromise."""
    type: IOCType
    value: str
    context: str = ""  # Surrounding text snippet


# Regex patterns for IOC extraction
_PATTERNS: dict[IOCType, str] = {
    IOCType.CVE: r"CVE-\d{4}-\d{4,7}",
    IOCType.SHA256_HASH: r"\b[a-fA-F0-9]{64}\b",
    IOCType.SHA1_HASH: r"\b[a-fA-F0-9]{40}\b",
    IOCType.MD5_HASH: r"\b[a-fA-F0-9]{32}\b",
    IOCType.URL: r"https?://(?:[^\s\"\'\)>]+)",
    IOCType.EMAIL: r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
    IOCType.IP_ADDRESS: (
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    IOCType.DOMAIN: (
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+[a-zA-Z]{2,}\b"
    ),
}

# Private / reserved IP ranges to exclude from IP IOCs
_PRIVATE_IP_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^0\."),
    re.compile(r"^169\.254\."),
]


def extract_iocs(text: str, include_private_ips: bool = False) -> list[IOC]:
    """Extract all IOCs from *text*.

    Args:
        text: Raw text to scan for IOCs.
        include_private_ips: If False (default), private/reserved IP
                             addresses are excluded from results.

    Returns:
        List of :class:`IOC` objects, deduplicated by (type, value).
    """
    found: list[IOC] = []
    seen: set[tuple[IOCType, str]] = set()

    for ioc_type, pattern in _PATTERNS.items():
        for match in re.finditer(pattern, text, re.IGNORECASE):
            value = match.group(0)

            # Exclude private IPs unless requested
            if ioc_type == IOCType.IP_ADDRESS and not include_private_ips:
                if any(p.match(value) for p in _PRIVATE_IP_RANGES):
                    continue

            key = (ioc_type, value.lower())
            if key in seen:
                continue
            seen.add(key)

            # Extract a small context window
            start = max(0, match.start() - 30)
            end = min(len(text), match.end() + 30)
            context = text[start:end].strip().replace("\n", " ")

            found.append(IOC(type=ioc_type, value=value, context=context))

    return found


def classify_ioc(value: str) -> IOCType | None:
    """Classify a single *value* as an IOC type, or return None."""
    for ioc_type, pattern in _PATTERNS.items():
        if re.fullmatch(pattern, value, re.IGNORECASE):
            return ioc_type
    return None
