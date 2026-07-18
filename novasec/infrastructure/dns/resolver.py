"""NovaSec DNS resolver infrastructure."""
from __future__ import annotations
import logging
from typing import Any

logger = logging.getLogger(__name__)


class AsyncDNSResolver:
    """Async DNS resolver wrapper around dnspython."""

    def __init__(self, nameservers: list[str] | None = None, timeout: float = 5.0) -> None:
        self.nameservers = nameservers or ["8.8.8.8", "1.1.1.1"]
        self.timeout = timeout

    async def resolve(self, hostname: str, record_type: str = "A") -> list[str]:
        try:
            import dns.asyncresolver
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = self.nameservers
            resolver.timeout = self.timeout
            answers = await resolver.resolve(hostname, record_type)
            return [str(r) for r in answers]
        except Exception as e:
            logger.debug("DNS resolve failed %s/%s: %s", hostname, record_type, e)
            return []

    async def reverse(self, ip: str) -> str | None:
        try:
            import dns.asyncresolver
            import dns.reversename
            rev_name = dns.reversename.from_address(ip)
            answers = await dns.asyncresolver.resolve(rev_name, "PTR")
            return str(next(iter(answers))).rstrip(".")
        except Exception:
            return None
