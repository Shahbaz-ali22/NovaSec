"""
NovaSec WHOIS Lookup — Domain Layer.

Performs WHOIS lookups on domains and IP addresses, extracting:
- Registrar information
- Registration and expiry dates
- Registrant contact data (if not redacted)
- Nameservers
- ASN / network block information
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from novasec.reporting.models import Evidence, Finding, FindingSet, Severity
from novasec.utils.network import is_valid_domain, is_valid_ip

if TYPE_CHECKING:
    from novasec.core.context import ExecutionContext

logger = logging.getLogger(__name__)


@dataclass
class WhoisResult:
    """Parsed WHOIS lookup result."""

    query: str
    raw_text: str = ""
    registrar: str = ""
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    updated_date: datetime | None = None
    registrant_name: str = ""
    registrant_org: str = ""
    registrant_country: str = ""
    registrant_email: str = ""
    nameservers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def is_expiring_soon(self) -> bool:
        """Return True if the domain expires within 30 days."""
        if not self.expiration_date:
            return False
        now = datetime.now(UTC)
        exp = self.expiration_date
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)
        return (exp - now).days <= 30

    @property
    def days_until_expiry(self) -> int | None:
        if not self.expiration_date:
            return None
        now = datetime.now(UTC)
        exp = self.expiration_date
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)
        return max(0, (exp - now).days)


class WhoisLookup:
    """Performs WHOIS lookups for domains and IP addresses.

    Usage::

        lookup = WhoisLookup()
        result = await lookup.query("example.com")
        findings = await lookup.to_findings(result, context)
    """

    async def query(self, target: str) -> WhoisResult:
        """Perform a WHOIS lookup on *target*.

        Args:
            target: Domain name or IP address.

        Returns:
            A :class:`WhoisResult` with parsed WHOIS data.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_query, target)

    def _sync_query(self, target: str) -> WhoisResult:
        """Execute the synchronous WHOIS query."""
        try:
            import whois  # type: ignore[import]

            data = whois.whois(target)
            result = WhoisResult(query=target)

            result.raw_text = str(data)
            result.registrar = str(data.registrar or "")
            result.registrant_org = str(data.org or "")
            result.registrant_country = str(data.country or "")
            result.registrant_email = str(data.emails[0] if data.emails else "")

            # Parse dates (whois may return list or single value)
            def _first_date(val: Any) -> datetime | None:
                if isinstance(val, list):
                    val = val[0] if val else None
                if isinstance(val, datetime):
                    return val
                return None

            result.creation_date = _first_date(data.creation_date)
            result.expiration_date = _first_date(data.expiration_date)
            result.updated_date = _first_date(data.updated_date)

            ns = data.name_servers or []
            result.nameservers = [str(s).lower() for s in (ns if isinstance(ns, list) else [ns])]

            status = data.status or []
            result.status = [str(s) for s in (status if isinstance(status, list) else [status])]

            return result

        except ImportError:
            return WhoisResult(
                query=target,
                error="python-whois not installed: pip install python-whois",
            )
        except Exception as e:
            logger.debug("WHOIS lookup failed for %s: %s", target, e)
            return WhoisResult(query=target, error=str(e))

    async def to_findings(
        self,
        result: WhoisResult,
        context: "ExecutionContext",
    ) -> FindingSet:
        """Convert a :class:`WhoisResult` to a :class:`FindingSet`."""
        finding_set = FindingSet(
            scan_id=context.scan_id,
            target=result.query,
            plugin_source="whois_lookup",
        )

        if result.error:
            return finding_set

        # Check domain expiry
        if result.is_expiring_soon and result.days_until_expiry is not None:
            finding_set.add(
                Finding(
                    title=f"Domain Expiring Soon: {result.query}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The domain {result.query} expires in "
                        f"{result.days_until_expiry} days. "
                        "Expired domains can be registered by attackers for "
                        "phishing, email interception, or domain hijacking."
                    ),
                    target=result.query,
                    plugin_source="whois_lookup",
                    impact="Domain expiry can lead to loss of control and potential hijacking.",
                    remediation="Renew the domain registration immediately.",
                    tags=["whois", "domain", "expiry", "hijacking-risk"],
                )
            )

        # Informational WHOIS summary
        details = []
        if result.registrar:
            details.append(f"Registrar:    {result.registrar}")
        if result.creation_date:
            details.append(f"Created:      {result.creation_date.strftime('%Y-%m-%d')}")
        if result.expiration_date:
            details.append(f"Expires:      {result.expiration_date.strftime('%Y-%m-%d')} ({result.days_until_expiry} days)")
        if result.registrant_org:
            details.append(f"Organization: {result.registrant_org}")
        if result.registrant_country:
            details.append(f"Country:      {result.registrant_country}")
        if result.nameservers:
            details.append(f"Nameservers:  {', '.join(result.nameservers[:4])}")

        finding_set.add(
            Finding(
                title=f"WHOIS Information: {result.query}",
                severity=Severity.INFO,
                description=f"WHOIS lookup completed for {result.query}.",
                target=result.query,
                plugin_source="whois_lookup",
                tags=["whois", "recon", "osint"],
                evidence=[
                    Evidence(
                        type="raw",
                        data="\n".join(details),
                        description="Parsed WHOIS data",
                    )
                ],
            )
        )

        return finding_set
