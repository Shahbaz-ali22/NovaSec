"""
NovaSec DNS Enumeration — Domain Layer.

Performs comprehensive DNS reconnaissance against a target domain:
- A / AAAA records (IPv4/IPv6 addresses)
- MX records (mail servers)
- NS records (nameservers)
- TXT records (SPF, DKIM, DMARC, verification tokens)
- CNAME records (aliases)
- SOA record (zone authority)
- Zone transfer attempt (AXFR)

Results are returned as :class:`~novasec.reporting.models.FindingSet`.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

try:
    import dns.asyncresolver
    import dns.exception
    import dns.resolver
    import dns.zone
    import dns.query
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from novasec.core.exceptions import DNSResolutionError
from novasec.reporting.models import Evidence, Finding, FindingSet, Severity
from novasec.utils.network import is_valid_domain

if TYPE_CHECKING:
    from novasec.core.context import ExecutionContext

logger = logging.getLogger(__name__)

# DNS record types to query by default
DEFAULT_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


@dataclass
class DNSRecord:
    """A single parsed DNS record."""

    record_type: str
    name: str
    value: str
    ttl: int = 0
    priority: int | None = None  # For MX records


@dataclass
class DNSEnumerationResult:
    """Full DNS enumeration result for a domain."""

    domain: str
    records: list[DNSRecord] = field(default_factory=list)
    zone_transfer_possible: bool = False
    zone_transfer_data: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    enumerated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def get_records_by_type(self, record_type: str) -> list[DNSRecord]:
        return [r for r in self.records if r.record_type == record_type]

    @property
    def a_records(self) -> list[str]:
        return [r.value for r in self.records if r.record_type == "A"]

    @property
    def mx_records(self) -> list[DNSRecord]:
        return sorted(
            [r for r in self.records if r.record_type == "MX"],
            key=lambda r: r.priority or 0,
        )

    @property
    def txt_records(self) -> list[str]:
        return [r.value for r in self.records if r.record_type == "TXT"]

    @property
    def has_spf(self) -> bool:
        return any("v=spf1" in t.lower() for t in self.txt_records)

    @property
    def has_dmarc(self) -> bool:
        return any("v=dmarc1" in t.lower() for t in self.txt_records)

    @property
    def has_dkim(self) -> bool:
        return any("v=dkim1" in t.lower() for t in self.txt_records)


class DNSEnumerator:
    """
    Performs asynchronous DNS enumeration against a target domain.

    Usage::

        enumerator = DNSEnumerator(nameservers=["8.8.8.8"])
        result = await enumerator.enumerate("example.com")
        findings = await enumerator.to_findings(result, context)
    """

    def __init__(
        self,
        nameservers: list[str] | None = None,
        timeout: float = 5.0,
        record_types: list[str] | None = None,
    ) -> None:
        if not HAS_DNSPYTHON:
            raise ImportError("dnspython is required: pip install dnspython")

        self.nameservers = nameservers or ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
        self.timeout = timeout
        self.record_types = record_types or DEFAULT_RECORD_TYPES

        # Configure the async resolver
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.nameservers = self.nameservers
        self._resolver.lifetime = timeout * 2
        self._resolver.timeout = timeout

    async def enumerate(self, domain: str) -> DNSEnumerationResult:
        """Perform full DNS enumeration on *domain*.

        Args:
            domain: The domain name to enumerate (e.g. "example.com").

        Returns:
            A :class:`DNSEnumerationResult` with all discovered records.

        Raises:
            DNSResolutionError: If the domain cannot be resolved at all.
        """
        if not is_valid_domain(domain):
            raise DNSResolutionError(
                f"Invalid domain name: {domain!r}",
                details={"domain": domain},
            )

        logger.info("Starting DNS enumeration for %s", domain)
        result = DNSEnumerationResult(domain=domain)

        # Resolve all record types concurrently
        tasks = [self._query_records(domain, rt, result) for rt in self.record_types]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Capture nameservers for zone transfer attempt
        result.nameservers = [r.value for r in result.records if r.record_type == "NS"]

        # Attempt zone transfer against each nameserver
        if result.nameservers:
            await self._attempt_zone_transfer(domain, result)

        logger.info(
            "DNS enumeration complete for %s: %d records found",
            domain, len(result.records),
        )
        return result

    async def _query_records(
        self,
        domain: str,
        record_type: str,
        result: DNSEnumerationResult,
    ) -> None:
        """Query a single record type and append results to *result*."""
        try:
            answers = await self._resolver.resolve(domain, record_type)
            for rdata in answers:
                record = self._parse_rdata(record_type, domain, rdata, answers.ttl)
                if record:
                    result.records.append(record)
                    logger.debug("DNS %s %s → %s", record_type, domain, record.value)

        except dns.resolver.NXDOMAIN:
            if record_type == "A":
                raise DNSResolutionError(
                    f"Domain {domain!r} does not exist (NXDOMAIN)",
                    details={"domain": domain},
                )
        except dns.resolver.NoAnswer:
            pass  # No records of this type — expected for many types
        except dns.exception.Timeout:
            result.errors.append(f"Timeout querying {record_type} records for {domain}")
            logger.debug("Timeout on %s/%s", domain, record_type)
        except Exception as e:
            result.errors.append(f"Error querying {record_type}: {e}")
            logger.debug("Error querying %s/%s: %s", domain, record_type, e)

    def _parse_rdata(
        self,
        record_type: str,
        name: str,
        rdata: Any,
        ttl: int,
    ) -> DNSRecord | None:
        """Parse a dnspython rdata object into a :class:`DNSRecord`."""
        try:
            if record_type == "A":
                return DNSRecord(record_type="A", name=name, value=str(rdata), ttl=ttl)
            elif record_type == "AAAA":
                return DNSRecord(record_type="AAAA", name=name, value=str(rdata), ttl=ttl)
            elif record_type == "MX":
                return DNSRecord(
                    record_type="MX",
                    name=name,
                    value=str(rdata.exchange).rstrip("."),
                    ttl=ttl,
                    priority=rdata.preference,
                )
            elif record_type == "NS":
                return DNSRecord(
                    record_type="NS",
                    name=name,
                    value=str(rdata.target).rstrip("."),
                    ttl=ttl,
                )
            elif record_type == "TXT":
                txt_data = b" ".join(rdata.strings).decode("utf-8", errors="replace")
                return DNSRecord(record_type="TXT", name=name, value=txt_data, ttl=ttl)
            elif record_type == "CNAME":
                return DNSRecord(
                    record_type="CNAME",
                    name=name,
                    value=str(rdata.target).rstrip("."),
                    ttl=ttl,
                )
            elif record_type == "SOA":
                value = (
                    f"mname={str(rdata.mname).rstrip('.')} "
                    f"rname={str(rdata.rname).rstrip('.')} "
                    f"serial={rdata.serial}"
                )
                return DNSRecord(record_type="SOA", name=name, value=value, ttl=ttl)
        except Exception as e:
            logger.debug("Failed to parse %s rdata: %s", record_type, e)
        return None

    async def _attempt_zone_transfer(
        self,
        domain: str,
        result: DNSEnumerationResult,
    ) -> None:
        """Attempt a DNS zone transfer (AXFR) against each nameserver."""
        for ns in result.nameservers:
            try:
                # Resolve nameserver to IP
                ns_answers = await self._resolver.resolve(ns, "A")
                ns_ip = str(next(iter(ns_answers)))

                # Attempt AXFR (synchronous — run in thread pool)
                loop = asyncio.get_event_loop()
                zone_data = await loop.run_in_executor(
                    None, self._do_axfr, domain, ns_ip
                )

                if zone_data:
                    result.zone_transfer_possible = True
                    result.zone_transfer_data = zone_data
                    logger.warning(
                        "ZONE TRANSFER POSSIBLE: %s allows AXFR from %s",
                        domain, ns,
                    )
                    break  # One success is enough to flag the issue

            except Exception as e:
                logger.debug("Zone transfer failed against %s: %s", ns, e)

    def _do_axfr(self, domain: str, nameserver_ip: str) -> list[str]:
        """Perform a synchronous AXFR request. Returns record strings."""
        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(nameserver_ip, domain, timeout=5.0)
            )
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(f"{name} {rdataset.ttl} {rdataset.rdtype} {rdata}")
            return records
        except Exception:
            return []

    async def to_findings(
        self,
        result: DNSEnumerationResult,
        context: "ExecutionContext",
    ) -> FindingSet:
        """Convert a :class:`DNSEnumerationResult` into a :class:`FindingSet`.

        Produces:
        - INFO findings for all discovered record types
        - HIGH finding if zone transfer is possible
        - MEDIUM finding if SPF is missing
        - MEDIUM finding if DMARC is missing
        """
        finding_set = FindingSet(
            scan_id=context.scan_id,
            target=result.domain,
            plugin_source="dns_enumerator",
        )

        # Zone transfer vulnerability
        if result.zone_transfer_possible:
            finding = Finding(
                title=f"DNS Zone Transfer Enabled: {result.domain}",
                severity=Severity.HIGH,
                description=(
                    f"The nameservers for {result.domain} allow unauthorized zone "
                    "transfers (AXFR). This exposes the complete DNS zone data to "
                    "any client, revealing internal hostnames, IP addresses, and "
                    "infrastructure details."
                ),
                target=result.domain,
                plugin_source="dns_enumerator",
                cwe_ids=["CWE-200"],
                owasp_category="A05:2021 - Security Misconfiguration",
                impact=(
                    "An attacker can map the entire internal network infrastructure, "
                    "discover hidden subdomains, and identify targets for further attacks."
                ),
                remediation=(
                    "Restrict zone transfers to authorized secondary DNS servers only. "
                    "In BIND: add 'allow-transfer { <secondary-ns-ip>; };' to the zone "
                    "configuration."
                ),
                references=[
                    "https://www.cvedetails.com/vulnerability-list/cweid-200/",
                    "https://attack.mitre.org/techniques/T1018/",
                ],
                tags=["dns", "zone-transfer", "information-disclosure", "misconfiguration"],
            )
            finding.add_evidence(
                type="raw",
                data="\n".join(result.zone_transfer_data[:50]),
                description="Zone transfer data (first 50 records)",
            )
            finding_set.add(finding)

        # Missing SPF record
        if not result.has_spf and result.mx_records:
            finding_set.add(
                Finding(
                    title=f"Missing SPF Record: {result.domain}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The domain {result.domain} has mail servers (MX records) "
                        "but no SPF (Sender Policy Framework) TXT record. "
                        "This allows anyone to send emails spoofing this domain."
                    ),
                    target=result.domain,
                    plugin_source="dns_enumerator",
                    cwe_ids=["CWE-346"],
                    owasp_category="A05:2021 - Security Misconfiguration",
                    impact="Domain can be used for phishing and spam campaigns.",
                    remediation=(
                        'Add a TXT record: "v=spf1 mx ~all" (adjust based on '
                        "your mail infrastructure)."
                    ),
                    tags=["dns", "email", "spf", "phishing"],
                )
            )

        # Missing DMARC record
        if not result.has_dmarc and result.mx_records:
            finding_set.add(
                Finding(
                    title=f"Missing DMARC Record: {result.domain}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"No DMARC policy found for {result.domain}. "
                        "DMARC (Domain-based Message Authentication) tells receiving "
                        "mail servers what to do with unauthenticated messages."
                    ),
                    target=result.domain,
                    plugin_source="dns_enumerator",
                    cwe_ids=["CWE-346"],
                    impact="Email spoofing attacks are easier without DMARC enforcement.",
                    remediation=(
                        f"Add a TXT record at _dmarc.{result.domain}: "
                        '"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"'
                    ),
                    tags=["dns", "email", "dmarc", "phishing"],
                )
            )

        # INFO finding: DNS records summary
        all_records_text = "\n".join(
            f"{r.record_type:6s} {r.name:30s} {r.value}"
            for r in sorted(result.records, key=lambda r: r.record_type)
        )
        finding_set.add(
            Finding(
                title=f"DNS Records Enumerated: {result.domain}",
                severity=Severity.INFO,
                description=(
                    f"DNS enumeration completed for {result.domain}. "
                    f"Found {len(result.records)} DNS records across "
                    f"{len(self.record_types)} queried record types."
                ),
                target=result.domain,
                plugin_source="dns_enumerator",
                tags=["dns", "recon", "information-gathering"],
                evidence=[
                    Evidence(
                        type="raw",
                        data=all_records_text,
                        description=f"All DNS records for {result.domain}",
                    )
                ],
            )
        )

        return finding_set
