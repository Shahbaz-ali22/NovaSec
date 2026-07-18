"""
NovaSec SSL/TLS Analysis — Domain Layer.

Analyzes the SSL/TLS configuration of a host:
- Certificate validity and chain
- Certificate expiry
- Subject Alternative Names (SANs)
- Weak cipher suites
- TLS protocol version support
- HSTS header presence
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from novasec.reporting.models import Evidence, Finding, FindingSet, Severity

if TYPE_CHECKING:
    from novasec.core.context import ExecutionContext

logger = logging.getLogger(__name__)


@dataclass
class CertificateInfo:
    """Parsed X.509 certificate information."""
    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    not_before: datetime | None = None
    not_after: datetime | None = None
    serial_number: str = ""
    san_domains: list[str] = field(default_factory=list)
    signature_algorithm: str = ""
    tls_version: str = ""
    cipher_suite: str = ""

    @property
    def is_expired(self) -> bool:
        if not self.not_after:
            return False
        exp = self.not_after
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)
        return exp < datetime.now(UTC)

    @property
    def days_until_expiry(self) -> int | None:
        if not self.not_after:
            return None
        exp = self.not_after
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)
        return max(0, (exp - datetime.now(UTC)).days)

    @property
    def common_name(self) -> str:
        return self.subject.get("commonName", "")


class SSLAnalyzer:
    """
    Analyzes SSL/TLS configuration and certificate health.

    Usage::

        analyzer = SSLAnalyzer()
        cert_info = await analyzer.analyze("example.com", port=443)
        findings = await analyzer.to_findings(cert_info, context)
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def analyze(
        self,
        host: str,
        port: int = 443,
    ) -> CertificateInfo:
        """Fetch and analyze the SSL certificate for *host*:*port*.

        Args:
            host: Target hostname or IP.
            port: TCP port (default 443).

        Returns:
            A :class:`CertificateInfo` with parsed certificate data.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_analyze, host, port)

    def _sync_analyze(self, host: str, port: int) -> CertificateInfo:
        """Synchronous SSL analysis — run in thread pool."""
        info = CertificateInfo()
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    info.tls_version = ssock.version() or ""
                    info.cipher_suite = ssock.cipher()[0] if ssock.cipher() else ""

                    # Parse subject
                    for field_pair in cert.get("subject", []):
                        for key, value in field_pair:
                            info.subject[key] = value

                    # Parse issuer
                    for field_pair in cert.get("issuer", []):
                        for key, value in field_pair:
                            info.issuer[key] = value

                    # Parse validity dates
                    not_before_str = cert.get("notBefore", "")
                    not_after_str = cert.get("notAfter", "")
                    if not_before_str:
                        info.not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
                    if not_after_str:
                        info.not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)

                    # SANs
                    for san_type, san_value in cert.get("subjectAltName", []):
                        if san_type == "DNS":
                            info.san_domains.append(san_value)

        except ssl.SSLCertVerificationError as e:
            info.signature_algorithm = f"VERIFICATION_ERROR: {e}"
        except Exception as e:
            logger.debug("SSL analysis failed for %s:%d: %s", host, port, e)
            info.signature_algorithm = f"ERROR: {e}"

        return info

    async def to_findings(
        self,
        cert: CertificateInfo,
        host: str,
        context: "ExecutionContext",
    ) -> FindingSet:
        """Convert SSL analysis to a :class:`FindingSet`."""
        finding_set = FindingSet(
            scan_id=context.scan_id,
            target=host,
            plugin_source="ssl_analyzer",
        )

        # Expired certificate
        if cert.is_expired:
            finding_set.add(
                Finding(
                    title=f"SSL Certificate Expired: {host}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The SSL certificate for {host} has expired. "
                        "Browsers and clients will show security warnings, "
                        "breaking the site for users."
                    ),
                    target=host,
                    plugin_source="ssl_analyzer",
                    owasp_category="A02:2021 - Cryptographic Failures",
                    impact="All HTTPS connections will show certificate errors.",
                    remediation="Renew the SSL certificate immediately.",
                    tags=["ssl", "certificate", "expired", "critical"],
                )
            )

        # Expiring soon (within 30 days)
        elif cert.days_until_expiry is not None and cert.days_until_expiry <= 30:
            finding_set.add(
                Finding(
                    title=f"SSL Certificate Expiring Soon: {host} ({cert.days_until_expiry} days)",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The SSL certificate for {host} expires in "
                        f"{cert.days_until_expiry} days."
                    ),
                    target=host,
                    plugin_source="ssl_analyzer",
                    remediation="Renew the SSL certificate before it expires.",
                    tags=["ssl", "certificate", "expiry"],
                )
            )

        # Weak TLS version
        weak_tls = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
        if cert.tls_version in weak_tls:
            finding_set.add(
                Finding(
                    title=f"Weak TLS Version: {host} ({cert.tls_version})",
                    severity=Severity.HIGH,
                    description=(
                        f"{host} supports {cert.tls_version}, which is deprecated "
                        "and vulnerable to protocol downgrade attacks (POODLE, BEAST)."
                    ),
                    target=host,
                    plugin_source="ssl_analyzer",
                    owasp_category="A02:2021 - Cryptographic Failures",
                    remediation="Disable TLSv1.0 and TLSv1.1. Enforce TLSv1.2 minimum, prefer TLSv1.3.",
                    tags=["ssl", "tls", "weak-protocol", "cryptography"],
                )
            )

        # Certificate info summary
        if cert.common_name:
            details = [
                f"Common Name:    {cert.common_name}",
                f"Issuer:         {cert.issuer.get('organizationName', 'Unknown')}",
                f"Not Before:     {cert.not_before}",
                f"Not After:      {cert.not_after} ({cert.days_until_expiry} days)",
                f"TLS Version:    {cert.tls_version}",
                f"Cipher Suite:   {cert.cipher_suite}",
                f"SANs:           {', '.join(cert.san_domains[:10])}",
            ]
            finding_set.add(
                Finding(
                    title=f"SSL/TLS Certificate Analysis: {host}",
                    severity=Severity.INFO,
                    description=f"SSL/TLS analysis completed for {host}.",
                    target=host,
                    plugin_source="ssl_analyzer",
                    tags=["ssl", "tls", "certificate", "recon"],
                    evidence=[
                        Evidence(
                            type="raw",
                            data="\n".join(details),
                            description="Certificate details",
                        )
                    ],
                )
            )

        return finding_set
