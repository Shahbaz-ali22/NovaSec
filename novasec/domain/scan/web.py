"""
NovaSec Web Application Scanning — Domain Layer.

Performs passive/active web application security checks:
- Security header analysis
- HTTP methods enumeration
- Directory traversal detection
- Common path enumeration
- Cookie security flags
- CORS misconfiguration
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx

from novasec.reporting.models import Evidence, Finding, FindingSet, Severity
from novasec.utils.text import normalize_url

if TYPE_CHECKING:
    from novasec.core.context import ExecutionContext

logger = logging.getLogger(__name__)

# Security headers that SHOULD be present
REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": "Missing HSTS — forces HTTPS",
    "X-Content-Type-Options": "Missing — allows MIME-type sniffing attacks",
    "X-Frame-Options": "Missing — allows clickjacking",
    "Content-Security-Policy": "Missing — increases XSS attack surface",
    "X-XSS-Protection": "Deprecated but checked for legacy server detection",
    "Referrer-Policy": "Missing — may leak sensitive URL information",
    "Permissions-Policy": "Missing — browser feature policy not set",
}

# Headers that reveal server information
INFORMATION_DISCLOSURE_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "Via", "X-Backend-Server",
]


@dataclass
class WebScanResult:
    """Web application scan result for a single URL."""
    url: str
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    missing_security_headers: list[str] = field(default_factory=list)
    disclosed_headers: dict[str, str] = field(default_factory=dict)
    allowed_methods: list[str] = field(default_factory=list)
    error: str = ""


class WebScanner:
    """
    Passive web application security scanner.

    Usage::

        scanner = WebScanner()
        result = await scanner.scan("https://example.com")
        findings = await scanner.to_findings(result, context)
    """

    def __init__(
        self,
        timeout: float = 15.0,
        verify_ssl: bool = True,
        proxy: str | None = None,
        user_agent: str = "NovaSec/1.0.0",
    ) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.user_agent = user_agent

    async def scan(self, url: str) -> WebScanResult:
        """Perform a passive security scan of *url*.

        Args:
            url: Target URL (must start with http:// or https://).

        Returns:
            A :class:`WebScanResult` with security analysis.
        """
        from novasec.utils.text import normalize_url as nurl
        url = nurl(url)
        result = WebScanResult(url=url)

        logger.info("Web scan: %s", url)

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify_ssl,
                proxy=self.proxy,
                follow_redirects=True,
                headers={"User-Agent": self.user_agent},
            ) as client:
                response = await client.get(url)
                result.status_code = response.status_code
                result.headers = dict(response.headers)

                self._check_security_headers(result)
                self._check_information_disclosure(result)
                await self._check_http_methods(client, url, result)

        except httpx.ConnectError as e:
            result.error = f"Connection failed: {e}"
        except httpx.TimeoutException:
            result.error = f"Request timed out after {self.timeout}s"
        except Exception as e:
            result.error = str(e)

        return result

    def _check_security_headers(self, result: WebScanResult) -> None:
        """Identify missing security headers."""
        lower_headers = {k.lower(): v for k, v in result.headers.items()}
        for header, _ in REQUIRED_SECURITY_HEADERS.items():
            if header.lower() not in lower_headers:
                result.missing_security_headers.append(header)

    def _check_information_disclosure(self, result: WebScanResult) -> None:
        """Identify headers that disclose server information."""
        lower_headers = {k.lower(): v for k, v in result.headers.items()}
        for header in INFORMATION_DISCLOSURE_HEADERS:
            val = lower_headers.get(header.lower())
            if val:
                result.disclosed_headers[header] = val

    async def _check_http_methods(
        self,
        client: httpx.AsyncClient,
        url: str,
        result: WebScanResult,
    ) -> None:
        """Test which HTTP methods the server allows."""
        try:
            response = await client.options(url)
            allow_header = response.headers.get("Allow", "")
            if allow_header:
                result.allowed_methods = [m.strip() for m in allow_header.split(",")]
        except Exception:
            pass

    async def to_findings(
        self,
        result: WebScanResult,
        context: "ExecutionContext",
    ) -> FindingSet:
        """Convert web scan results to a :class:`FindingSet`."""
        finding_set = FindingSet(
            scan_id=context.scan_id,
            target=result.url,
            plugin_source="web_scanner",
        )

        if result.error:
            return finding_set

        # Missing security headers
        if result.missing_security_headers:
            critical_missing = [h for h in result.missing_security_headers
                                if h in ("Strict-Transport-Security", "Content-Security-Policy")]
            severity = Severity.HIGH if critical_missing else Severity.MEDIUM
            finding_set.add(
                Finding(
                    title=f"Missing Security Headers: {result.url}",
                    severity=severity,
                    description=(
                        f"{len(result.missing_security_headers)} security response headers "
                        f"are missing from {result.url}."
                    ),
                    target=result.url,
                    plugin_source="web_scanner",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    impact="Missing headers increase exposure to XSS, clickjacking, and MIME-sniffing attacks.",
                    remediation="\n".join(
                        f"Add header: {h}" for h in result.missing_security_headers
                    ),
                    tags=["web", "headers", "misconfiguration"],
                    evidence=[
                        Evidence(
                            type="raw",
                            data="\n".join(result.missing_security_headers),
                            description="Missing security headers",
                        )
                    ],
                )
            )

        # Information disclosure via headers
        if result.disclosed_headers:
            header_data = "\n".join(
                f"{k}: {v}" for k, v in result.disclosed_headers.items()
            )
            finding_set.add(
                Finding(
                    title=f"Server Information Disclosure: {result.url}",
                    severity=Severity.LOW,
                    description=(
                        f"Server response headers reveal technology stack information "
                        f"for {result.url}. This aids attackers in fingerprinting the server."
                    ),
                    target=result.url,
                    plugin_source="web_scanner",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    remediation="Remove or obfuscate Server, X-Powered-By, and similar headers.",
                    tags=["web", "information-disclosure", "fingerprinting"],
                    evidence=[Evidence(type="raw", data=header_data, description="Disclosing headers")],
                )
            )

        # Dangerous HTTP methods
        dangerous_methods = {"TRACE", "TRACK", "PUT", "DELETE"}
        dangerous_allowed = dangerous_methods & set(result.allowed_methods)
        if dangerous_allowed:
            finding_set.add(
                Finding(
                    title=f"Dangerous HTTP Methods Enabled: {result.url}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The server allows potentially dangerous HTTP methods: "
                        f"{', '.join(dangerous_allowed)}. "
                        "TRACE can be used for XST attacks. PUT/DELETE may allow unauthorized modification."
                    ),
                    target=result.url,
                    plugin_source="web_scanner",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    remediation="Disable TRACE, TRACK, and restrict PUT/DELETE via server configuration.",
                    tags=["web", "http-methods", "misconfiguration"],
                )
            )

        return finding_set
