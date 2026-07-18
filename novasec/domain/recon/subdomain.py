"""
NovaSec Subdomain Enumeration — Domain Layer.

Discovers subdomains using multiple techniques:
1. Wordlist-based brute-force (DNS resolution)
2. Certificate Transparency log search (crt.sh)
3. DNS permutation expansion
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, AsyncIterator

try:
    import dns.asyncresolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

import httpx

from novasec.core.exceptions import InvalidTargetError
from novasec.reporting.models import Evidence, Finding, FindingSet, Severity
from novasec.utils.network import is_valid_domain

if TYPE_CHECKING:
    from novasec.core.context import ExecutionContext

logger = logging.getLogger(__name__)

# Default wordlist bundled with the framework
BUILTIN_WORDLIST = Path(__file__).parent / "wordlists" / "subdomains-100.txt"

# Certificate Transparency API
CRT_SH_URL = "https://crt.sh/?q=%.{domain}&output=json"


@dataclass
class SubdomainResult:
    """A discovered subdomain."""

    subdomain: str
    ip_addresses: list[str] = field(default_factory=list)
    discovered_via: str = "bruteforce"  # "bruteforce" | "ct_log" | "permutation"
    cname: str | None = None


class SubdomainEnumerator:
    """
    Discovers subdomains via DNS brute-force and certificate transparency.

    Usage::

        enumerator = SubdomainEnumerator(concurrency=50)
        results = await enumerator.enumerate(
            domain="example.com",
            wordlist_path="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        )
    """

    def __init__(
        self,
        nameservers: list[str] | None = None,
        concurrency: int = 50,
        timeout: float = 3.0,
        use_ct_logs: bool = True,
    ) -> None:
        if not HAS_DNSPYTHON:
            raise ImportError("dnspython is required: pip install dnspython")

        self.nameservers = nameservers or ["8.8.8.8", "1.1.1.1"]
        self.concurrency = concurrency
        self.timeout = timeout
        self.use_ct_logs = use_ct_logs

        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.nameservers = self.nameservers
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout * 2

    async def enumerate(
        self,
        domain: str,
        wordlist_path: Path | None = None,
    ) -> list[SubdomainResult]:
        """Enumerate subdomains for *domain*.

        Args:
            domain: The root domain to enumerate subdomains for.
            wordlist_path: Path to a subdomain wordlist file.
                           Defaults to the built-in 100-word wordlist.

        Returns:
            Sorted list of :class:`SubdomainResult` objects.
        """
        if not is_valid_domain(domain):
            raise InvalidTargetError(
                f"Invalid domain: {domain!r}", details={"domain": domain}
            )

        results: list[SubdomainResult] = []
        seen: set[str] = set()

        logger.info("Starting subdomain enumeration for %s", domain)

        # Source 1: Certificate Transparency logs
        if self.use_ct_logs:
            ct_results = await self._query_ct_logs(domain)
            for r in ct_results:
                if r.subdomain not in seen:
                    seen.add(r.subdomain)
                    results.append(r)
            logger.info("CT logs: found %d subdomains", len(ct_results))

        # Source 2: DNS brute-force via wordlist
        wordlist = wordlist_path or BUILTIN_WORDLIST
        if wordlist.exists():
            words = wordlist.read_text(encoding="utf-8").splitlines()
            words = [w.strip() for w in words if w.strip() and not w.startswith("#")]
            logger.info("Wordlist brute-force: testing %d words", len(words))

            brute_results = await self._bruteforce(domain, words)
            for r in brute_results:
                if r.subdomain not in seen:
                    seen.add(r.subdomain)
                    results.append(r)
            logger.info("Brute-force: found %d additional subdomains", len(brute_results))
        else:
            logger.warning("Wordlist not found: %s — skipping brute-force", wordlist)

        logger.info(
            "Subdomain enumeration complete for %s: %d total subdomains found",
            domain, len(results),
        )
        return sorted(results, key=lambda r: r.subdomain)

    async def _query_ct_logs(self, domain: str) -> list[SubdomainResult]:
        """Query crt.sh for certificate transparency subdomain data."""
        results: list[SubdomainResult] = []
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(url)
                if response.status_code != 200:
                    return results
                data = response.json()
                seen_names: set[str] = set()
                for entry in data:
                    names = entry.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lstrip("*.")
                        if (
                            name.endswith(f".{domain}")
                            and name not in seen_names
                        ):
                            seen_names.add(name)
                            results.append(
                                SubdomainResult(
                                    subdomain=name,
                                    discovered_via="ct_log",
                                )
                            )
        except Exception as e:
            logger.debug("CT log query failed: %s", e)
        return results

    async def _bruteforce(
        self,
        domain: str,
        words: list[str],
    ) -> list[SubdomainResult]:
        """Resolve words as subdomains concurrently."""
        semaphore = asyncio.Semaphore(self.concurrency)
        results: list[SubdomainResult] = []

        async def resolve_word(word: str) -> None:
            subdomain = f"{word}.{domain}"
            async with semaphore:
                try:
                    answers = await self._resolver.resolve(subdomain, "A")
                    ips = [str(r) for r in answers]
                    results.append(
                        SubdomainResult(
                            subdomain=subdomain,
                            ip_addresses=ips,
                            discovered_via="bruteforce",
                        )
                    )
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                    pass
                except Exception as e:
                    logger.debug("Error resolving %s: %s", subdomain, e)

        await asyncio.gather(*(resolve_word(w) for w in words), return_exceptions=True)
        return results

    async def to_findings(
        self,
        results: list[SubdomainResult],
        domain: str,
        context: "ExecutionContext",
    ) -> FindingSet:
        """Convert subdomain results to a :class:`FindingSet`."""
        finding_set = FindingSet(
            scan_id=context.scan_id,
            target=domain,
            plugin_source="subdomain_enumerator",
        )

        if not results:
            return finding_set

        # Compile a summary evidence block
        summary_lines = []
        for r in results:
            ips = ", ".join(r.ip_addresses) if r.ip_addresses else "not resolved"
            summary_lines.append(f"{r.subdomain:50s} [{ips}] via {r.discovered_via}")

        finding_set.add(
            Finding(
                title=f"Subdomains Discovered: {domain} ({len(results)} found)",
                severity=Severity.INFO,
                description=(
                    f"Subdomain enumeration for {domain} discovered {len(results)} "
                    f"subdomains via DNS brute-force and certificate transparency logs."
                ),
                target=domain,
                plugin_source="subdomain_enumerator",
                tags=["recon", "subdomain", "dns", "attack-surface"],
                evidence=[
                    Evidence(
                        type="raw",
                        data="\n".join(summary_lines),
                        description=f"All discovered subdomains for {domain}",
                    )
                ],
            )
        )

        return finding_set
