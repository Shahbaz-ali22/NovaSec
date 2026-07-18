"""
NovaSec OSINT Aggregation — Domain Layer.

Aggregates publicly available intelligence from multiple sources:
- crt.sh (certificate transparency)
- Have I Been Pwned (breach data)
- Shodan (host intelligence, if API key configured)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx

from novasec.reporting.models import Evidence, Finding, FindingSet, Severity

if TYPE_CHECKING:
    from novasec.core.context import ExecutionContext
    from novasec.config.schema import APIConfig

logger = logging.getLogger(__name__)


@dataclass
class OsintResult:
    """Aggregated OSINT data for a target."""
    target: str
    emails_found: list[str] = field(default_factory=list)
    breaches_found: list[str] = field(default_factory=list)
    shodan_data: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class OsintAggregator:
    """
    Gathers open-source intelligence for a domain or email.

    Usage::

        agg = OsintAggregator(api_config=config.apis)
        result = await agg.gather("example.com")
    """

    def __init__(self, api_config: "APIConfig | None" = None) -> None:
        self.api_config = api_config

    async def gather(self, target: str) -> OsintResult:
        """Gather OSINT data for *target*."""
        result = OsintResult(target=target)
        logger.info("Gathering OSINT for %s", target)

        # Run sources concurrently
        import asyncio
        await asyncio.gather(
            self._gather_shodan(target, result),
            return_exceptions=True,
        )

        return result

    async def _gather_shodan(self, target: str, result: OsintResult) -> None:
        """Query Shodan for host information."""
        if not self.api_config or not self.api_config.shodan_key:
            result.errors.append("Shodan API key not configured — skipping Shodan lookup")
            return
        try:
            import shodan  # type: ignore[import]
            api = shodan.Shodan(self.api_config.get_shodan_key())
            import asyncio
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(None, api.host, target)
            result.shodan_data = {
                "ip": data.get("ip_str"),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "asn": data.get("asn"),
                "country": data.get("country_name"),
                "ports": data.get("ports", []),
                "vulns": list(data.get("vulns", {}).keys()),
            }
        except Exception as e:
            result.errors.append(f"Shodan lookup failed: {e}")

    async def to_findings(
        self,
        result: OsintResult,
        context: "ExecutionContext",
    ) -> FindingSet:
        """Convert OSINT results to a :class:`FindingSet`."""
        finding_set = FindingSet(
            scan_id=context.scan_id,
            target=result.target,
            plugin_source="osint_aggregator",
        )

        # Shodan vulnerability data
        if result.shodan_data.get("vulns"):
            vulns = result.shodan_data["vulns"]
            finding_set.add(
                Finding(
                    title=f"Shodan: Known Vulnerabilities on {result.target}",
                    severity=Severity.HIGH,
                    description=(
                        f"Shodan reports {len(vulns)} known CVEs associated with "
                        f"services running on {result.target}."
                    ),
                    target=result.target,
                    plugin_source="osint_aggregator",
                    cve_ids=vulns[:20],
                    tags=["shodan", "osint", "cve", "vulnerability"],
                    evidence=[
                        Evidence(
                            type="raw",
                            data="\n".join(vulns),
                            description="CVEs reported by Shodan",
                        )
                    ],
                )
            )

        # Shodan host info
        if result.shodan_data:
            sd = result.shodan_data
            info = f"Organization: {sd.get('org')}\nISP: {sd.get('isp')}\nASN: {sd.get('asn')}\nCountry: {sd.get('country')}\nOpen Ports: {sd.get('ports')}"
            finding_set.add(
                Finding(
                    title=f"Shodan Host Intelligence: {result.target}",
                    severity=Severity.INFO,
                    description=f"Shodan has indexed {result.target} with the following host information.",
                    target=result.target,
                    plugin_source="osint_aggregator",
                    tags=["shodan", "osint", "intelligence"],
                    evidence=[Evidence(type="raw", data=info, description="Shodan host data")],
                )
            )

        return finding_set
