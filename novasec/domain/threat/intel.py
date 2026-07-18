"""
NovaSec Threat Intelligence Aggregation — Domain Layer.

Aggregates threat data from multiple intelligence sources:
- VirusTotal (file/URL/domain/IP reputation)
- Shodan (host intelligence)
- NVD (CVE data)

Results are correlated and merged into unified threat profiles.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from novasec.config.schema import APIConfig

logger = logging.getLogger(__name__)


@dataclass
class ThreatProfile:
    """Aggregated threat intelligence for a target indicator."""
    indicator: str
    indicator_type: str  # "ip", "domain", "hash", "url"
    reputation_score: float = 0.0   # 0.0 (clean) to 10.0 (malicious)
    malicious: bool = False
    sources_checked: list[str] = field(default_factory=list)
    virustotal_data: dict[str, Any] = field(default_factory=dict)
    shodan_data: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class ThreatIntelAggregator:
    """
    Aggregates threat intelligence from multiple sources.

    Usage::

        aggregator = ThreatIntelAggregator(api_config=config.apis)
        profile = await aggregator.analyze("1.2.3.4", indicator_type="ip")
    """

    def __init__(self, api_config: "APIConfig | None" = None) -> None:
        self.api_config = api_config

    async def analyze(
        self,
        indicator: str,
        indicator_type: str = "domain",
    ) -> ThreatProfile:
        """Query all configured intelligence sources for *indicator*.

        Args:
            indicator: The IOC value to analyze.
            indicator_type: "ip" | "domain" | "hash" | "url"

        Returns:
            A :class:`ThreatProfile` with aggregated intelligence.
        """
        import asyncio

        profile = ThreatProfile(indicator=indicator, indicator_type=indicator_type)

        tasks = []
        if self.api_config and self.api_config.virustotal_key:
            tasks.append(self._query_virustotal(indicator, indicator_type, profile))
        if self.api_config and self.api_config.shodan_key and indicator_type == "ip":
            tasks.append(self._query_shodan(indicator, profile))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            profile.errors.append("No API keys configured — skipping threat intel lookup")

        return profile

    async def _query_virustotal(
        self,
        indicator: str,
        indicator_type: str,
        profile: ThreatProfile,
    ) -> None:
        """Query VirusTotal v3 API."""
        import httpx

        if not self.api_config or not self.api_config.virustotal_key:
            return

        key = self.api_config.get_virustotal_key()
        endpoint_map = {
            "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{indicator}",
            "hash": f"https://www.virustotal.com/api/v3/files/{indicator}",
            "url": "https://www.virustotal.com/api/v3/urls",
        }
        url = endpoint_map.get(indicator_type)
        if not url:
            return

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    url,
                    headers={"x-apikey": key},
                )
                if response.status_code == 200:
                    data = response.json().get("data", {}).get("attributes", {})
                    last_analysis = data.get("last_analysis_stats", {})
                    malicious_count = last_analysis.get("malicious", 0)
                    total = sum(last_analysis.values()) or 1
                    profile.virustotal_data = {
                        "malicious": malicious_count,
                        "total_engines": total,
                        "reputation": data.get("reputation", 0),
                    }
                    profile.malicious = malicious_count > 5
                    profile.reputation_score = min(10.0, (malicious_count / total) * 10)
                    profile.sources_checked.append("virustotal")
        except Exception as e:
            profile.errors.append(f"VirusTotal query failed: {e}")

    async def _query_shodan(self, ip: str, profile: ThreatProfile) -> None:
        """Query Shodan for host intelligence."""
        if not self.api_config or not self.api_config.shodan_key:
            return
        try:
            import asyncio
            import shodan  # type: ignore[import]
            api = shodan.Shodan(self.api_config.get_shodan_key())
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(None, api.host, ip)
            profile.shodan_data = {
                "org": data.get("org"),
                "asn": data.get("asn"),
                "ports": data.get("ports", []),
                "tags": data.get("tags", []),
            }
            profile.tags.extend(data.get("tags", []))
            profile.sources_checked.append("shodan")
        except Exception as e:
            profile.errors.append(f"Shodan query failed: {e}")
