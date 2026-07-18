"""
NovaSec Shodan API Adapter — Infrastructure Layer.

Wraps the official shodan Python client behind the IThreatIntelAPI interface.
"""

from __future__ import annotations
import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


class ShodanAdapter:
    """
    Shodan Internet DB API adapter.

    Implements host lookup, search, and exploit queries via the Shodan Python SDK.
    Requires a valid Shodan API key configured in ``apis.shodan_key``.
    """

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self._api: Any = None

    def _get_api(self) -> Any:
        if self._api is None:
            try:
                import shodan  # type: ignore[import]
                self._api = shodan.Shodan(self.api_key)
            except ImportError:
                raise ImportError("shodan package not installed: pip install shodan")
        return self._api

    async def host(self, ip: str) -> dict[str, Any]:
        """Look up a host by IP address."""
        loop = asyncio.get_event_loop()
        try:
            data = await loop.run_in_executor(None, self._get_api().host, ip)
            return {
                "ip": data.get("ip_str"),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "asn": data.get("asn"),
                "country": data.get("country_name"),
                "city": data.get("city"),
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "vulns": list(data.get("vulns", {}).keys()),
                "tags": data.get("tags", []),
                "services": [
                    {
                        "port": svc.get("port"),
                        "transport": svc.get("transport"),
                        "product": svc.get("product", ""),
                        "version": svc.get("version", ""),
                        "banner": svc.get("data", "")[:200],
                    }
                    for svc in data.get("data", [])
                ],
            }
        except Exception as e:
            logger.error("Shodan host lookup failed for %s: %s", ip, e)
            raise

    async def search(self, query: str, page: int = 1) -> dict[str, Any]:
        """Execute a Shodan search query."""
        loop = asyncio.get_event_loop()
        try:
            results = await loop.run_in_executor(
                None, lambda: self._get_api().search(query, page=page)
            )
            return {
                "total": results.get("total", 0),
                "matches": [
                    {"ip": m.get("ip_str"), "port": m.get("port"), "org": m.get("org")}
                    for m in results.get("matches", [])[:20]
                ],
            }
        except Exception as e:
            logger.error("Shodan search failed: %s", e)
            raise

    async def get_api_info(self) -> dict[str, Any]:
        """Return Shodan API key information (credits, plan, etc.)."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._get_api().info)
