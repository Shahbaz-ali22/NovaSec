"""NovaSec Censys API Adapter."""
from __future__ import annotations
import logging
from typing import Any
import httpx

logger = logging.getLogger(__name__)
CENSYS_BASE = "https://search.censys.io/api/v2"


class CensysAdapter:
    """Censys Search API adapter for host and certificate enumeration."""

    def __init__(self, api_id: str, api_secret: str) -> None:
        self.auth = (api_id, api_secret)

    async def search_hosts(self, query: str, per_page: int = 25) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=20.0, auth=self.auth) as client:
            r = await client.get(
                f"{CENSYS_BASE}/hosts/search",
                params={"q": query, "per_page": per_page},
            )
            r.raise_for_status()
            return r.json()

    async def view_host(self, ip: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=20.0, auth=self.auth) as client:
            r = await client.get(f"{CENSYS_BASE}/hosts/{ip}")
            r.raise_for_status()
            return r.json().get("result", {})
