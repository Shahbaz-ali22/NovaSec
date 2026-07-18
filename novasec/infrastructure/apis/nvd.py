"""NovaSec NIST NVD API v2 Adapter."""
from __future__ import annotations
import logging
from typing import Any
import httpx

logger = logging.getLogger(__name__)
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDAdapter:
    """NIST National Vulnerability Database API v2 adapter."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key

    def _headers(self) -> dict[str, str]:
        if self.api_key:
            return {"apiKey": self.api_key}
        return {}

    async def get_cve(self, cve_id: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(NVD_BASE, params={"cveId": cve_id}, headers=self._headers())
            r.raise_for_status()
            vulns = r.json().get("vulnerabilities", [])
            return vulns[0].get("cve", {}) if vulns else {}

    async def search_by_keyword(self, keyword: str, results_per_page: int = 20) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(
                NVD_BASE,
                params={"keywordSearch": keyword, "resultsPerPage": results_per_page},
                headers=self._headers(),
            )
            r.raise_for_status()
            return [v.get("cve", {}) for v in r.json().get("vulnerabilities", [])]
