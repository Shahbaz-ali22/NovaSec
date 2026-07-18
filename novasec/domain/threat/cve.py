"""
NovaSec CVE Enrichment — Domain Layer.

Looks up CVE details from the NIST National Vulnerability Database (NVD)
API v2 and enriches findings with CVSS scores, descriptions, and CPEs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CVEDetail:
    """Enriched CVE information from NVD."""
    cve_id: str
    description: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str = ""
    severity: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published_date: str = ""
    modified_date: str = ""
    error: str = ""


class CVELookup:
    """
    Queries the NIST NVD API for CVE details.

    Usage::

        lookup = CVELookup(api_key="optional-nvd-key")
        detail = await lookup.get_cve("CVE-2023-44487")
        print(detail.cvss_score)
    """

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key
        self._cache: dict[str, CVEDetail] = {}

    async def get_cve(self, cve_id: str) -> CVEDetail:
        """Fetch CVE details for *cve_id* from NVD.

        Results are cached in-process to avoid redundant API calls.
        """
        cve_id = cve_id.upper().strip()
        if cve_id in self._cache:
            return self._cache[cve_id]

        detail = await self._fetch_from_nvd(cve_id)
        self._cache[cve_id] = detail
        return detail

    async def get_cves_bulk(self, cve_ids: list[str]) -> list[CVEDetail]:
        """Fetch multiple CVEs, respecting NVD rate limits."""
        import asyncio
        results = []
        for cve_id in cve_ids:
            results.append(await self.get_cve(cve_id))
            await asyncio.sleep(0.6)  # NVD rate limit: ~100 req/30s without key
        return results

    async def _fetch_from_nvd(self, cve_id: str) -> CVEDetail:
        """Perform the actual NVD API request."""
        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    NVD_API_BASE,
                    params={"cveId": cve_id},
                    headers=headers,
                )
                if response.status_code == 404:
                    return CVEDetail(cve_id=cve_id, error="CVE not found in NVD")
                if response.status_code != 200:
                    return CVEDetail(
                        cve_id=cve_id,
                        error=f"NVD API error: HTTP {response.status_code}",
                    )

                data = response.json()
                return self._parse_nvd_response(cve_id, data)

        except httpx.TimeoutException:
            return CVEDetail(cve_id=cve_id, error="NVD API request timed out")
        except Exception as e:
            return CVEDetail(cve_id=cve_id, error=str(e))

    def _parse_nvd_response(self, cve_id: str, data: dict[str, Any]) -> CVEDetail:
        """Parse NVD API v2 JSON response into :class:`CVEDetail`."""
        detail = CVEDetail(cve_id=cve_id)
        try:
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                detail.error = "No data returned from NVD"
                return detail

            cve_data = vulnerabilities[0].get("cve", {})

            # Description (English)
            descriptions = cve_data.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    detail.description = desc.get("value", "")
                    break

            # CVSS metrics
            metrics = cve_data.get("metrics", {})
            for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(version_key, [])
                if metric_list:
                    primary = next(
                        (m for m in metric_list if m.get("type") == "Primary"),
                        metric_list[0],
                    )
                    cvss_data = primary.get("cvssData", {})
                    detail.cvss_score = cvss_data.get("baseScore")
                    detail.cvss_vector = cvss_data.get("vectorString")
                    detail.severity = primary.get("baseSeverity", "")
                    detail.cvss_version = version_key
                    break

            # CWE
            weaknesses = cve_data.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    if desc.get("value", "").startswith("CWE-"):
                        detail.cwe_ids.append(desc["value"])

            # References
            refs = cve_data.get("references", [])
            detail.references = [r.get("url", "") for r in refs[:10]]

            detail.published_date = cve_data.get("published", "")
            detail.modified_date = cve_data.get("lastModified", "")

        except Exception as e:
            detail.error = f"Parse error: {e}"

        return detail
