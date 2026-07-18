"""NovaSec VirusTotal API v3 Adapter."""
from __future__ import annotations
import logging
from typing import Any
import httpx

logger = logging.getLogger(__name__)
VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalAdapter:
    """VirusTotal v3 API adapter for file, URL, IP, and domain reputation."""

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self._headers = {"x-apikey": api_key}

    async def get_ip_report(self, ip: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(f"{VT_BASE}/ip_addresses/{ip}", headers=self._headers)
            r.raise_for_status()
            return r.json().get("data", {}).get("attributes", {})

    async def get_domain_report(self, domain: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(f"{VT_BASE}/domains/{domain}", headers=self._headers)
            r.raise_for_status()
            return r.json().get("data", {}).get("attributes", {})

    async def get_file_report(self, sha256_hash: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(f"{VT_BASE}/files/{sha256_hash}", headers=self._headers)
            r.raise_for_status()
            return r.json().get("data", {}).get("attributes", {})
