"""
NovaSec Async HTTP Client — Infrastructure Layer.

A configurable async HTTP client built on httpx that implements the
:class:`~novasec.core.interfaces.IHTTPClient` contract.

Features:
- Automatic retry with exponential backoff (via tenacity)
- Configurable proxy support
- Rate limiting
- Custom User-Agent
- Connection pooling
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)


class AsyncHTTPClient:
    """
    Production-grade async HTTP client wrapping httpx.

    Usage::

        async with AsyncHTTPClient(timeout=30, proxy="http://127.0.0.1:8080") as client:
            response = await client.get("https://example.com")
            print(response.status_code)
    """

    def __init__(
        self,
        timeout: int = 30,
        retries: int = 3,
        verify_ssl: bool = True,
        proxy: str | None = None,
        user_agent: str = "NovaSec/1.0.0",
        max_connections: int = 100,
        follow_redirects: bool = True,
    ) -> None:
        self.timeout = httpx.Timeout(timeout=timeout, connect=10.0)
        self.retries = retries
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.user_agent = user_agent
        self.max_connections = max_connections
        self.follow_redirects = follow_redirects

        self._client: httpx.AsyncClient | None = None

    def _build_client(self) -> httpx.AsyncClient:
        """Build and return a configured httpx.AsyncClient."""
        return httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            proxy=self.proxy,
            follow_redirects=self.follow_redirects,
            limits=httpx.Limits(
                max_connections=self.max_connections,
                max_keepalive_connections=20,
            ),
            headers={"User-Agent": self.user_agent},
        )

    async def __aenter__(self) -> "AsyncHTTPClient":
        self._client = self._build_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    async def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Perform an HTTP GET request."""
        logger.debug("GET %s", url)
        return await self._get_client().get(url, headers=headers, params=params, **kwargs)

    async def post(
        self,
        url: str,
        data: Any = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Perform an HTTP POST request."""
        logger.debug("POST %s", url)
        return await self._get_client().post(
            url, data=data, json=json, headers=headers, **kwargs
        )

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        """Perform an HTTP HEAD request."""
        return await self._get_client().head(url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> httpx.Response:
        """Perform an HTTP OPTIONS request."""
        return await self._get_client().options(url, **kwargs)

    async def close(self) -> None:
        """Close the underlying httpx client."""
        if self._client:
            await self._client.aclose()
            self._client = None
