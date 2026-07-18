"""NovaSec HTTP proxy configuration."""
from __future__ import annotations


def get_proxy_config(proxy_url: str | None) -> dict | None:
    """Return httpx-compatible proxy config dict from a proxy URL string."""
    if not proxy_url:
        return None
    return {"all://": proxy_url}
