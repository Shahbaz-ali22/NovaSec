"""
NovaSec Scan Domain Unit Tests.
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from novasec.core.context import ExecutionContext
from novasec.domain.scan.web import WebScanner, WebScanResult


@pytest.mark.asyncio
async def test_web_scanner_headers(mock_context: ExecutionContext) -> None:
    """Test passive header evaluation on a target URL."""
    scanner = WebScanner()
    
    # Run mock request/response loop
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Server": "Apache/2.4.41",
            "Content-Type": "text/html",
        }
        mock_get.return_value = mock_response
        
        result = await scanner.scan("http://example.com")
        
        assert isinstance(result, WebScanResult)
        assert result.status_code == 200
        assert "Server" in result.headers
        assert len(result.missing_security_headers) > 0  # HSTS etc. missing
        
        findings = await scanner.to_findings(result, mock_context)
        assert len(findings.findings) > 0
