"""
NovaSec DNS Enumeration Unit Tests.
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from novasec.core.context import ExecutionContext
from novasec.domain.recon.dns import DNSEnumerator, DNSEnumerationResult
from novasec.reporting.models import Severity


@pytest.mark.asyncio
@patch("dns.asyncresolver.Resolver")
async def test_dns_enumeration(mock_resolver_cls, mock_context: ExecutionContext) -> None:
    """Test DNS query resolving mock logic."""
    # Setup mock query responses
    mock_resolver = mock_resolver_cls.return_value
    mock_resolver.resolve = AsyncMock()
    
    # We only return MX record and fallback for others
    class MockRecord:
        def __init__(self, val):
            self.exchange = val
            self.preference = 10
    class MockAnswers(list):
        ttl = 3600

    mock_ans = MockAnswers([MockRecord("mail.example.com")])
    mock_resolver.resolve.return_value = mock_ans
    
    enumerator = DNSEnumerator()
    
    # We override record_types to search MX records only to simplify mock layout
    enumerator.record_types = ["MX"]
    result = await enumerator.enumerate("example.com")
    
    assert isinstance(result, DNSEnumerationResult)
    assert len(result.records) == 1
    assert result.records[0].value == "mail.example.com"
    
    # Verify missing SPF / DMARC triggers are mapped to findings
    findings = await enumerator.to_findings(result, mock_context)
    assert len(findings.findings) > 0
