"""
NovaSec Vulnerability Scanning — Domain Layer.

Aggregates findings from multiple scan sources, deduplicates them,
correlates with CVE data, and computes CVSS scores.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from novasec.reporting.models import Finding, FindingSet, Severity

if TYPE_CHECKING:
    from novasec.core.context import ExecutionContext

logger = logging.getLogger(__name__)


class VulnerabilityCorrelator:
    """
    Aggregates and deduplicates findings from multiple scan sources.

    Usage::

        correlator = VulnerabilityCorrelator()
        combined = correlator.merge([finding_set_1, finding_set_2])
        deduplicated = correlator.deduplicate(combined)
    """

    def merge(self, finding_sets: list[FindingSet]) -> FindingSet:
        """Merge multiple :class:`FindingSet` objects into one."""
        merged = FindingSet()
        for fs in finding_sets:
            merged.findings.extend(fs.findings)
        logger.info("Merged %d finding sets → %d total findings", len(finding_sets), len(merged))
        return merged

    def deduplicate(self, finding_set: FindingSet) -> FindingSet:
        """Remove duplicate findings based on title + target + severity."""
        seen: set[tuple[str, str, str]] = set()
        unique: list[Finding] = []
        for finding in finding_set.findings:
            key = (finding.title.lower(), finding.target.lower(), finding.severity.value)
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        removed = len(finding_set.findings) - len(unique)
        if removed > 0:
            logger.debug("Deduplicated %d duplicate findings", removed)

        return FindingSet(
            scan_id=finding_set.scan_id,
            target=finding_set.target,
            findings=unique,
        )

    def sort_by_severity(self, finding_set: FindingSet) -> FindingSet:
        """Return a new FindingSet sorted by severity (most critical first)."""
        sorted_findings = sorted(
            finding_set.findings,
            key=lambda f: f.severity.sort_order,
        )
        return FindingSet(
            scan_id=finding_set.scan_id,
            target=finding_set.target,
            findings=sorted_findings,
        )
