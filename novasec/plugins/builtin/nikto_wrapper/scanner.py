"""NovaSec Nikto Web Scanner Plugin."""
from __future__ import annotations
import logging
import re
import shutil
from typing import Any

from novasec.plugins.base import PluginBase, PluginManifest
from novasec.reporting.models import Evidence, Finding, FindingSet, Severity

logger = logging.getLogger(__name__)


class NiktoScanner(PluginBase):
    """Wraps the Nikto web vulnerability scanner via subprocess."""

    def validate_target(self, target: str) -> bool:
        from novasec.utils.network import is_valid_url, is_valid_domain, is_valid_ip
        return is_valid_url(target) or is_valid_domain(target) or is_valid_ip(target)

    async def run(
        self,
        target: str,
        context: Any,
        timeout: int = 120,
        **options: Any,
    ) -> FindingSet:
        """Execute Nikto against *target* and parse output into findings."""
        finding_set = FindingSet(
            scan_id=context.scan_id,
            target=target,
            plugin_source=self.name,
        )

        if not shutil.which("nikto"):
            logger.error("nikto not found. Install: sudo apt install nikto")
            return finding_set

        from novasec.infrastructure.subprocess.runner import SubprocessRunner
        runner = SubprocessRunner(timeout=timeout)

        args = ["nikto", "-h", target, "-Format", "txt", "-nointeractive"]
        result = await runner.run(args, timeout=timeout)

        if result.output:
            self._parse_nikto_output(result.output, target, finding_set)

        return finding_set

    def _parse_nikto_output(
        self, output: str, target: str, finding_set: FindingSet
    ) -> None:
        """Parse nikto text output and create findings."""
        # Nikto output lines starting with "+ " are findings
        for line in output.splitlines():
            if line.startswith("+ ") and "Server:" not in line and "Target:" not in line:
                msg = line[2:].strip()
                if not msg:
                    continue
                # Guess severity from keywords
                severity = Severity.INFO
                if any(kw in msg.lower() for kw in ["vuln", "xss", "injection", "sql"]):
                    severity = Severity.HIGH
                elif any(kw in msg.lower() for kw in ["missing", "header", "allow"]):
                    severity = Severity.MEDIUM

                finding_set.add(
                    Finding(
                        title=f"Nikto: {msg[:80]}",
                        severity=severity,
                        description=msg,
                        target=target,
                        plugin_source=self.name,
                        tags=["nikto", "web", "misconfiguration"],
                        evidence=[Evidence(type="output", data=line, description="Nikto finding")],
                    )
                )

    async def cleanup(self) -> None:
        pass
