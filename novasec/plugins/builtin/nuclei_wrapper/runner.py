"""NovaSec Nuclei Template Scanner Plugin."""
from __future__ import annotations
import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Any

from novasec.plugins.base import PluginBase, PluginManifest
from novasec.reporting.models import Evidence, Finding, FindingSet, Severity

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


class NucleiRunner(PluginBase):
    """Nuclei template-based vulnerability scanner plugin."""

    def validate_target(self, target: str) -> bool:
        from novasec.utils.network import is_valid_url, is_valid_ip, is_valid_domain
        return is_valid_url(target) or is_valid_ip(target) or is_valid_domain(target)

    async def run(
        self,
        target: str,
        context: Any,
        tags: str | None = None,
        templates: str | None = None,
        severity: str = "critical,high,medium",
        timeout: int = 300,
        **options: Any,
    ) -> FindingSet:
        """Execute Nuclei against *target* using specified templates or tags."""
        finding_set = FindingSet(
            scan_id=context.scan_id,
            target=target,
            plugin_source=self.name,
        )

        if not shutil.which("nuclei"):
            logger.error("nuclei not found. Install: sudo apt install nuclei")
            return finding_set

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as tf:
            output_file = tf.name

        from novasec.infrastructure.subprocess.runner import SubprocessRunner
        runner = SubprocessRunner(timeout=timeout)

        args = [
            "nuclei",
            "-target", target,
            "-jsonl-output", output_file,
            "-severity", severity,
            "-silent",
            "-no-color",
        ]
        if tags:
            args.extend(["-tags", tags])
        if templates:
            args.extend(["-t", templates])

        await runner.run(args, timeout=timeout)
        self._parse_nuclei_output(output_file, target, finding_set)
        Path(output_file).unlink(missing_ok=True)

        return finding_set

    def _parse_nuclei_output(
        self, output_file: str, target: str, finding_set: FindingSet
    ) -> None:
        """Parse Nuclei JSONL output and create findings."""
        try:
            content = Path(output_file).read_text(encoding="utf-8")
        except FileNotFoundError:
            return

        count = 0
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = result.get("info", {})
            severity_str = info.get("severity", "info").lower()
            severity = SEVERITY_MAP.get(severity_str, Severity.INFO)

            matched_at = result.get("matched-at", target)
            template_id = result.get("template-id", "unknown")
            name = info.get("name", template_id)
            description = info.get("description", "")
            remediation = info.get("remediation", "")
            refs = info.get("reference", [])
            cve_ids = [
                r for r in (result.get("extracted-results") or [])
                if r.startswith("CVE-")
            ]
            tags = info.get("tags", [])

            finding_set.add(
                Finding(
                    title=f"Nuclei: {name}",
                    severity=severity,
                    description=description or f"Nuclei template '{template_id}' matched.",
                    target=matched_at,
                    plugin_source=self.name,
                    cve_ids=cve_ids,
                    remediation=remediation,
                    references=refs if isinstance(refs, list) else [refs],
                    tags=["nuclei"] + (tags if isinstance(tags, list) else []),
                    evidence=[
                        Evidence(
                            type="raw",
                            data=json.dumps(result, indent=2, default=str)[:2000],
                            description="Nuclei raw result",
                        )
                    ],
                )
            )
            count += 1

        logger.info("Nuclei: %d findings from %s", count, target)

    async def cleanup(self) -> None:
        pass
