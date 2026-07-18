"""NovaSec FFUF Web Fuzzer Plugin."""
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

DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"
FALLBACK_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


class FFUFFuzzer(PluginBase):
    """FFUF-based web directory and endpoint fuzzer."""

    def validate_target(self, target: str) -> bool:
        from novasec.utils.network import is_valid_url
        return is_valid_url(target)

    async def run(
        self,
        target: str,
        context: Any,
        wordlist: str | None = None,
        extensions: str = "php,html,txt,js",
        status_codes: str = "200,204,301,302,307,401,403",
        timeout: int = 300,
        **options: Any,
    ) -> FindingSet:
        """Fuzz *target* with FFUF for hidden directories and files."""
        finding_set = FindingSet(
            scan_id=context.scan_id,
            target=target,
            plugin_source=self.name,
        )

        if not shutil.which("ffuf"):
            logger.error("ffuf not found. Install: sudo apt install ffuf")
            return finding_set

        # Resolve wordlist
        wl = wordlist or (
            DEFAULT_WORDLIST if Path(DEFAULT_WORDLIST).exists()
            else FALLBACK_WORDLIST
        )

        if not Path(wl).exists():
            finding_set.add(Finding(
                title="FFUF: Wordlist not found",
                severity=Severity.INFO,
                description=f"Could not find wordlist at {wl}. Install seclists: sudo apt install seclists",
                target=target,
                plugin_source=self.name,
                tags=["ffuf"],
            ))
            return finding_set

        url = f"{target.rstrip('/')}/FUZZ"
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            output_file = tf.name

        from novasec.infrastructure.subprocess.runner import SubprocessRunner
        runner = SubprocessRunner(timeout=timeout)

        args = [
            "ffuf",
            "-u", url,
            "-w", wl,
            "-o", output_file,
            "-of", "json",
            "-mc", status_codes,
            "-t", "50" if context.profile != "stealth" else "10",
            "-s",  # silent mode (no banner)
        ]

        await runner.run(args, timeout=timeout)
        self._parse_ffuf_output(output_file, target, finding_set)
        Path(output_file).unlink(missing_ok=True)

        return finding_set

    def _parse_ffuf_output(
        self, output_file: str, target: str, finding_set: FindingSet
    ) -> None:
        """Parse FFUF JSON output and create findings."""
        try:
            data = json.loads(Path(output_file).read_text())
        except Exception:
            return

        results = data.get("results", [])
        if not results:
            return

        paths = []
        for r in results:
            url = r.get("url", "")
            status = r.get("status", 0)
            length = r.get("length", 0)
            paths.append(f"{status}  {length:8d}  {url}")

            # Flag interesting status codes
            if status in (200, 403):
                severity = Severity.INFO if status == 200 else Severity.LOW
                finding_set.add(
                    Finding(
                        title=f"{'Content Found' if status == 200 else 'Forbidden Path'}: {url}",
                        severity=severity,
                        description=f"FFUF discovered {'accessible content' if status == 200 else 'a forbidden path'} at {url} (HTTP {status}).",
                        target=url,
                        plugin_source=self.name,
                        tags=["ffuf", "content-discovery", "web"],
                    )
                )

        if paths:
            finding_set.add(
                Finding(
                    title=f"Content Discovery: {target} ({len(results)} paths found)",
                    severity=Severity.INFO,
                    description=f"FFUF discovered {len(results)} paths at {target}.",
                    target=target,
                    plugin_source=self.name,
                    tags=["ffuf", "content-discovery"],
                    evidence=[Evidence(type="raw", data="\n".join(paths[:100]), description="FFUF results")],
                )
            )

    async def cleanup(self) -> None:
        pass
