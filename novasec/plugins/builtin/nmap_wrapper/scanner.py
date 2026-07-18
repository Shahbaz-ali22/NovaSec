"""
NovaSec Nmap Wrapper Plugin.

Integrates nmap port scanning via python-nmap. Supports:
- TCP SYN scan (requires root)
- TCP connect scan (no root required)
- Service version detection (-sV)
- Default NSE scripts (-sC)
- OS detection (-O, requires root)

Usage (via CLI)::

    novasec scan nmap --target 192.168.1.1 --ports 1-1000
    novasec scan nmap --target 10.0.0.0/24 --profile aggressive
"""

from __future__ import annotations

import logging
import shutil
from typing import Any

from novasec.plugins.base import PluginBase, PluginManifest
from novasec.reporting.models import Evidence, Finding, FindingSet, Severity

logger = logging.getLogger(__name__)

# Service-to-severity mapping for well-known dangerous services
DANGEROUS_SERVICES = {
    "telnet": (Severity.HIGH, "Plaintext protocol — use SSH instead"),
    "ftp": (Severity.MEDIUM, "Plaintext credentials — use SFTP/FTPS instead"),
    "vnc": (Severity.HIGH, "VNC exposed — restrict access via firewall"),
    "rlogin": (Severity.CRITICAL, "rlogin is highly insecure — disable immediately"),
    "rsh": (Severity.CRITICAL, "rsh is highly insecure — disable immediately"),
    "tftp": (Severity.HIGH, "TFTP has no authentication — disable or restrict"),
}


class NmapScanner(PluginBase):
    """
    Nmap port and service scanner plugin.

    Wraps the nmap command-line tool via python-nmap, parses XML output,
    and converts results into NovaSec :class:`~novasec.reporting.models.Finding` objects.
    """

    def validate_target(self, target: str) -> bool:
        """Accept IPs, CIDRs, and hostnames."""
        from novasec.utils.network import is_valid_ip, is_valid_cidr, is_valid_domain
        return is_valid_ip(target) or is_valid_cidr(target) or is_valid_domain(target)

    async def run(
        self,
        target: str,
        context: Any,
        ports: str = "1-1024",
        arguments: str = "-sV -sC",
        **options: Any,
    ) -> FindingSet:
        """
        Execute nmap against *target*.

        Args:
            target: IP address, CIDR range, or hostname.
            context: The current :class:`~novasec.core.context.ExecutionContext`.
            ports: Port specification (e.g. "1-1000", "80,443,8080").
            arguments: Additional nmap arguments (default: ``-sV -sC``).

        Returns:
            A :class:`FindingSet` with all discovered services and vulnerabilities.
        """
        if not shutil.which("nmap"):
            logger.error("nmap not found. Install with: sudo apt install nmap")
            return FindingSet(
                scan_id=context.scan_id,
                target=target,
                plugin_source=self.name,
            )

        # Adjust scan arguments based on profile
        if context.profile == "stealth":
            arguments = "-sT -T2"  # TCP connect, slow timing
        elif context.profile == "aggressive":
            arguments = "-sV -sC -O -T4"  # Fast, version+script+OS

        logger.info(
            "Nmap scan: target=%s, ports=%s, args=%s",
            target, ports, arguments,
        )

        try:
            import nmap  # type: ignore[import]
        except ImportError:
            logger.error("python-nmap not installed: pip install python-nmap")
            return FindingSet(
                scan_id=context.scan_id, target=target, plugin_source=self.name
            )

        # Execute nmap in a thread pool (blocking call)
        import asyncio
        loop = asyncio.get_event_loop()
        nm = nmap.PortScanner()

        try:
            scan_result = await loop.run_in_executor(
                None,
                lambda: nm.scan(target, ports=ports, arguments=arguments),
            )
        except nmap.PortScannerError as e:
            logger.error("Nmap scan failed: %s", e)
            return FindingSet(
                scan_id=context.scan_id, target=target, plugin_source=self.name
            )
        except Exception as e:
            logger.error("Unexpected nmap error: %s", e)
            return FindingSet(
                scan_id=context.scan_id, target=target, plugin_source=self.name
            )

        return self._parse_results(nm, target, context, arguments)

    def _parse_results(
        self,
        nm: Any,
        target: str,
        context: Any,
        arguments: str,
    ) -> FindingSet:
        """Parse nmap PortScanner output into a :class:`FindingSet`."""
        finding_set = FindingSet(
            scan_id=context.scan_id,
            target=target,
            plugin_source=self.name,
        )

        all_open_ports: list[str] = []

        for host in nm.all_hosts():
            host_state = nm[host].state()
            if host_state != "up":
                continue

            host_info = []

            # Parse open TCP ports
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    port_data = nm[host][proto][port]
                    state = port_data.get("state", "")
                    if state != "open":
                        continue

                    name = port_data.get("name", "")
                    product = port_data.get("product", "")
                    version = port_data.get("version", "")
                    service_str = " ".join(filter(None, [name, product, version]))

                    port_line = f"{port:5d}/{proto}  open  {service_str}"
                    all_open_ports.append(port_line)
                    host_info.append(port_line)

                    # Flag dangerous services
                    if name.lower() in DANGEROUS_SERVICES:
                        severity, remediation = DANGEROUS_SERVICES[name.lower()]
                        finding_set.add(
                            Finding(
                                title=f"Dangerous Service Exposed: {name.upper()} on {host}:{port}",
                                severity=severity,
                                description=(
                                    f"The service '{name}' ({service_str}) is exposed on "
                                    f"{host}:{port}/{proto}. {remediation}"
                                ),
                                target=f"{host}:{port}",
                                plugin_source=self.name,
                                port=port,
                                protocol=proto,
                                service=name,
                                remediation=remediation,
                                tags=["nmap", "network", "dangerous-service", name.lower()],
                            )
                        )

                    # Check for NSE script output (potential vulnerabilities)
                    script_output = port_data.get("script", {})
                    for script_name, script_result in script_output.items():
                        if any(kw in script_result.lower() for kw in ["vuln", "vulnerable", "exploit"]):
                            finding_set.add(
                                Finding(
                                    title=f"NSE Script Finding: {script_name} on {host}:{port}",
                                    severity=Severity.MEDIUM,
                                    description=f"Nmap NSE script '{script_name}' produced a potential vulnerability finding.",
                                    target=f"{host}:{port}",
                                    plugin_source=self.name,
                                    port=port,
                                    protocol=proto,
                                    service=name,
                                    tags=["nmap", "nse", "script"],
                                    evidence=[
                                        Evidence(
                                            type="output",
                                            data=script_result[:2000],
                                            description=f"NSE script {script_name} output",
                                        )
                                    ],
                                )
                            )

            # OS detection
            osmatch = nm[host].get("osmatch", [])
            if osmatch:
                best_match = osmatch[0]
                os_guess = f"{best_match.get('name')} (accuracy: {best_match.get('accuracy')}%)"
                finding_set.add(
                    Finding(
                        title=f"OS Fingerprint: {host} — {best_match.get('name')}",
                        severity=Severity.INFO,
                        description=f"Nmap OS detection identified {host} as: {os_guess}",
                        target=host,
                        plugin_source=self.name,
                        tags=["nmap", "os-detection", "fingerprinting"],
                    )
                )

            # Per-host summary finding
            if host_info:
                finding_set.add(
                    Finding(
                        title=f"Open Ports on {host}: {len(host_info)} services",
                        severity=Severity.INFO,
                        description=f"Nmap discovered {len(host_info)} open ports on {host}.",
                        target=host,
                        plugin_source=self.name,
                        tags=["nmap", "port-scan", "network"],
                        evidence=[
                            Evidence(
                                type="output",
                                data=f"nmap {arguments} -p {','.join(str(p.split('/')[0].strip()) for p in host_info[:5])} {host}\n\n"
                                     + "\n".join(host_info),
                                description="Nmap scan output",
                            )
                        ],
                    )
                )

        return finding_set

    async def cleanup(self) -> None:
        """No resources to release."""
