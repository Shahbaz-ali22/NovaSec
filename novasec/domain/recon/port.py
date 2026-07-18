"""
NovaSec Port Discovery — Domain Layer.

Performs port scanning via the nmap plugin or a lightweight
asyncio-based TCP connect scanner as a fallback.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from novasec.reporting.models import Evidence, Finding, FindingSet, Severity
from novasec.utils.network import is_valid_ip, is_valid_cidr, expand_cidr, port_range_to_list

if TYPE_CHECKING:
    from novasec.core.context import ExecutionContext

logger = logging.getLogger(__name__)

WELL_KNOWN_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

DANGEROUS_PORTS = {23, 21, 3389, 5900}  # Telnet, FTP, RDP, VNC


@dataclass
class OpenPort:
    """A discovered open port."""
    port: int
    protocol: str = "tcp"
    service: str = ""
    banner: str = ""
    state: str = "open"


@dataclass
class PortScanResult:
    """Port scan results for a single host."""
    host: str
    open_ports: list[OpenPort] = field(default_factory=list)
    error: str = ""

    @property
    def has_dangerous_ports(self) -> bool:
        return any(p.port in DANGEROUS_PORTS for p in self.open_ports)


class PortScanner:
    """
    Lightweight asyncio TCP connect port scanner.

    This is used as a fallback when nmap is not available.
    For full-featured port scanning, use the nmap_wrapper plugin.

    Usage::

        scanner = PortScanner(concurrency=200, timeout=2.0)
        results = await scanner.scan("192.168.1.1", ports="1-1000")
    """

    def __init__(
        self,
        concurrency: int = 200,
        timeout: float = 2.0,
    ) -> None:
        self.concurrency = concurrency
        self.timeout = timeout

    async def scan(
        self,
        host: str,
        ports: str | list[int] = "1-1024",
    ) -> PortScanResult:
        """Scan *host* for open TCP ports.

        Args:
            host: Target IP address or hostname.
            ports: Port specification — "80", "1-1000", "22,80,443,8000-8100".

        Returns:
            A :class:`PortScanResult` with all open ports.
        """
        if isinstance(ports, str):
            port_list = port_range_to_list(ports)
        else:
            port_list = sorted(set(ports))

        logger.info("Port scan: %s (%d ports, concurrency=%d)", host, len(port_list), self.concurrency)

        result = PortScanResult(host=host)
        semaphore = asyncio.Semaphore(self.concurrency)

        async def probe(port: int) -> None:
            async with semaphore:
                if await self._is_port_open(host, port):
                    service = WELL_KNOWN_SERVICES.get(port, "unknown")
                    result.open_ports.append(
                        OpenPort(port=port, protocol="tcp", service=service)
                    )

        await asyncio.gather(*(probe(p) for p in port_list), return_exceptions=True)
        result.open_ports.sort(key=lambda p: p.port)

        logger.info(
            "Port scan complete: %s — %d open ports",
            host, len(result.open_ports),
        )
        return result

    async def _is_port_open(self, host: str, port: int) -> bool:
        """Return True if TCP port *port* on *host* is open."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    async def to_findings(
        self,
        result: PortScanResult,
        context: "ExecutionContext",
    ) -> FindingSet:
        """Convert a :class:`PortScanResult` to a :class:`FindingSet`."""
        finding_set = FindingSet(
            scan_id=context.scan_id,
            target=result.host,
            plugin_source="port_scanner",
        )

        if result.error:
            return finding_set

        # Flag dangerous open ports
        for port_info in result.open_ports:
            if port_info.port in DANGEROUS_PORTS:
                descriptions = {
                    23: ("Telnet Service Detected", Severity.HIGH,
                         "Telnet transmits data including credentials in plaintext.",
                         "Disable Telnet and replace with SSH."),
                    21: ("FTP Service Detected", Severity.MEDIUM,
                         "FTP transmits credentials and data in plaintext.",
                         "Replace FTP with SFTP or FTPS."),
                    3389: ("RDP Exposed", Severity.HIGH,
                           "Remote Desktop Protocol is exposed to the network.",
                           "Restrict RDP access via firewall or VPN."),
                    5900: ("VNC Service Exposed", Severity.HIGH,
                           "VNC remote desktop is exposed.",
                           "Restrict VNC access via firewall or VPN-only."),
                }
                if port_info.port in descriptions:
                    title, severity, desc, remediation = descriptions[port_info.port]
                    finding_set.add(
                        Finding(
                            title=f"{title}: {result.host}:{port_info.port}",
                            severity=severity,
                            description=desc,
                            target=f"{result.host}:{port_info.port}",
                            plugin_source="port_scanner",
                            port=port_info.port,
                            protocol="tcp",
                            service=port_info.service,
                            remediation=remediation,
                            tags=["network", "open-port", port_info.service.lower()],
                        )
                    )

        # Informational: all open ports
        if result.open_ports:
            port_lines = [
                f"{p.port:5d}/tcp   {p.state:6s}  {p.service}"
                for p in result.open_ports
            ]
            finding_set.add(
                Finding(
                    title=f"Open Ports Discovered: {result.host} ({len(result.open_ports)} ports)",
                    severity=Severity.INFO,
                    description=f"Port scan of {result.host} found {len(result.open_ports)} open TCP ports.",
                    target=result.host,
                    plugin_source="port_scanner",
                    tags=["network", "port-scan", "recon"],
                    evidence=[
                        Evidence(
                            type="raw",
                            data="\n".join(port_lines),
                            description="Open port listing",
                        )
                    ],
                )
            )

        return finding_set
