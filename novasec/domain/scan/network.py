"""
NovaSec Network Scanning — Domain Layer.

Network-level scanning: OS fingerprinting, service version detection,
and network topology mapping (uses nmap plugin when available).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from novasec.reporting.models import Evidence, Finding, FindingSet, Severity
from novasec.utils.network import is_valid_ip, is_valid_cidr

if TYPE_CHECKING:
    from novasec.core.context import ExecutionContext

logger = logging.getLogger(__name__)


@dataclass
class NetworkHost:
    """A discovered network host."""
    ip: str
    hostname: str = ""
    os_guess: str = ""
    open_ports: list[int] = field(default_factory=list)
    mac_address: str = ""
    vendor: str = ""
    state: str = "up"


class NetworkMapper:
    """
    Network topology mapper — discovers live hosts and services.

    For deep scanning, this delegates to the nmap_wrapper plugin.
    This class provides the domain-level interface and result modelling.
    """

    async def discover_hosts(
        self,
        cidr: str,
        context: "ExecutionContext",
    ) -> list[NetworkHost]:
        """Discover live hosts in *cidr*.

        In production, this should delegate to the nmap plugin.
        Returns an empty list as a safe stub.
        """
        if not (is_valid_ip(cidr) or is_valid_cidr(cidr)):
            logger.warning("Invalid network target: %s", cidr)
            return []

        logger.info("Network host discovery: %s", cidr)
        # Delegate to nmap plugin if registered
        return []

    async def to_findings(
        self,
        hosts: list[NetworkHost],
        target: str,
        context: "ExecutionContext",
    ) -> FindingSet:
        """Convert network discovery results to a :class:`FindingSet`."""
        finding_set = FindingSet(
            scan_id=context.scan_id,
            target=target,
            plugin_source="network_mapper",
        )

        if hosts:
            host_lines = [
                f"{h.ip:20s} {h.hostname:30s} {h.os_guess}"
                for h in hosts
            ]
            finding_set.add(
                Finding(
                    title=f"Live Hosts Discovered: {target} ({len(hosts)} hosts)",
                    severity=Severity.INFO,
                    description=f"Network discovery found {len(hosts)} live hosts in {target}.",
                    target=target,
                    plugin_source="network_mapper",
                    tags=["network", "host-discovery", "recon"],
                    evidence=[
                        Evidence(
                            type="raw",
                            data="\n".join(host_lines),
                            description="Discovered hosts",
                        )
                    ],
                )
            )

        return finding_set
