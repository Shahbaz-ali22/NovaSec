"""
Network utility functions — IP, CIDR, URL, domain validation.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse


def is_valid_ip(value: str) -> bool:
    """Return True if *value* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_cidr(value: str) -> bool:
    """Return True if *value* is a valid CIDR network (e.g. 192.168.1.0/24)."""
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    """Return True if *value* is a syntactically valid domain name."""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value))


def is_valid_url(value: str) -> bool:
    """Return True if *value* is a valid HTTP/HTTPS URL."""
    try:
        result = urlparse(value)
        return result.scheme in ("http", "https") and bool(result.netloc)
    except ValueError:
        return False


def is_valid_target(value: str) -> bool:
    """Return True if *value* is a valid scan target (IP, CIDR, domain, or URL)."""
    return (
        is_valid_ip(value)
        or is_valid_cidr(value)
        or is_valid_domain(value)
        or is_valid_url(value)
    )


def expand_cidr(cidr: str) -> list[str]:
    """Expand a CIDR range into a list of host IP strings.

    Limited to /16 or smaller to prevent accidental huge expansions.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses > 65536:
        raise ValueError(f"CIDR {cidr} is too large (> /16). Use a smaller range.")
    return [str(host) for host in net.hosts()]


def extract_hostname(url: str) -> str:
    """Extract the hostname from a URL or return the value as-is."""
    parsed = urlparse(url)
    return parsed.netloc or url


def port_range_to_list(port_range: str) -> list[int]:
    """Convert a port range string to a list of integers.

    Supports formats: "80", "80,443", "1-1000", "22,80,443,8000-8100"
    """
    ports: list[int] = []
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start, end = int(start_str), int(end_str)
            if start > end or start < 1 or end > 65535:
                raise ValueError(f"Invalid port range: {part}")
            ports.extend(range(start, end + 1))
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError(f"Invalid port number: {port}")
            ports.append(port)
    return sorted(set(ports))


def resolve_hostname(hostname: str) -> str | None:
    """Synchronously resolve *hostname* to an IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None
