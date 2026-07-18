"""
NovaSec Core Interfaces (Protocols & ABCs).

Defines the contracts that every framework component must implement.
These are the stable, versioned boundaries between layers — changing them
is a breaking change.

Design: Python Protocol classes are used for structural subtyping (duck typing
with type-checker support), while ABCs are used when shared base behaviour
must be enforced at runtime.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, AsyncIterator, Protocol, runtime_checkable

if TYPE_CHECKING:
    from novasec.core.context import ExecutionContext
    from novasec.reporting.models import Finding, FindingSet, Report


# ---------------------------------------------------------------------------
# Scanner Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class IScanner(Protocol):
    """Contract for any scanner module — domain or plugin-based."""

    @property
    def name(self) -> str:
        """Unique scanner identifier (e.g. 'nmap_wrapper', 'dns_enum')."""
        ...

    async def scan(
        self,
        target: str,
        context: "ExecutionContext",
        **options: Any,
    ) -> "FindingSet":
        """Execute a scan against *target* and return a set of findings."""
        ...

    def validate_target(self, target: str) -> bool:
        """Return True if *target* is a valid input for this scanner."""
        ...


# ---------------------------------------------------------------------------
# Resolver Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class IResolver(Protocol):
    """Contract for DNS / name resolution adapters."""

    async def resolve(
        self,
        hostname: str,
        record_type: str = "A",
    ) -> list[str]:
        """Resolve *hostname* for the given *record_type*."""
        ...

    async def reverse(self, ip: str) -> str | None:
        """Perform a reverse DNS lookup on *ip*."""
        ...


# ---------------------------------------------------------------------------
# HTTP Client Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class IHTTPClient(Protocol):
    """Contract for async HTTP client adapters."""

    async def get(
        self, url: str, headers: dict[str, str] | None = None, **kwargs: Any
    ) -> "HTTPResponse":
        ...

    async def post(
        self,
        url: str,
        data: Any = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> "HTTPResponse":
        ...

    async def __aenter__(self) -> "IHTTPClient":
        ...

    async def __aexit__(self, *args: Any) -> None:
        ...


class HTTPResponse(Protocol):
    """Minimal HTTP response protocol."""

    @property
    def status_code(self) -> int: ...

    @property
    def text(self) -> str: ...

    @property
    def content(self) -> bytes: ...

    def json(self) -> Any: ...

    @property
    def headers(self) -> dict[str, str]: ...


# ---------------------------------------------------------------------------
# Reporter Interface
# ---------------------------------------------------------------------------


class IReporter(ABC):
    """Abstract base for all report formatters.

    Concrete implementations must override ``generate``. The framework
    guarantees that ``generate`` is called with a fully-assembled
    :class:`~novasec.reporting.models.Report` object.
    """

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Machine-readable format identifier (e.g. 'json', 'html', 'pdf')."""

    @property
    @abstractmethod
    def file_extension(self) -> str:
        """File extension for output files (e.g. '.json', '.html', '.pdf')."""

    @abstractmethod
    def generate(self, report: "Report") -> bytes:
        """Serialise *report* into the target format and return raw bytes."""

    def write_to_file(self, report: "Report", output_path: str) -> None:
        """Convenience method to write the report to *output_path*."""
        import pathlib

        data = self.generate(report)
        pathlib.Path(output_path).write_bytes(data)


# ---------------------------------------------------------------------------
# Plugin Interface
# ---------------------------------------------------------------------------


class IPlugin(ABC):
    """Abstract base for all NovaSec plugins.

    Every plugin — first-party or community — must inherit from this class.
    The framework calls lifecycle methods in this order:

        ``setup`` → ``validate_target`` → ``run`` → ``cleanup``
    """

    @property
    @abstractmethod
    def manifest(self) -> Any:
        """Return the plugin's :class:`~novasec.plugins.base.PluginManifest`."""

    @abstractmethod
    async def setup(self, context: "ExecutionContext") -> None:
        """Initialize plugin resources before execution."""

    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """Return True if *target* is valid for this plugin."""

    @abstractmethod
    async def run(
        self,
        target: str,
        context: "ExecutionContext",
        **options: Any,
    ) -> "FindingSet":
        """Execute plugin logic and return findings."""

    @abstractmethod
    async def cleanup(self) -> None:
        """Release any resources held by this plugin."""

    def get_help(self) -> str:
        """Return human-readable plugin usage help."""
        manifest = self.manifest
        return (
            f"{manifest.display_name} v{manifest.version}\n"
            f"{manifest.description}\n"
            f"Author: {manifest.author}\n"
            f"Category: {manifest.category}"
        )


# ---------------------------------------------------------------------------
# Storage / Repository Interface
# ---------------------------------------------------------------------------


class IStorage(ABC):
    """Abstract base for persistence backends."""

    @abstractmethod
    async def save_finding(self, finding: "Finding") -> str:
        """Persist a finding and return its storage ID."""

    @abstractmethod
    async def get_findings(
        self,
        scan_id: str | None = None,
        severity: str | None = None,
    ) -> list["Finding"]:
        """Retrieve findings, optionally filtered."""

    @abstractmethod
    async def save_scan_session(self, session: dict[str, Any]) -> None:
        """Persist a scan session metadata record."""

    @abstractmethod
    async def get_scan_sessions(self) -> list[dict[str, Any]]:
        """Retrieve all scan session records."""


# ---------------------------------------------------------------------------
# Event Bus Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class IEventBus(Protocol):
    """Contract for the internal publish/subscribe event bus."""

    def subscribe(self, event_name: str, handler: Any) -> None:
        """Register *handler* to be called when *event_name* is published."""
        ...

    def unsubscribe(self, event_name: str, handler: Any) -> None:
        """Remove *handler* from *event_name* subscriptions."""
        ...

    async def publish(self, event_name: str, **payload: Any) -> None:
        """Publish *event_name* with optional *payload* to all subscribers."""
        ...


# ---------------------------------------------------------------------------
# Threat Intelligence API Interface
# ---------------------------------------------------------------------------


@runtime_checkable
class IThreatIntelAPI(Protocol):
    """Contract for external threat intelligence API adapters."""

    @property
    def api_name(self) -> str: ...

    async def lookup_ip(self, ip: str) -> dict[str, Any]: ...

    async def lookup_domain(self, domain: str) -> dict[str, Any]: ...

    async def lookup_hash(self, file_hash: str) -> dict[str, Any]: ...
