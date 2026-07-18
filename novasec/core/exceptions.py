"""
NovaSec Exception Hierarchy.

All framework exceptions derive from ``NovaSECError``. This enables callers
to catch *any* NovaSec error with a single ``except NovaSECError`` clause,
or to catch specific categories for targeted handling.

Hierarchy:
    NovaSECError
    ├── ConfigError
    │   ├── ConfigNotFoundError
    │   └── ConfigValidationError
    ├── PluginError
    │   ├── PluginNotFoundError
    │   ├── PluginLoadError
    │   ├── PluginValidationError
    │   └── PluginExecutionError
    ├── ScanError
    │   ├── InvalidTargetError
    │   ├── ScanTimeoutError
    │   └── ScanPermissionError
    ├── NetworkError
    │   ├── DNSResolutionError
    │   ├── ConnectionError
    │   └── ProxyError
    ├── ReportError
    │   ├── ReportGenerationError
    │   └── UnsupportedFormatError
    ├── StorageError
    │   ├── DatabaseError
    │   └── FileStorageError
    └── APIError
        ├── APIAuthError
        ├── APIRateLimitError
        └── APIResponseError
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class NovaSECError(Exception):
    """Base class for all NovaSec framework exceptions."""

    def __init__(self, message: str, *, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict = details or {}

    def __str__(self) -> str:
        if self.details:
            detail_str = ", ".join(f"{k}={v!r}" for k, v in self.details.items())
            return f"{self.message} [{detail_str}]"
        return self.message


# ---------------------------------------------------------------------------
# Configuration Errors
# ---------------------------------------------------------------------------


class ConfigError(NovaSECError):
    """Base class for configuration-related errors."""


class ConfigNotFoundError(ConfigError):
    """Raised when a required configuration file cannot be found."""


class ConfigValidationError(ConfigError):
    """Raised when configuration values fail Pydantic validation."""


# ---------------------------------------------------------------------------
# Plugin Errors
# ---------------------------------------------------------------------------


class PluginError(NovaSECError):
    """Base class for plugin-related errors."""


class PluginNotFoundError(PluginError):
    """Raised when a requested plugin is not found in the registry."""


class PluginLoadError(PluginError):
    """Raised when a plugin module cannot be imported or instantiated."""


class PluginValidationError(PluginError):
    """Raised when a plugin manifest or entrypoint fails validation."""


class PluginExecutionError(PluginError):
    """Raised when a plugin raises an unhandled exception during ``run``."""


# ---------------------------------------------------------------------------
# Scan Errors
# ---------------------------------------------------------------------------


class ScanError(NovaSECError):
    """Base class for scan-related errors."""


class InvalidTargetError(ScanError):
    """Raised when the provided scan target is invalid or unreachable."""


class ScanTimeoutError(ScanError):
    """Raised when a scan operation exceeds the configured timeout."""


class ScanPermissionError(ScanError):
    """Raised when the scan requires elevated privileges (e.g. raw sockets)."""


# ---------------------------------------------------------------------------
# Network Errors
# ---------------------------------------------------------------------------


class NetworkError(NovaSECError):
    """Base class for network-related errors."""


class DNSResolutionError(NetworkError):
    """Raised when DNS resolution fails for a given hostname."""


class ConnectionError(NetworkError):  # noqa: A001
    """Raised when a TCP/IP connection cannot be established."""


class ProxyError(NetworkError):
    """Raised when the configured proxy is unreachable or rejects the connection."""


# ---------------------------------------------------------------------------
# Report Errors
# ---------------------------------------------------------------------------


class ReportError(NovaSECError):
    """Base class for reporting-related errors."""


class ReportGenerationError(ReportError):
    """Raised when report generation fails for any reason."""


class UnsupportedFormatError(ReportError):
    """Raised when an unsupported output format is requested."""


# ---------------------------------------------------------------------------
# Storage Errors
# ---------------------------------------------------------------------------


class StorageError(NovaSECError):
    """Base class for storage/persistence errors."""


class DatabaseError(StorageError):
    """Raised on SQLite/database operation failures."""


class FileStorageError(StorageError):
    """Raised on filesystem I/O failures."""


# ---------------------------------------------------------------------------
# API Errors
# ---------------------------------------------------------------------------


class APIError(NovaSECError):
    """Base class for external API integration errors."""

    def __init__(
        self,
        message: str,
        *,
        api_name: str = "unknown",
        status_code: int | None = None,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, details=details)
        self.api_name = api_name
        self.status_code = status_code


class APIAuthError(APIError):
    """Raised when an API returns 401/403 — likely invalid API key."""


class APIRateLimitError(APIError):
    """Raised when an API returns 429 — rate limit exceeded."""

    def __init__(
        self,
        message: str,
        *,
        api_name: str = "unknown",
        retry_after: int | None = None,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, api_name=api_name, details=details)
        self.retry_after = retry_after


class APIResponseError(APIError):
    """Raised when an API returns an unexpected response."""
