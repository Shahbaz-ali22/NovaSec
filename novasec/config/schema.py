"""
NovaSec Configuration Schemas.

All configuration models are Pydantic v2 BaseModel subclasses.
The root model is ``NovaSECConfig``, composed of typed sub-models
for each configuration domain.

Environment variable override format:
    NOVASEC_<SECTION>__<KEY>=value

Examples:
    NOVASEC_NETWORK__TIMEOUT=60
    NOVASEC_APIS__SHODAN_KEY=your-key-here
    NOVASEC_LOGGING__LEVEL=DEBUG
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import (
    AnyUrl,
    BaseModel,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class GeneralConfig(BaseModel):
    """General framework settings."""

    output_dir: Path = Path("./novasec_workspace")
    workspace_name: str = "default"
    max_threads: int = Field(default=10, ge=1, le=200)
    max_concurrent_tasks: int = Field(default=20, ge=1, le=500)
    banner: bool = True

    @field_validator("output_dir", mode="before")
    @classmethod
    def expand_path(cls, v: Any) -> Path:
        return Path(v).expanduser().resolve()


class NetworkConfig(BaseModel):
    """Network and HTTP client settings."""

    timeout: int = Field(default=30, ge=1, le=300, description="Request timeout in seconds")
    connect_timeout: int = Field(default=10, ge=1, le=60)
    retries: int = Field(default=3, ge=0, le=10)
    retry_delay: float = Field(default=1.0, ge=0.0)
    rate_limit: int = Field(default=10, ge=1, le=1000, description="Requests per second")
    proxy: str | None = Field(default=None, description="HTTP/SOCKS proxy URL")
    verify_ssl: bool = True
    follow_redirects: bool = True
    user_agent: str = "NovaSec/1.0.0 (+https://github.com/novasec/novasec)"
    max_connections: int = Field(default=100, ge=1, le=1000)

    @field_validator("proxy", mode="before")
    @classmethod
    def validate_proxy(cls, v: str | None) -> str | None:
        if v is not None and not v.startswith(("http://", "https://", "socks5://")):
            raise ValueError("Proxy must start with http://, https://, or socks5://")
        return v


class DNSConfig(BaseModel):
    """DNS resolution settings."""

    nameservers: list[str] = Field(default_factory=lambda: ["8.8.8.8", "8.8.4.4", "1.1.1.1"])
    timeout: float = Field(default=5.0, ge=0.5, le=30.0)
    lifetime: float = Field(default=10.0, ge=1.0, le=60.0)
    use_tcp: bool = False
    doh_url: str | None = None  # DNS-over-HTTPS endpoint


class ScanConfig(BaseModel):
    """Default scan behaviour settings."""

    default_ports: list[int] = Field(
        default_factory=lambda: [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
    )
    aggressive: bool = False
    stealth_mode: bool = False
    randomize_ports: bool = False
    skip_host_discovery: bool = False
    max_hosts: int = Field(default=256, ge=1, le=65536)
    scan_timeout: int = Field(default=300, ge=10, le=3600, description="Total scan timeout in seconds")


class ExploitConfig(BaseModel):
    """Exploit module settings — safety first."""

    enabled: bool = False  # Must be explicitly enabled
    safe_mode: bool = True  # Never actually exploit — verify only
    require_confirmation: bool = True
    max_payload_size: int = Field(default=4096, ge=0)


class APIConfig(BaseModel):
    """External API credentials and settings."""

    shodan_key: SecretStr | None = None
    virustotal_key: SecretStr | None = None
    censys_id: SecretStr | None = None
    censys_secret: SecretStr | None = None
    nvd_api_key: SecretStr | None = None  # Optional — increases NVD rate limits

    def get_shodan_key(self) -> str | None:
        return self.shodan_key.get_secret_value() if self.shodan_key else None

    def get_virustotal_key(self) -> str | None:
        return self.virustotal_key.get_secret_value() if self.virustotal_key else None

    def get_censys_credentials(self) -> tuple[str, str] | None:
        if self.censys_id and self.censys_secret:
            return (
                self.censys_id.get_secret_value(),
                self.censys_secret.get_secret_value(),
            )
        return None


class ReportingConfig(BaseModel):
    """Report generation settings."""

    default_format: Literal["json", "html", "pdf", "markdown", "csv"] = "html"
    output_dir: Path = Path("./novasec_workspace/reports")
    include_evidence: bool = True
    include_remediation: bool = True
    include_raw_output: bool = False
    company_name: str = ""
    report_title: str = "NovaSec Security Assessment Report"
    logo_path: Path | None = None

    @field_validator("output_dir", mode="before")
    @classmethod
    def expand_path(cls, v: Any) -> Path:
        return Path(v).expanduser().resolve()


class LoggingConfig(BaseModel):
    """Structured logging configuration."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    format: Literal["json", "rich", "plain"] = "rich"
    log_file: Path | None = None
    audit_log: Path = Path("~/.novasec/logs/audit.jsonl")
    rotate_max_bytes: int = Field(default=10 * 1024 * 1024, description="10 MB")
    rotate_backup_count: int = Field(default=5, ge=1, le=20)
    include_caller_info: bool = False

    @field_validator("audit_log", "log_file", mode="before")
    @classmethod
    def expand_path(cls, v: Any) -> Any:
        if v is None:
            return v
        return Path(v).expanduser().resolve()


class PluginConfig(BaseModel):
    """Plugin system settings."""

    enabled: bool = True
    extra_plugin_dirs: list[Path] = Field(default_factory=list)
    disabled_plugins: list[str] = Field(default_factory=list)
    auto_install_python_deps: bool = False  # Safety: off by default


# ---------------------------------------------------------------------------
# Root Configuration Model
# ---------------------------------------------------------------------------


class NovaSECConfig(BaseSettings):
    """Root NovaSec configuration model.

    Inherits from BaseSettings to support environment variable overrides.
    Environment variables follow the pattern:
        NOVASEC_<SECTION>__<KEY>=value

    Example:
        NOVASEC_NETWORK__TIMEOUT=60
        NOVASEC_APIS__SHODAN_KEY=your-key
    """

    model_config = SettingsConfigDict(
        env_prefix="NOVASEC_",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )

    general: GeneralConfig = Field(default_factory=GeneralConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    dns: DNSConfig = Field(default_factory=DNSConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    exploit: ExploitConfig = Field(default_factory=ExploitConfig)
    apis: APIConfig = Field(default_factory=APIConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    plugins: PluginConfig = Field(default_factory=PluginConfig)

    @model_validator(mode="after")
    def validate_stealth_aggressive_conflict(self) -> "NovaSECConfig":
        """Stealth and aggressive mode cannot both be True."""
        if self.scan.stealth_mode and self.scan.aggressive:
            raise ValueError(
                "scan.stealth_mode and scan.aggressive cannot both be enabled."
            )
        return self
