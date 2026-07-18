"""
NovaSec Execution Context.

An ``ExecutionContext`` is an immutable snapshot of everything a scan
operation needs to know about its invocation: who requested it, what the
target is, what options were provided, and where to write output.

One context is created per CLI command invocation and passed down through
every layer without modification. Layers that need to add information should
create a derived context using :meth:`ExecutionContext.with_options`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class OutputConfig:
    """Controls how results are presented to the user."""

    format: str = "rich"          # "rich" | "json" | "plain"
    output_dir: Path = Path("./novasec_workspace")
    save_to_file: bool = False
    verbose: bool = False
    no_color: bool = False


@dataclass(frozen=True)
class ExecutionContext:
    """Immutable execution context for a single NovaSec operation.

    This object is created by CLI commands and passed through the entire
    call stack. It must never be mutated — use :meth:`with_options` to
    create a derived context.
    """

    # Unique identifier for this execution
    scan_id: str = field(default_factory=lambda: f"ns-{uuid.uuid4().hex[:8]}")

    # Primary scan target (domain, IP, URL, CIDR)
    target: str = ""

    # Wall-clock time when this context was created
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Output configuration
    output: OutputConfig = field(default_factory=OutputConfig)

    # Arbitrary scan options (plugin-specific knobs)
    options: dict[str, Any] = field(default_factory=dict)

    # Active scan profile name (e.g. "stealth", "aggressive")
    profile: str = "default"

    # Operator information (from system user)
    operator: str = field(
        default_factory=lambda: __import__("getpass").getuser()
    )

    def with_options(self, **kwargs: Any) -> "ExecutionContext":
        """Return a new context with the given fields overridden.

        Example::

            ctx = ExecutionContext(target="example.com")
            verbose_ctx = ctx.with_options(
                output=OutputConfig(verbose=True)
            )
        """
        import dataclasses

        return dataclasses.replace(self, **kwargs)

    def with_merged_options(self, **extra_options: Any) -> "ExecutionContext":
        """Return a new context with *extra_options* merged into ``options``."""
        merged = {**self.options, **extra_options}
        return self.with_options(options=merged)

    @property
    def workspace_dir(self) -> Path:
        """Return the output directory for this scan session."""
        return self.output.output_dir / self.scan_id

    def to_dict(self) -> dict[str, Any]:
        """Serialise the context to a plain dictionary (for logging/audit)."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "operator": self.operator,
            "profile": self.profile,
            "output_format": self.output.format,
            "options": self.options,
        }
