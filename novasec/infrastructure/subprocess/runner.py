"""
NovaSec Safe Subprocess Runner — Infrastructure Layer.

Executes external CLI tools (nmap, nikto, ffuf, nuclei) in a controlled
subprocess with timeout, output capture, and automatic cleanup.

Security:
- Never uses shell=True (prevents shell injection)
- Arguments are always passed as lists
- Processes are killed on timeout
- stdout/stderr are captured and returned (never printed directly)
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass

from novasec.core.exceptions import ScanError

logger = logging.getLogger(__name__)


@dataclass
class SubprocessResult:
    """Result of a subprocess execution."""
    command: list[str]
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def succeeded(self) -> bool:
        return self.return_code == 0 and not self.timed_out

    @property
    def output(self) -> str:
        """Return stdout, falling back to stderr if stdout is empty."""
        return self.stdout or self.stderr


class SubprocessRunner:
    """
    Safe, async subprocess executor for external security tools.

    Usage::

        runner = SubprocessRunner(timeout=300)
        result = await runner.run(["nmap", "-sV", "-p", "80,443", "example.com"])
        if result.succeeded:
            print(result.stdout)
    """

    def __init__(self, timeout: float = 300.0) -> None:
        self.timeout = timeout

    @staticmethod
    def is_tool_available(tool_name: str) -> bool:
        """Return True if *tool_name* is available in the system PATH."""
        return shutil.which(tool_name) is not None

    async def run(
        self,
        args: list[str],
        timeout: float | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> SubprocessResult:
        """Execute *args* as a subprocess and return its output.

        Args:
            args: Command and arguments as a list (NEVER as a shell string).
            timeout: Override the default timeout for this invocation.
            env: Environment variables for the subprocess.
            cwd: Working directory for the subprocess.

        Returns:
            A :class:`SubprocessResult` with stdout, stderr, and return code.

        Raises:
            ScanError: If the command is not found in PATH.
        """
        effective_timeout = timeout or self.timeout

        if not args:
            raise ScanError("Cannot run an empty command")

        tool = args[0]
        if not self.is_tool_available(tool):
            raise ScanError(
                f"Tool not found: {tool!r}. "
                f"Install it with: sudo apt install {tool}",
                details={"tool": tool},
            )

        logger.debug("Running: %s (timeout=%.1fs)", " ".join(args), effective_timeout)

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=cwd,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=effective_timeout,
                )
                return SubprocessResult(
                    command=args,
                    return_code=proc.returncode or 0,
                    stdout=stdout_bytes.decode("utf-8", errors="replace"),
                    stderr=stderr_bytes.decode("utf-8", errors="replace"),
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                logger.warning(
                    "Command timed out after %.1fs: %s", effective_timeout, args[0]
                )
                return SubprocessResult(
                    command=args,
                    return_code=-1,
                    stdout="",
                    stderr=f"Command timed out after {effective_timeout}s",
                    timed_out=True,
                )

        except FileNotFoundError:
            raise ScanError(
                f"Command not found: {tool!r}",
                details={"command": args},
            )
        except PermissionError:
            raise ScanError(
                f"Permission denied executing {tool!r}. Try running with sudo.",
                details={"command": args},
            )
