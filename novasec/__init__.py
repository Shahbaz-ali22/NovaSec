"""
NovaSec — Modular, production-grade cybersecurity CLI framework.

A comprehensive toolkit for Security Engineers, SOC Analysts,
Penetration Testers, and Bug Bounty Hunters.
"""

__version__ = "1.0.0"
__author__ = "NovaSec Team"
__email__ = "team@novasec.dev"
__license__ = "MIT"

# Public API surface
from novasec.core.exceptions import NovaSECError
from novasec.core.context import ExecutionContext

__all__ = [
    "__version__",
    "__author__",
    "NovaSECError",
    "ExecutionContext",
]
