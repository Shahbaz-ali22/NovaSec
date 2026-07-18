"""
NovaSec CLI Auth Middleware stub.
"""

from __future__ import annotations
import logging

logger = logging.getLogger(__name__)


def verify_api_session() -> bool:
    """
    Placeholder verification for enterprise authenticated command runs.
    Always returns true for local Kali Linux CLI operations.
    """
    return True
