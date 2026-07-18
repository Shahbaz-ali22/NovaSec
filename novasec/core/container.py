"""
NovaSec Dependency Injection Container.

A simple, explicit dependency injection container that wires together
concrete implementations with their abstract interfaces.

The container is populated during framework startup (in ``app.py``) and
then queried by CLI commands to obtain correctly configured service
instances. This removes direct coupling between commands and
infrastructure implementations, making unit-testing trivial.

Design: This is an intentionally simple container — no reflection, no
magic, no auto-wiring. Every binding is explicit and readable. For a
CLI tool, simplicity beats cleverness.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, TypeVar

from novasec.core.exceptions import NovaSECError

logger = logging.getLogger(__name__)

T = TypeVar("T")


class DIError(NovaSECError):
    """Raised when the DI container cannot resolve a dependency."""


class Container:
    """Dependency injection container.

    Supports two binding modes:
    - **Instance**: A pre-created object is returned on every ``resolve`` call.
    - **Factory**: A callable is invoked on every ``resolve`` call to create
      a new instance.

    Usage::

        container = Container()
        container.bind(IHTTPClient, AsyncHTTPClient(timeout=30))
        container.bind_factory(IScanner, lambda: NmapScanner(config))

        http = container.resolve(IHTTPClient)
    """

    def __init__(self) -> None:
        self._instances: dict[type, Any] = {}
        self._factories: dict[type, Callable[[], Any]] = {}

    def bind(self, interface: type[T], instance: T) -> None:
        """Bind *interface* to a concrete *instance* (singleton binding).

        Args:
            interface: The abstract type or Protocol being bound.
            instance: The concrete object to return on resolve.
        """
        self._instances[interface] = instance
        logger.debug("DI: bound %r → %r", interface.__name__, type(instance).__name__)

    def bind_factory(self, interface: type[T], factory: Callable[[], T]) -> None:
        """Bind *interface* to a *factory* callable (transient binding).

        The factory is called fresh on each :meth:`resolve` invocation.

        Args:
            interface: The abstract type or Protocol being bound.
            factory: A zero-argument callable returning a concrete instance.
        """
        self._factories[interface] = factory
        logger.debug("DI: bound factory for %r", interface.__name__)

    def resolve(self, interface: type[T]) -> T:
        """Return the concrete implementation bound to *interface*.

        Raises:
            DIError: If no binding exists for *interface*.
        """
        if interface in self._instances:
            return self._instances[interface]  # type: ignore[return-value]

        if interface in self._factories:
            return self._factories[interface]()  # type: ignore[return-value]

        raise DIError(
            f"No binding found for {interface!r}.",
            details={"registered_interfaces": [i.__name__ for i in self._instances]},
        )

    def has(self, interface: type) -> bool:
        """Return True if *interface* has a registered binding."""
        return interface in self._instances or interface in self._factories

    def override(self, interface: type[T], instance: T) -> None:
        """Override an existing binding (primarily for testing).

        Replaces any existing instance or factory binding.
        """
        self._instances[interface] = instance
        self._factories.pop(interface, None)
        logger.debug("DI: overrode binding for %r", interface.__name__)

    def reset(self) -> None:
        """Clear all bindings (for use between tests)."""
        self._instances.clear()
        self._factories.clear()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_container: Container | None = None


def get_container() -> Container:
    """Return the global DI Container singleton."""
    global _container
    if _container is None:
        _container = Container()
    return _container
