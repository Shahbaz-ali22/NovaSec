"""
NovaSec Internal Event Bus.

A lightweight publish/subscribe event bus for decoupled communication
between framework layers. Producers publish events; consumers subscribe
to them without needing a direct reference to the producer.

Common Events:
    scan.started        — A scan operation began
    scan.completed      — A scan operation finished (with results)
    scan.error          — A scan operation failed
    finding.discovered  — A new finding was identified
    plugin.loaded       — A plugin was loaded into the registry
    report.generated    — A report file was written to disk
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)

# Type alias for event handlers (sync or async callables)
Handler = Callable[..., Any | Coroutine[Any, Any, None]]


class EventBus:
    """Asynchronous publish/subscribe event bus.

    Handlers may be either regular functions or coroutines — the bus
    handles both transparently.

    Usage::

        bus = EventBus()

        @bus.on("finding.discovered")
        async def notify_slack(finding, **_):
            await slack.post(f"New finding: {finding.title}")

        await bus.publish("finding.discovered", finding=my_finding)
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Subscription
    # ------------------------------------------------------------------

    def subscribe(self, event_name: str, handler: Handler) -> None:
        """Register *handler* to be called when *event_name* is published."""
        self._handlers[event_name].append(handler)
        logger.debug("Subscribed %r to event '%s'", handler.__name__, event_name)

    def unsubscribe(self, event_name: str, handler: Handler) -> None:
        """Remove *handler* from *event_name* subscriptions.

        Does nothing if *handler* is not currently subscribed.
        """
        try:
            self._handlers[event_name].remove(handler)
        except ValueError:
            pass

    def on(self, event_name: str) -> Callable[[Handler], Handler]:
        """Decorator shorthand for :meth:`subscribe`.

        Usage::

            @bus.on("scan.started")
            async def log_scan(scan_id, target, **_):
                logger.info("Scan %s started for %s", scan_id, target)
        """

        def decorator(handler: Handler) -> Handler:
            self.subscribe(event_name, handler)
            return handler

        return decorator

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    async def publish(self, event_name: str, **payload: Any) -> None:
        """Publish *event_name* to all registered handlers.

        Handlers are called sequentially. Errors in one handler do not
        prevent subsequent handlers from being called — they are logged
        at ERROR level and suppressed.

        Args:
            event_name: The name of the event to publish.
            **payload: Arbitrary keyword arguments passed to each handler.
        """
        handlers = self._handlers.get(event_name, [])
        if not handlers:
            return

        logger.debug("Publishing event '%s' to %d handlers", event_name, len(handlers))

        for handler in handlers:
            try:
                result = handler(**payload)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception(
                    "Handler %r raised an error on event '%s'",
                    getattr(handler, "__name__", repr(handler)),
                    event_name,
                )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def list_events(self) -> list[str]:
        """Return a list of all event names that have subscribers."""
        return list(self._handlers.keys())

    def subscriber_count(self, event_name: str) -> int:
        """Return the number of handlers subscribed to *event_name*."""
        return len(self._handlers.get(event_name, []))

    def clear(self) -> None:
        """Remove all subscribers (useful in tests)."""
        self._handlers.clear()


# ---------------------------------------------------------------------------
# Well-known event name constants
# ---------------------------------------------------------------------------


class Events:
    """Namespace of standard NovaSec event names."""

    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_ERROR = "scan.error"

    FINDING_DISCOVERED = "finding.discovered"

    PLUGIN_LOADED = "plugin.loaded"
    PLUGIN_ERROR = "plugin.error"

    REPORT_GENERATED = "report.generated"

    CONFIG_LOADED = "config.loaded"


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    """Return the global EventBus singleton."""
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus
