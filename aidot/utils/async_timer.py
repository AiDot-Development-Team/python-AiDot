"""Async timer utility."""

import asyncio
import logging
from typing import Callable, Optional, Union, Awaitable

_LOGGER = logging.getLogger(__name__)


class AsyncTimer:
    """Async timer with callback support.

    Supports both sync and async callbacks, one-shot and repeating timers.

    Example:
        # One-shot timer
        timer = AsyncTimer(callback=on_timeout, interval=5.0)
        timer.start()
        timer.cancel()

        # Repeating timer (heartbeat)
        timer = AsyncTimer(callback=send_ping, interval=30.0, repeat=True)
        timer.start()
        timer.cancel()
    """

    def __init__(
        self,
        callback: Callable[[], Union[None, Awaitable[None]]],
        interval: float,
        repeat: bool = False,
        name: Optional[str] = None,
    ) -> None:
        """
        Initialize timer.

        Args:
            callback: Callback function (can be async or sync).
            interval: Interval in seconds.
            repeat: Whether to repeat. Defaults to False.
            name: Optional name for logging.
        """
        self._callback = callback
        self._interval = interval
        self._repeat = repeat
        self._name = name or "AsyncTimer"
        self._handle: Optional[asyncio.TimerHandle] = None
        self._is_cancelled = True
        self._is_running = False

    def start(self) -> None:
        """Start the timer."""
        if not self._is_cancelled and self._handle:
            _LOGGER.debug(f"{self._name}: Timer already running")
            return

        self._is_cancelled = False
        self._is_running = False
        self._schedule()
        _LOGGER.debug(f"{self._name}: Timer started, interval={self._interval}s, repeat={self._repeat}")

    def _schedule(self) -> None:
        """Schedule the next callback."""
        if self._is_cancelled:
            return
        loop = asyncio.get_running_loop()
        self._handle = loop.call_later(self._interval, self._on_timer)

    def _on_timer(self) -> None:
        """Timer callback."""
        if self._is_cancelled:
            return

        self._is_running = True

        try:
            # Execute callback
            result = self._callback()
            # If it's a coroutine, create task
            if asyncio.iscoroutine(result):
                asyncio.create_task(self._run_async_callback(result))
        except Exception as e:
            _LOGGER.error(f"{self._name}: Callback error: {e}")

        self._is_running = False

        # Schedule next if repeating
        if self._repeat and not self._is_cancelled:
            self._schedule()

    async def _run_async_callback(self, coro: Awaitable[None]) -> None:
        """Run async callback with error handling."""
        try:
            await coro
        except Exception as e:
            _LOGGER.error(f"{self._name}: Async callback error: {e}")

    def cancel(self) -> None:
        """Cancel the timer."""
        self._is_cancelled = True
        if self._handle:
            self._handle.cancel()
            self._handle = None
        _LOGGER.debug(f"{self._name}: Timer cancelled")

    def restart(self) -> None:
        """Restart the timer (cancel and start)."""
        self.cancel()
        self.start()

    @property
    def is_running(self) -> bool:
        """Check if timer is running."""
        return not self._is_cancelled and self._handle is not None

    @property
    def is_cancelled(self) -> bool:
        """Check if timer is cancelled."""
        return self._is_cancelled

    @property
    def interval(self) -> float:
        """Get the interval."""
        return self._interval

    def set_interval(self, value: float, restart: bool = True) -> None:
        """Set the interval.

        Args:
            value: New interval in seconds.
            restart: Whether to restart the timer. Defaults to True.
        """
        if self._interval == value:
            return
        self._interval = value
        if restart and self.is_running:
            self.restart()

    def __repr__(self) -> str:
        """String representation."""
        status = "running" if self.is_running else "cancelled" if self._is_cancelled else "stopped"
        return f"<{self._name}: interval={self._interval}s, repeat={self._repeat}, status={status}>"
