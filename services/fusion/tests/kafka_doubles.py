"""Kafka client doubles shared across the fusion suite.

:class:`TwoStageProducer` is the canonical producer double. It lives in its
own module rather than in one test file because reaching for ``AsyncMock()``
instead is a silent loss of coverage -- see the class docstring.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace


class TwoStageProducer:
    """A producer double with aiokafka's real enqueue/acknowledge split.

    ``AIOKafkaProducer.send`` is a coroutine that appends a record to the
    client's in-memory batch accumulator and returns a **future** that
    resolves when the broker acknowledges it. Those are two outcomes, and
    only the second one means the record left the process.

    ``AsyncMock()`` collapses them. Its ``send`` returns an awaitable
    resolving to a ``MagicMock``, so ``send`` and ``send_and_wait`` are
    indistinguishable under it -- both read as "awaited, no exception" --
    and a publish that only enqueues passes every assertion. That is why the
    fused-alert path shipped awaiting the enqueue and discarding the delivery
    future. Use this double for anything that reaches a publish.

    ``send`` here resolves as soon as the record is accepted into the batch
    and hands back a future, which can resolve with metadata (delivered),
    resolve with an exception (the broker refused it *after* the enqueue
    returned), or never resolve at all (still in the accumulator).
    """

    def __init__(self, *, ack_after: float = 0.0, ack_error: Exception | None = None, never_ack: bool = False) -> None:
        self.enqueued: list[dict] = []
        self.futures: list[asyncio.Future] = []
        self._ack_after = ack_after
        self._ack_error = ack_error
        self._never_ack = never_ack
        self._tasks: list[asyncio.Task] = []

    async def send(self, topic, value=None, key=None):  # noqa: ANN001, ANN201
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self.enqueued.append({"topic": topic, "value": value, "key": key})
        self.futures.append(future)
        if not self._never_ack:
            self._tasks.append(loop.create_task(self._settle(future)))
        return future

    async def _settle(self, future: asyncio.Future) -> None:
        if self._ack_after:
            await asyncio.sleep(self._ack_after)
        if future.done():  # pragma: no cover — the caller cancelled it
            return
        if self._ack_error is not None:
            future.set_exception(self._ack_error)
        else:
            future.set_result(SimpleNamespace(topic="t", partition=0, offset=len(self.enqueued)))

    async def drain(self) -> None:
        """Settle the pending ack tasks so a test leaves no stray task behind."""
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
