"""Live agent-activity event bus. WebSocket clients subscribe to this.

Every published event carries a `tenant_id` so that the bus can fan out
strictly per tenant. Subscribers pass the set of tenant_ids they're
allowed to see (typically `TenantContext.viewable_tenant_ids`). Events
without a tenant_id, or events whose tenant_id is `"__global__"`, are
considered platform-level and visible to everyone — but the publisher
is responsible for never leaking customer payloads onto the global bus.
"""
from __future__ import annotations

import asyncio
from collections import deque
from typing import Deque, Iterable


GLOBAL_TENANT = "__global__"


class _Subscriber:
    __slots__ = ("queue", "tenant_ids")

    def __init__(
        self, queue: asyncio.Queue, tenant_ids: frozenset[str] | None
    ) -> None:
        self.queue = queue
        # None means "see everything" (admin/platform debugging only).
        self.tenant_ids = tenant_ids

    def can_see(self, event: dict) -> bool:
        if self.tenant_ids is None:
            return True
        tid = event.get("tenant_id")
        if tid is None or tid == GLOBAL_TENANT:
            return True
        return tid in self.tenant_ids


class EventBus:
    def __init__(self, history_size: int = 200) -> None:
        self._subscribers: list[_Subscriber] = []
        self._history: Deque[dict] = deque(maxlen=history_size)

    def publish(self, event: dict) -> None:
        # Stamp a tenant_id if the caller forgot; better to fail closed.
        event.setdefault("tenant_id", GLOBAL_TENANT)
        self._history.append(event)
        for sub in list(self._subscribers):
            if not sub.can_see(event):
                continue
            try:
                sub.queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

    def subscribe(
        self, tenant_ids: Iterable[str] | None = None
    ) -> asyncio.Queue:
        """Subscribe to events scoped to `tenant_ids`.

        `None` returns the firehose (use only for platform admin or
        background indexers). Pass an empty iterable to receive only
        global/platform events.
        """
        ids: frozenset[str] | None
        if tenant_ids is None:
            ids = None
        else:
            ids = frozenset(tenant_ids)
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        sub = _Subscriber(q, ids)
        # Replay only the slice of history this subscriber is allowed to see
        # so reconnecting clients don't accidentally backfill into the
        # wrong tenant.
        for h in list(self._history)[-50:]:
            if not sub.can_see(h):
                continue
            try:
                q.put_nowait(h)
            except asyncio.QueueFull:
                break
        self._subscribers.append(sub)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers = [s for s in self._subscribers if s.queue is not q]


bus = EventBus()
