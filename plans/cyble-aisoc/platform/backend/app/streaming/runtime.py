"""Watermarked streaming runtime + correlation rules (t6-streaming).

This module deliberately mirrors the *vocabulary* of a real streaming
engine — watermarks, tumbling/sliding windows, keyed state — so a
rule written here lifts unchanged into Flink, Bytewax, or
Materialize when we move detection compute off-process.

Mental model
------------

* Events arrive with an ``event_time`` and a partition ``key``
  (typically the tenant + user/host).
* The runtime tracks a per-tenant *watermark*: the largest
  event_time seen, minus a lateness budget. Events older than the
  watermark are dropped (counted in stats; never silently lost).
* Windows are owned by rules. A rule may declare:
    - tumbling windows (fixed, non-overlapping) for things like
      "10 failed logins in 5 minutes",
    - sliding windows (overlapping) for things like "an exfil
      transfer within 60s of a process spawn".
* When the watermark advances past a window's close boundary, the
  rule emits zero or more :class:`Detection` instances.

Why ``time.monotonic()`` is *not* used
--------------------------------------

Real streaming systems use *event time*, not wall-clock or
monotonic time. We follow that here so a backfill of last week's
data produces the same detections it would have produced in real
time, and so tests can use a synthetic clock.

Stats and back-pressure
-----------------------

Each ingest returns the number of detections it produced. The
caller (in the live system: the Kafka consumer) is free to apply
back-pressure if detection production lags ingest. The runtime
itself does no I/O — it's a pure function over the event stream.
"""
from __future__ import annotations

import bisect
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional


DetectionCallback = Callable[["Detection"], None]


@dataclass(frozen=True)
class WindowSpec:
    """A windowing specification.

    ``size_seconds`` is the window's duration. ``slide_seconds`` is
    how far the window advances between firings; setting it equal
    to ``size_seconds`` produces non-overlapping (tumbling)
    windows, smaller values produce sliding windows.
    """

    size_seconds: float
    slide_seconds: float

    @classmethod
    def tumbling(cls, size_seconds: float) -> "WindowSpec":
        return cls(size_seconds=size_seconds, slide_seconds=size_seconds)

    @classmethod
    def sliding(cls, size_seconds: float, slide_seconds: float) -> "WindowSpec":
        return cls(size_seconds=size_seconds, slide_seconds=slide_seconds)


@dataclass(frozen=True)
class Detection:
    """A single detection produced by a streaming rule."""

    rule_id: str
    tenant_id: str
    key: str
    event_time: float
    severity: str
    description: str
    matching_event_count: int
    sample_events: tuple[dict, ...] = ()


@dataclass
class _KeyedBuffer:
    """A sorted-by-event-time event buffer for one (rule, key) pair.

    We keep the events in event-time order so the window scans only
    cost ``O(log n)`` for the bisect lookup of the window's lower
    bound, plus ``O(k)`` for the in-window scan. Eviction is done
    lazily: when the watermark advances past a window's close
    boundary, we drop everything older than the latest *open*
    window's lower bound.
    """

    times: list[float] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)

    def add(self, event_time: float, event: dict) -> None:
        # Most events arrive in roughly event-time order, so
        # bisect.insort gives us the right behaviour for both the
        # common case (append) and the late-event case (insert).
        idx = bisect.bisect_right(self.times, event_time)
        self.times.insert(idx, event_time)
        self.events.insert(idx, event)

    def evict_before(self, lower_bound: float) -> None:
        if not self.times or self.times[0] >= lower_bound:
            return
        cut = bisect.bisect_left(self.times, lower_bound)
        del self.times[:cut]
        del self.events[:cut]

    def in_window(self, lower: float, upper: float) -> list[dict]:
        if not self.times:
            return []
        lo = bisect.bisect_left(self.times, lower)
        hi = bisect.bisect_right(self.times, upper)
        return list(self.events[lo:hi])


# ---------------------------------------------------------------------------
# Rule base + two concrete rule types
# ---------------------------------------------------------------------------


@dataclass
class StreamingRule:
    """Base class for streaming detection rules.

    Subclasses implement :meth:`evaluate_window` to inspect the
    events that fell inside a window's bounds and emit zero or more
    detections.
    """

    rule_id: str
    severity: str
    description: str
    window: WindowSpec
    key_field: str = "key"

    def event_key(self, event: dict) -> Optional[str]:
        return event.get(self.key_field)

    def evaluate_window(
        self,
        *,
        tenant_id: str,
        key: str,
        events: list[dict],
        window_start: float,
        window_end: float,
    ) -> list[Detection]:
        raise NotImplementedError


@dataclass
class BurstThresholdRule(StreamingRule):
    """Fire when at least ``threshold`` events match a predicate in the window."""

    threshold: int = 5
    match: Callable[[dict], bool] = field(default=lambda e: True)

    def evaluate_window(
        self,
        *,
        tenant_id: str,
        key: str,
        events: list[dict],
        window_start: float,
        window_end: float,
    ) -> list[Detection]:
        matched = [e for e in events if self.match(e)]
        if len(matched) < self.threshold:
            return []
        return [
            Detection(
                rule_id=self.rule_id,
                tenant_id=tenant_id,
                key=key,
                event_time=window_end,
                severity=self.severity,
                description=self.description,
                matching_event_count=len(matched),
                # Cap the sample so a runaway window doesn't blow up
                # downstream payloads.
                sample_events=tuple(matched[-5:]),
            )
        ]


@dataclass
class CorrelationRule(StreamingRule):
    """Fire when at least one event of each predicate appears in the window.

    Use case: "a process spawn followed within 60 seconds by an
    outbound exfiltration to a new IP" — two distinct predicates
    that must both fire on the same key.
    """

    predicates: list[Callable[[dict], bool]] = field(default_factory=list)

    def evaluate_window(
        self,
        *,
        tenant_id: str,
        key: str,
        events: list[dict],
        window_start: float,
        window_end: float,
    ) -> list[Detection]:
        if not self.predicates:
            return []
        matched_per_predicate: list[list[dict]] = [
            [e for e in events if pred(e)] for pred in self.predicates
        ]
        if not all(matched_per_predicate):
            return []
        sample = tuple(
            evt for bucket in matched_per_predicate for evt in bucket[:1]
        )
        return [
            Detection(
                rule_id=self.rule_id,
                tenant_id=tenant_id,
                key=key,
                event_time=window_end,
                severity=self.severity,
                description=self.description,
                matching_event_count=sum(len(b) for b in matched_per_predicate),
                sample_events=sample,
            )
        ]


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------


@dataclass
class _RuntimeStats:
    events_ingested: int = 0
    events_dropped_late: int = 0
    detections_emitted: int = 0
    windows_evaluated: int = 0


class StreamingRuntime:
    """Watermarked, keyed event router for streaming detection rules.

    Construction order matters: register every rule before pushing
    events. Adding rules at runtime is safe but rules added after
    events have flowed will only see future windows.
    """

    def __init__(
        self,
        *,
        lateness_budget_seconds: float = 30.0,
        max_buffer_per_key: int = 5000,
    ) -> None:
        self._lateness = lateness_budget_seconds
        self._max_buffer = max_buffer_per_key
        self._rules: list[StreamingRule] = []
        # (rule_id, tenant_id, key) -> buffer
        self._buffers: dict[tuple[str, str, str], _KeyedBuffer] = {}
        # tenant_id -> current watermark. We keep this per-tenant so
        # one tenant's quiet pipeline can't hold back another's
        # window firings.
        self._watermarks: dict[str, float] = defaultdict(float)
        # (rule_id, tenant_id, key) -> next window-end time we have
        # *not yet* evaluated. Tracked per-key so the window grid
        # advances independently for each entity.
        self._next_close: dict[tuple[str, str, str], float] = {}
        self._listeners: list[DetectionCallback] = []
        # Detection ring buffer for callers that want a synchronous
        # readback (tests, the API layer). Capped to keep memory
        # bounded under load.
        self._recent: deque[Detection] = deque(maxlen=1000)
        self.stats = _RuntimeStats()

    # ─── Rule registration ────────────────────────────────────────────

    def add_rule(self, rule: StreamingRule) -> None:
        self._rules.append(rule)

    @property
    def rules(self) -> list[StreamingRule]:
        return list(self._rules)

    # ─── Listener registration ────────────────────────────────────────

    def on_detection(self, cb: DetectionCallback) -> None:
        self._listeners.append(cb)

    def recent_detections(self) -> list[Detection]:
        return list(self._recent)

    # ─── Ingest ───────────────────────────────────────────────────────

    def ingest(self, event: dict) -> list[Detection]:
        """Push one event through every applicable rule.

        Returns the list of detections produced by the watermark
        advance triggered by this event. A typical event produces
        zero detections; only events that close a window yield
        results.
        """

        tenant_id = str(event.get("tenant_id", ""))
        event_time = float(event.get("event_time", 0.0))
        if not tenant_id or event_time <= 0:
            raise ValueError("streaming events require tenant_id + event_time")

        watermark = self._watermarks[tenant_id]
        if event_time + self._lateness < watermark:
            self.stats.events_dropped_late += 1
            return []

        self.stats.events_ingested += 1

        # Fan the event out to every rule whose key it matches.
        for rule in self._rules:
            key = rule.event_key(event)
            if key is None:
                continue
            buf_key = (rule.rule_id, tenant_id, str(key))
            buf = self._buffers.setdefault(buf_key, _KeyedBuffer())
            buf.add(event_time, event)

            # Bound buffer growth: oldest events drop first. The
            # watermark eviction below is the primary mechanism;
            # this is a safety valve for pathological keys.
            if len(buf.times) > self._max_buffer:
                excess = len(buf.times) - self._max_buffer
                del buf.times[:excess]
                del buf.events[:excess]

            if buf_key not in self._next_close:
                self._next_close[buf_key] = self._initial_close(rule, event_time)

        # Advance watermark and fire any windows it just closed.
        new_watermark = max(watermark, event_time - self._lateness)
        self._watermarks[tenant_id] = new_watermark
        return self._fire_windows(tenant_id, new_watermark)

    def _initial_close(self, rule: StreamingRule, event_time: float) -> float:
        """First window-end timestamp for a brand-new (rule, key) state.

        Aligned to the slide grid so two keys that started at
        different times still produce overlapping window boundaries.
        """
        slide = rule.window.slide_seconds
        size = rule.window.size_seconds
        # Start the first close at the next slide tick after the
        # event's event_time. Keeps grid alignment intuitive.
        next_tick = (int(event_time // slide) + 1) * slide
        return next_tick + (size - slide if size > slide else 0)

    def _fire_windows(self, tenant_id: str, watermark: float) -> list[Detection]:
        """Walk every rule/key whose next window close has passed the watermark."""

        produced: list[Detection] = []
        for buf_key, close in list(self._next_close.items()):
            rid, tid, key = buf_key
            if tid != tenant_id:
                continue
            rule = self._rule_by_id(rid)
            if rule is None:
                continue
            while close <= watermark:
                window_start = close - rule.window.size_seconds
                window_end = close
                buf = self._buffers.get(buf_key)
                events = buf.in_window(window_start, window_end) if buf else []
                detections = rule.evaluate_window(
                    tenant_id=tid,
                    key=key,
                    events=events,
                    window_start=window_start,
                    window_end=window_end,
                )
                self.stats.windows_evaluated += 1
                for d in detections:
                    produced.append(d)
                    self._recent.append(d)
                    self.stats.detections_emitted += 1
                    for listener in self._listeners:
                        try:
                            listener(d)
                        except Exception:  # noqa: BLE001 - listeners are best-effort
                            # A misbehaving listener must not stall
                            # detection: log and keep going.
                            pass
                close += rule.window.slide_seconds
            self._next_close[buf_key] = close

            # Garbage-collect events that no future window can include.
            buf = self._buffers.get(buf_key)
            if buf:
                horizon = close - rule.window.size_seconds
                buf.evict_before(horizon)
                if not buf.times:
                    # Drop empty buffers + scheduling entries to
                    # keep the runtime memory-bounded under churn.
                    self._buffers.pop(buf_key, None)
                    self._next_close.pop(buf_key, None)

        return produced

    def _rule_by_id(self, rule_id: str) -> Optional[StreamingRule]:
        for rule in self._rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    # ─── Bulk operations ─────────────────────────────────────────────

    def ingest_many(self, events: Iterable[dict]) -> list[Detection]:
        """Convenience for ingesting a batch."""
        out: list[Detection] = []
        for event in events:
            out.extend(self.ingest(event))
        return out
