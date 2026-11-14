"""Process-wide streaming runtime singleton (t6-streaming).

Mirrors the lifecycle pattern of :mod:`app.detections.runtime`: one
runtime per process, lazily constructed on first use, hot-reload
supported via :func:`reload`.

The runtime is *stateful* — events flow into it over time and
detections fall out as windows close. We deliberately stash that
state in a module-level singleton so tests and the API hit the
same instance, while production deployments that want isolation
can construct their own :class:`StreamingRuntime` directly.
"""
from __future__ import annotations

import threading
from typing import Optional

from app.streaming.builtin import builtin_streaming_rules
from app.streaming.runtime import StreamingRuntime


_lock = threading.Lock()
_runtime: Optional[StreamingRuntime] = None


def _build_runtime() -> StreamingRuntime:
    runtime = StreamingRuntime()
    for rule in builtin_streaming_rules():
        runtime.add_rule(rule)
    return runtime


def get_streaming_runtime() -> StreamingRuntime:
    global _runtime
    if _runtime is not None:
        return _runtime
    with _lock:
        if _runtime is None:
            _runtime = _build_runtime()
        return _runtime


def reload() -> StreamingRuntime:
    """Drop the current runtime and rebuild it from the rule pack."""
    global _runtime
    with _lock:
        _runtime = _build_runtime()
        return _runtime
