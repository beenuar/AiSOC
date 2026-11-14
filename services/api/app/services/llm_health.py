"""Did the LLM actually answer? (issue #1241)

``GET /api/v1/llm/status`` reports *configuration* — which provider this pod is
pointed at, and whether the air-gap policy would let a call leave. It places no
call, so a deployment whose every completion times out still renders the
emerald **Live** pill in Settings → Deployment & AI. The panel's own header
claims the indicator "cannot drift from runtime behaviour", which is true of
which provider is configured and false of whether it answers.

This module is the missing half: a bounded, in-process record of how the calls
the product is *already making* turned out.

What it deliberately is not
---------------------------
**Not a probe.** Nothing here places a request. A synthetic completion on every
page load would spend the tenant's budget to answer a question the real traffic
has already answered, and on a local 3B model it is not cheap.

**Not a latency number.** No figure for how long a call takes is published
anywhere, because none has been measured for this path. ``aisoc_run_costs``
carries a latency sum, but it is written by ``services/agents`` for completed
runs only and records nothing at all about a call that timed out — which is the
case that matters here.

**Not a ratio.** The verdict is the outcome of the most recent observed call.
A ratio over a short window is noise, and a ratio over a long one keeps
reporting healthy for a provider that died five minutes ago. "The last call we
made did not come back" is the question an operator is asking when they look at
that badge. The counts travel alongside so a blip is distinguishable from an
outage.

Scope, stated rather than implied
---------------------------------
Per-process. Behind several replicas this reports what *this* pod has seen, and
a pod that has served no AI traffic reports ``unknown`` rather than a green it
has not earned. ``unknown`` is a first-class answer here: an absence of evidence
rendered as health is the same defect in a different costume.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Literal

#: How many outcomes to keep. Enough to say "3 of the last 12 failed" and small
#: enough that the whole thing is a few hundred bytes per process.
_WINDOW_SIZE = 20

#: Outcomes older than this stop counting. A provider that was failing an hour
#: ago says nothing about the one answering now, and an operator reading a red
#: badge needs it to be about the present.
_WINDOW_SECONDS = 900.0

RecentHealth = Literal["healthy", "degraded", "unknown"]

_lock = threading.Lock()
_outcomes: deque[tuple[float, bool, str]] = deque(maxlen=_WINDOW_SIZE)


def record_success() -> None:
    """Note that a chat-completions call returned."""
    with _lock:
        _outcomes.append((time.monotonic(), True, ""))


def record_failure(kind: str) -> None:
    """Note that a chat-completions call did not return a usable response.

    ``kind`` is the exception class name (``ReadTimeout``, ``ConnectError``,
    ``HTTPStatusError``…) — never the message, which can carry a URL with a key
    in it.
    """
    with _lock:
        _outcomes.append((time.monotonic(), False, kind))


def reset() -> None:
    """Drop the window. For tests and for a deliberate operator re-baseline."""
    with _lock:
        _outcomes.clear()


def snapshot() -> dict[str, Any]:
    """The three fields ``/llm/status`` adds, derived from real outcomes only."""
    cutoff = time.monotonic() - _WINDOW_SECONDS
    with _lock:
        recent = [entry for entry in _outcomes if entry[0] >= cutoff]

    if not recent:
        return {
            "recent_health": "unknown",
            "recent_calls": 0,
            "recent_failures": 0,
            "recent_note": (
                "No LLM call has been observed by this pod recently, so whether the provider "
                "answers is unmeasured. This reports configuration only."
            ),
        }

    failures = [entry for entry in recent if not entry[1]]
    last_ok = recent[-1][1]
    last_kind = recent[-1][2]

    if last_ok:
        note = f"The most recent LLM call succeeded ({len(failures)} of the last {len(recent)} failed)."
        health: RecentHealth = "healthy"
    else:
        note = (
            f"The most recent LLM call failed ({last_kind or 'error'}); "
            f"{len(failures)} of the last {len(recent)} failed. "
            "If the provider is a local model on CPU, raise AISOC_LITELLM_REQUEST_TIMEOUT."
        )
        health = "degraded"

    return {
        "recent_health": health,
        "recent_calls": len(recent),
        "recent_failures": len(failures),
        "recent_note": note,
    }
