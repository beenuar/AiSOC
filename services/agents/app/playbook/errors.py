"""Failures a second attempt cannot change.

The engine retries a failed step with exponential backoff up to
``step.retry_max``. That is right for a bridge that was momentarily
unreachable and wrong for a run whose context has no tenant: no amount of
waiting adds one, so the run spends fourteen seconds sleeping before failing
with the message it already had on the first attempt.

The cost is not the fourteen seconds. It is that a permanent misconfiguration
presents as flakiness — an operator watching a containment playbook during an
incident sees a step "retrying", concludes the network is unhappy, and waits.
The two cases need to look different because the operator's next move is
different: one is "wait", the other is "go and set the variable".

So the distinction is carried by the exception type rather than inferred from
the message. Any handler can raise something marked with
``PermanentStepFailure`` and the engine will fail the step on the first
attempt; nothing else about the failure path changes, and a handler that does
not care keeps the retry it has today.

The line this package draws
---------------------------
**Permanent** — the cause is this deployment's configuration or a violation of
the API's own contract. A second identical request gets a second identical
answer.

**Transient** — the cause is reachability. The request never arrived, or the
far side failed to serve it. A second attempt may well land.
"""

from __future__ import annotations


class PermanentStepFailure(Exception):
    """Marker: retrying this step cannot change the outcome.

    Raised on its own or mixed into a handler's own exception type, so the
    engine can ask ``isinstance`` rather than parse a message. It is a real
    exception rather than a bare mixin so a handler with no hierarchy of its
    own can raise it directly.
    """
