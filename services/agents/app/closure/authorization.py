"""The one place a production alert may be authorized to close itself.

Phase 1 of the closure remediation. See
`docs/remediation/phase-1-closure-authorization.md`.

Why this exists
---------------
`alerts.status` becomes `'resolved'` in exactly one statement: the `UPDATE
alerts` at the end of :func:`app.investigator.ledger.persist_auto_triage`,
whose `CASE WHEN $7 AND NOT $10 THEN 'resolved'` turns on a caller-supplied
`auto_closed` flag. Two production callers set that flag and only one of them
asked permission.

* :func:`app.agents.auto_triage_agent.run_auto_triage` consulted
  :func:`app.closure.policy.decide` — the kill switch, the tenant's policy
  row, the earned `auto_close` grant.
* :meth:`FusedAlertTriageWorker._maybe_suppress_from_memory` set
  `AgentStatus.COMPLETED` straight from a stored outcome prior, and
  `_record` forwarded `auto_closed=state.status is AgentStatus.COMPLETED`.
  The strings `closure_policy` and `kill_switch` appear in that module only
  inside comments.

A remembered verdict had become remembered permission. A trusted prior says
something about the *alert*; it says nothing about whether this tenant, today,
under the current policy, with the stop controls as they stand, permits a
machine to close it.

What this is not
----------------
It is **not** a second policy implementation. Thresholds, the enabled flag,
`require_grant` and the kill switch all stay in :mod:`app.closure.policy` and
are reached through :func:`policy.decide`. What this module adds is the set of
preconditions that are not per-tenant policy at all — the verdict has to be
auto-closeable, the run has to be real rather than a shadow or a replay, and
the reasoning has to be grounded in the evidence — and, crucially, a single
call site that every caller of the durable write passes through.

The agent still pre-checks the policy before it writes a verdict, because an
operator reading an alert wants "auto-close withheld: ..." in the findings
rather than silence. That pre-check is advisory. This one decides, it runs
against the state of the world at the moment of the write, and because it
lives inside `persist_auto_triage` a future caller cannot route around it
without removing it.

Why at the write and not at the decision
----------------------------------------
Retries, resumed work and deduplicated verdicts all persist a verdict that
was reached earlier, sometimes much earlier. An authorization computed with
the verdict and carried alongside it would let a tenant disable closure and
still have in-flight work close alerts afterwards. Evaluating here means the
answer is always derived from the policy that is in force when the row
changes, never from the one that was in force when the model answered.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import structlog

from app.closure import policy as closure_policy
from app.memory.institutional import POOL_READY, POOL_UNAVAILABLE, POOL_UNCONFIGURED

logger = structlog.get_logger()

__all__ = [
    "POOL_READY",
    "POOL_UNAVAILABLE",
    "POOL_UNCONFIGURED",
    "ClosureAuthorization",
    "alert_class_of",
    "authorize_auto_closure",
]

#: The keys a fused alert may carry its class under, in precedence order.
#: Shared with :func:`app.agents.auto_triage_agent._alert_class_of` rather
#: than restated, because the agent pre-checks the policy for one class and
#: this module re-checks it at the write: two derivations that disagreed
#: would let a policy row pass one and fail the other, and the result would
#: read as a flapping gate rather than as two readers of one field.
_CLASS_KEYS = ("alert_class", "category", "rule_category")


@dataclass(frozen=True)
class ClosureAuthorization:
    """Whether this write may close the alert, and why not if it may not."""

    allowed: bool
    reason: str
    #: Which control decided. One of ``shadow``, ``verdict``,
    #: ``groundedness``, ``kill_switch``, ``policy``, ``default_deny``,
    #: ``error``. Written into the alert's findings so an operator asking
    #: "why is this still open" is told which control to look at, rather
    #: than being sent to debug a subsystem that is working.
    source: str
    threshold: float | None = None

    def __bool__(self) -> bool:
        return self.allowed


def alert_class_of(raw_alert: Mapping[str, Any] | None) -> str | None:
    """The class a closure policy row and an `auto_close` grant key on."""
    if not isinstance(raw_alert, Mapping):
        return None
    for key in _CLASS_KEYS:
        value = raw_alert.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


async def authorize_auto_closure(
    *,
    tenant_ref: str | None,
    raw_alert: Mapping[str, Any] | None,
    verdict: str,
    confidence: float,
    shadow: bool,
    ungrounded: bool | None,
    tier: str,
    default_threshold: float | None = None,
) -> ClosureAuthorization:
    """Decide whether this durable write may move an alert to ``resolved``.

    Called from :func:`app.investigator.ledger.persist_auto_triage` with the
    tenant already resolved to its canonical UUID, so the policy that is read
    is unambiguously the one belonging to the alert being closed.

    Every failure is a refusal. An unreadable policy, an unreachable
    database, a tenant that cannot be identified: none of them is a yes.
    """
    # Imported here, not at module scope, and this is the documented
    # circular-dependency exception rather than a style slip. The ledger
    # imports this module, `app.agents.__init__` eagerly imports
    # `auto_triage_agent`, and that reaches the ledger — so a top-level
    # `from app.agents.dispositions import ...` makes `app.closure.authorization`
    # unimportable with a partially-initialised-module error. The same applies
    # to `AUTO_CLOSE_THRESHOLD` below, which additionally is mutable at
    # runtime through `set_threshold`, so reading it per call is what keeps
    # the chokepoint and the agent's pre-check in step.
    from app.agents.dispositions import AUTO_CLOSEABLE_DISPOSITIONS, normalize_disposition

    if shadow:
        # Belt and braces. `persist_auto_triage`'s SQL already guards with
        # `NOT $10`, and `ShadowTriageWriter` already forces `auto_closed`
        # off. Repeating it here means the chokepoint's answer is complete on
        # its own terms, so a reader does not have to hold three mechanisms
        # in their head to know a shadow run cannot close anything.
        return ClosureAuthorization(False, "shadow run: production status is never changed by an observation", "shadow")

    normalized = normalize_disposition(str(verdict or ""), default="")
    if normalized not in AUTO_CLOSEABLE_DISPOSITIONS:
        return ClosureAuthorization(
            False,
            f"verdict {normalized or str(verdict)!r} is not auto-closeable; it escalates to a human",
            "verdict",
        )

    if ungrounded:
        # The groundedness gate demotes the verdict in the worker, but only
        # when it is switched on and only on the LLM path. Repeating the
        # refusal here means an ungrounded verdict cannot close an alert by
        # arriving through some other tier.
        return ClosureAuthorization(
            False,
            "the reasoning cites indicators the evidence does not contain, so the verdict is not fit to close on",
            "groundedness",
        )

    if not (tenant_ref or "").strip():
        return ClosureAuthorization(
            False,
            "no tenant on this verdict, so no policy can authorize closing it",
            "default_deny",
        )

    threshold = default_threshold
    if threshold is None:
        from app.agents.auto_triage_agent import AUTO_CLOSE_THRESHOLD

        threshold = AUTO_CLOSE_THRESHOLD

    decision = await closure_policy.decide(
        tenant_id=tenant_ref,
        alert_class=alert_class_of(raw_alert),
        confidence=float(confidence or 0.0),
        default_threshold=float(threshold),
    )

    if not decision.allowed:
        logger.info(
            "closure.authorization.withheld",
            tenant_id=tenant_ref,
            tier=tier,
            verdict=normalized,
            source=decision.source,
            reason=decision.reason,
        )
    return ClosureAuthorization(decision.allowed, decision.reason, decision.source, decision.threshold)
