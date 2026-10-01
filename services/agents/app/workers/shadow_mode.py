"""Shadow mode on the live queue: triage runs, and nothing it says is acted on.

Gap-closure Phase 2.1.

Phase 1 built shadow execution for replay, over a customer's *closed* history:
:class:`app.replay.shadow.ShadowTriageWriter` implements every write the
triage path makes and performs none of them. This is the same seam pointed at
live alerts, and it differs in exactly one way that matters.

A replay writes nothing at all, because its findings are already closed and
anything it wrote would be noise in a store somebody else reads. A live shadow
run has to write two things: the verdict, so an analyst can see what the agent
thought, and a decision row, so agreement can be measured when that analyst
closes the alert. What it must not do is *act*: no disposition set on the
alert, no auto-closure, no writeback to the source SIEM, no approval queued,
no outcome prior recorded, no escalation into the investigation graph.

The one that is easy to get wrong
=================================

``ledger.persist_auto_triage`` writes ``alerts.disposition``. That column is
the analyst's verdict, set from the feedback endpoint, and it is also the
column reconciliation reads to learn what the analyst decided. Letting a
shadow verdict land in it would mean the agent filled in the answer it is
about to be graded against, and every alert an analyst did not explicitly
re-dispose would score as perfect agreement.

That is the Phase 1 leakage lesson arriving by a different route, and it is
the reason ``persist_auto_triage`` grew a ``shadow`` flag rather than this
module simply forwarding the call. Under that flag the ledger still writes the
run, the event and the ``ai_score`` / ``ai_summary`` /
``ai_recommendations`` columns, which are the agent's own fields, and leaves
``disposition``, ``status`` and ``resolved_at`` untouched. The analyst decides
from a blank field, which is the only way their closure is independent
evidence.

Cost is not suppressed
======================

:attr:`ShadowModeTriageWriter.persists_cost` is ``True``. A shadow run places
real model calls against a real key, and a tenant measuring for a month must
see that spend. Replay declines it because a replay is a measurement the
tenant asked for and should not be billed twice for; a shadow run is the
product running.

Deduplication is not suppressed either
======================================

:meth:`~ShadowModeTriageWriter.cache_verdict` forwards. Production dedups an
alert flood through the cost governor, so a shadow run that did not would cost
more than the thing it is modelling and would measure a pipeline the tenant
will never operate. Replay declines it for a reason that does not apply here:
in a replay the cache is a third route by which the test window answers
itself, and on a live queue there is no test window.

Which way it fails
==================

:class:`LiveShadowModePolicy` distinguishes "no database configured" from
"database configured and unreadable", the same distinction
``app.services.tenant_policy`` draws in the actions service and for the same
reason. No database means no shadow table, no tenant could have enabled
anything, and nowhere to record a decision: shadow is off. A configured
database that will not answer means a tenant may well have asked for shadow
and we cannot see it, so the run is treated as shadow. Acting on an alert a
tenant asked us only to observe is the worse of the two errors, and the other
one is a few seconds of writeback that resumes on the next read.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Protocol, runtime_checkable

import structlog

from app.investigator import ledger as ledger_module

__all__ = [
    "UNCLASSIFIED",
    "LiveShadowModePolicy",
    "ShadowDecision",
    "ShadowModePolicy",
    "ShadowModeTriageWriter",
    "alert_class_of",
    "record_shadow_decision",
]

logger = structlog.get_logger(__name__)

#: Where an alert with no category lands. A null class would drop the alert
#: out of every per-class aggregate, so a tenant whose detection content sets
#: no category would appear to have no evidence at all rather than one bucket
#: of it.
UNCLASSIFIED = "unclassified"

#: Matches every class. A tenant starting out does not yet know which classes
#: their queue contains, which is most of what the first weeks of measurement
#: are for.
WILDCARD = "*"

#: Policy changes are rare and this is read once per alert, so a short TTL
#: keeps the common case to zero round trips while still picking up a change
#: within seconds. Same value and same reasoning as the actions service's
#: tenant policy cache.
_CACHE_TTL_SECONDS = 30.0

_cache: dict[tuple[str, str], tuple[float, bool]] = {}


def alert_class_of(raw_alert: dict[str, Any] | None) -> str:
    """The class this alert is measured under.

    ``alerts.category`` is what the console and the detection corpus already
    group by, so shadow mode uses it rather than inventing a parallel
    taxonomy that would have to be explained and kept in step.
    """
    category = str((raw_alert or {}).get("category") or "").strip().lower()
    return category or UNCLASSIFIED


@runtime_checkable
class ShadowModePolicy(Protocol):
    """Whether this tenant is measuring this alert class rather than acting on it."""

    async def is_shadow(self, tenant_ref: str, alert_class: str) -> bool:
        """True when this alert is to be measured rather than acted on."""


class LiveShadowModePolicy:
    """Reads ``aisoc_shadow_mode``. Treats an unreadable policy as shadow."""

    __slots__ = ()

    async def is_shadow(self, tenant_ref: str, alert_class: str) -> bool:
        key = (str(tenant_ref), alert_class)
        cached = _cache.get(key)
        now = time.monotonic()
        if cached is not None and now - cached[0] < _CACHE_TTL_SECONDS:
            return cached[1]

        pool = await ledger_module.get_pool()
        if pool is None:
            # No database: nothing could have been enabled and there is
            # nowhere to record a decision. Not cached, because a pool that
            # appears later should take effect immediately.
            return False

        try:
            async with pool.acquire() as conn:
                tenant_id = await ledger_module._resolve_tenant_id(conn, str(tenant_ref))
                if tenant_id is None:
                    # An unknown tenant cannot have configured anything, and a
                    # decision row for it would violate the foreign key.
                    logger.warning("shadow_mode.unknown_tenant", tenant_ref=str(tenant_ref)[:120])
                    return False
                await ledger_module._set_rls_context(conn, tenant_id)
                row = await conn.fetchrow(
                    """
                    SELECT bool_or(enabled) AS enabled
                    FROM aisoc_shadow_mode
                    WHERE tenant_id = $1 AND alert_class = ANY($2::text[])
                    """,
                    tenant_id,
                    [alert_class, WILDCARD],
                )
        except Exception as exc:  # noqa: BLE001 - never act on an unreadable policy
            logger.error(
                "shadow_mode.read_failed",
                tenant_ref=str(tenant_ref)[:120],
                alert_class=alert_class[:120],
                error=str(exc)[:300],
                treating_as="shadow",
            )
            return True

        enabled = bool(row and row["enabled"])
        _cache[key] = (now, enabled)
        return enabled


def clear_cache() -> None:
    """Drop the shadow-mode cache. Used by tests and after a policy update."""
    _cache.clear()


class ShadowDecision:
    """One verdict produced in shadow, on its way to the decision ledger.

    A plain object rather than a dataclass mirroring the table: the columns it
    fills are written out once in :func:`record_shadow_decision`, and a second
    field list here would be the copy that drifts.
    """

    __slots__ = (
        "alert_class",
        "alert_id",
        "confidence",
        "evidence_signature",
        "external_id",
        "model",
        "rule_id",
        "source",
        "tenant_ref",
        "verdict",
    )

    def __init__(
        self,
        *,
        tenant_ref: str,
        alert_class: str,
        alert_id: Any = None,
        external_id: str | None = None,
        rule_id: str | None = None,
        source: str | None = None,
        model: str | None = None,
        verdict: str | None = None,
        confidence: float | None = None,
        evidence_signature: str | None = None,
    ) -> None:
        self.tenant_ref = tenant_ref
        self.alert_class = alert_class
        self.alert_id = alert_id
        self.external_id = external_id
        self.rule_id = rule_id
        self.source = source
        self.model = model
        self.verdict = verdict
        self.confidence = confidence
        self.evidence_signature = evidence_signature


async def record_shadow_decision(decision: ShadowDecision) -> bool:
    """Append the verdict to ``aisoc_shadow_decisions``. Returns whether it landed.

    Idempotent on ``(tenant_id, alert_id)``. A broker redelivery re-triages the
    same alert, and two rows carrying the same opinion would count as two
    agreements: the sample would grow toward the promotion threshold without
    any new evidence behind it. The conflict updates rather than doing nothing,
    so a re-triage that produced a *different* verdict replaces the old one
    instead of leaving a stale opinion in the evidence.

    The analyst half is never touched on conflict. A decision that has already
    been graded keeps its grade.
    """
    pool = await ledger_module.get_pool()
    if pool is None:
        return False

    alert_uuid = ledger_module._coerce_uuid(decision.alert_id)
    if alert_uuid is None and not decision.external_id:
        # Nothing to reconcile against later. Recording it would add a row
        # that can never become evidence and can never be matched to a
        # closure, which reads on the scorecard as an agent that never gets
        # graded rather than as a wiring fault.
        logger.warning("shadow_mode.decision_unlinkable", tenant_ref=str(decision.tenant_ref)[:120])
        return False

    try:
        async with pool.acquire() as conn:
            tenant_id = await ledger_module._resolve_tenant_id(conn, str(decision.tenant_ref))
            if tenant_id is None:
                logger.warning("shadow_mode.decision_unknown_tenant", tenant_ref=str(decision.tenant_ref)[:120])
                return False
            await ledger_module._set_rls_context(conn, tenant_id)
            await conn.execute(
                """
                INSERT INTO aisoc_shadow_decisions
                    (id, tenant_id, alert_id, external_id, alert_class, rule_id,
                     source, model, verdict, confidence, evidence_signature, decided_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())
                ON CONFLICT (tenant_id, alert_id) WHERE alert_id IS NOT NULL
                DO UPDATE SET
                    verdict = EXCLUDED.verdict,
                    confidence = EXCLUDED.confidence,
                    model = EXCLUDED.model,
                    evidence_signature = EXCLUDED.evidence_signature,
                    decided_at = EXCLUDED.decided_at
                """,
                uuid.uuid4(),
                tenant_id,
                alert_uuid,
                decision.external_id,
                decision.alert_class or UNCLASSIFIED,
                decision.rule_id,
                decision.source,
                decision.model,
                decision.verdict,
                float(decision.confidence) if decision.confidence is not None else None,
                decision.evidence_signature,
            )
    except Exception as exc:  # noqa: BLE001 - a durable verdict outranks its measurement
        logger.warning(
            "shadow_mode.decision_write_failed",
            tenant_ref=str(decision.tenant_ref)[:120],
            error=str(exc)[:300],
        )
        return False
    return True


class ShadowModeTriageWriter:
    """A :class:`app.workers.triage_persistence.TriageWriter` that records and never acts.

    Wraps the live sink rather than reimplementing it. The two calls that are
    forwarded are forwarded to the real thing, so a shadow run and a live run
    differ by which methods are declined and by one flag, not by two code
    paths that have to be kept in step.
    """

    def __init__(self, delegate: Any, decision: ShadowDecision) -> None:
        self._delegate = delegate
        self._decision = decision
        #: Whether the decision row landed. Read by the worker's metrics so a
        #: silently failing measurement shows up as a number rather than as a
        #: scorecard that never fills in.
        self.recorded = False

    @property
    def escalation_allowed(self) -> bool:
        # Escalation runs the investigation graph, which enriches, proposes and
        # writes a node per step. That is acting.
        return False

    @property
    def persists_cost(self) -> bool:
        # Real calls against a real key. A tenant measuring for a month must
        # see the spend.
        return True

    async def persist_auto_triage(self, **fields: Any) -> None:
        """Record the verdict without letting it stand in for the analyst's."""
        fields["auto_closed"] = False
        fields["shadow"] = True
        await self._delegate.persist_auto_triage(**fields)

        self._decision.verdict = str(fields.get("verdict") or "") or None
        confidence = fields.get("confidence")
        self._decision.confidence = float(confidence) if confidence is not None else None
        raw = fields.get("raw_alert") or {}
        if self._decision.rule_id is None:
            self._decision.rule_id = _opt_text(raw.get("rule_id"))
        if self._decision.source is None:
            self._decision.source = _opt_text(raw.get("connector_type") or raw.get("source"))
        if self._decision.external_id is None:
            self._decision.external_id = _opt_text(raw.get("external_id"))
        self.recorded = await record_shadow_decision(self._decision)

    async def record_outcome(
        self,
        tenant_id: str,
        signature: str,
        *,
        disposition: str,
        confidence: float,
        author: str,
        alert_id: Any = None,
        injection_suspected: bool = False,
    ) -> None:
        # An outcome prior lets a later identical alert close without triage.
        # A shadow verdict must never reach that far: it would act on a future
        # alert through a store rather than directly, and it would put the
        # agent's own opinion into the evidence for the next one.
        return None

    async def record_suppression(
        self,
        *,
        tenant_ref: str,
        signature: str,
        alert_id: Any,
        disposition: str,
        prior_author: str,
    ) -> None:
        return None

    async def raise_approval(self, **fields: Any) -> Any:
        # An approval is a proposal to act, put in front of a human. Under
        # measurement there is nothing to approve.
        return None

    async def write_back_disposition(
        self,
        *,
        tenant_id: str,
        alert_id: str,
        disposition: str,
        confidence: float | None = None,
        rationale: str = "",
    ) -> dict[str, Any] | None:
        return None

    def cache_verdict(
        self,
        governor: Any,
        tenant_id: str,
        fingerprint: str,
        verdict: dict[str, Any],
        *,
        usd: float,
        tokens: int,
    ) -> None:
        self._delegate.cache_verdict(governor, tenant_id, fingerprint, verdict, usd=usd, tokens=tokens)


def _opt_text(value: Any) -> str | None:
    """A trimmed string, or ``None`` for absent and empty alike."""
    text = str(value).strip() if value is not None else ""
    return text or None
