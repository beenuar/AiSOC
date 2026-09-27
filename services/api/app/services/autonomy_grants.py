"""Autonomy granted on a measured track record, and taken back when it slips.

Gap-closure Phase 2.3.

The thesis of this phase, in one sentence: autonomy is promoted by evidence,
not by a settings toggle. This module is where that becomes true. Nothing here
decides *what* the thresholds are or *how* agreement is computed, both of which
live in ``app/_vendor/autonomy_evidence_rules.py``, a byte-identical copy of
the module ``services/actions`` enforces from. What lives here is the part that
needs a database and an audit log: reading the evidence, recording the
transition, and writing it where it cannot later be rewritten.

Three properties are worth stating where somebody changing this file will see
them.

**A transition always carries its evidence.** Not a reference to it, not a
flag that lets it be recomputed later: the numbers themselves, frozen. Six
months after a disputed auto-closure, "why was this tenant allowed to do that"
has to be answerable against the numbers as they stood on the day. By then the
window has moved, decisions have aged out, the thresholds may have been
retuned and the model has probably changed, so a recomputed justification
would describe a different world while looking authoritative doing it.

**An override is a different word, never a different number.** An operator can
overrule a refusal, and that has to stay possible, because a gate with no
override is a gate that gets worked around by people who then stop telling you.
What must not happen is an override becoming indistinguishable from earned
autonomy once it is a week old. So the source is derived from the gate's own
verdict rather than from anything the caller sends, it is a constrained column
rather than a flag inside the JSON, it is a different audit action string, and
the refusals that were overruled travel in the snapshot beside it.

**Demotion is not the mirror image of promotion.** Promotion refuses an
unmeasured rate, because "not measured" must never be read as "met the
threshold". Demotion ignores one, because a week in which no malicious alert
arrived is not evidence the agent got worse, and revoking a grant over an
empty denominator would make quiet weeks dangerous.

Where the audit write goes
==========================

``emit_audit`` queues the row on the caller's session and computes the hash
chain; the caller owns the transaction. Every transition here commits the
grant and its audit row together, so a grant cannot exist without the entry
that explains it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import structlog
from fastapi import Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app._vendor.autonomy_evidence_rules import (
    CAPABILITIES,
    SCOPE_KINDS,
    EvidenceSnapshot,
    GrantSource,
    GrantState,
    PromotionThresholds,
    Refusal,
    TransitionDecision,
    evaluate_demotion,
    evaluate_promotion,
)
from app.services.audit import emit_audit
from app.services.shadow_agreement import agreement_for

logger = structlog.get_logger(__name__)

__all__ = [
    "AUDIT_DEMOTED",
    "AUDIT_GRANTED",
    "AUDIT_OVERRIDDEN",
    "AUDIT_REVOKED",
    "GrantRow",
    "GrantTransition",
    "list_grants",
    "reconcile_grants",
    "request_promotion",
    "revoke_grant",
]

#: Four audit actions, not one with a field. A reader filtering the audit log
#: for "who gave this tenant autonomy they had not earned" must not have to
#: parse JSON to find out, and a single `autonomy:changed` action would make
#: an override and an earned grant the same line until somebody did.
AUDIT_GRANTED = "autonomy:granted"
AUDIT_OVERRIDDEN = "autonomy:overridden"
AUDIT_DEMOTED = "autonomy:demoted"
AUDIT_REVOKED = "autonomy:revoked"


class GrantScopeError(ValueError):
    """A scope or capability outside the fixed vocabulary."""


@dataclass(frozen=True)
class GrantRow:
    """One tenant's standing on one capability, as the console renders it."""

    id: str
    scope_kind: str
    scope_key: str
    capability: str
    state: str
    source: str
    evidence: dict[str, Any] | None
    granted_at: str | None
    demoted_at: str | None
    demoted_reason: str | None
    override_reason: str | None

    @property
    def is_override(self) -> bool:
        """Whether this autonomy was overruled into existence rather than earned."""
        return self.source == GrantSource.OPERATOR_OVERRIDE.value

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scope_kind": self.scope_kind,
            "scope_key": self.scope_key,
            "capability": self.capability,
            "state": self.state,
            "source": self.source,
            # Surfaced as its own field so no client has to compare a string
            # to know it is looking at an override.
            "is_override": self.is_override,
            "evidence": self.evidence,
            "granted_at": self.granted_at,
            "demoted_at": self.demoted_at,
            "demoted_reason": self.demoted_reason,
            "override_reason": self.override_reason,
        }


@dataclass(frozen=True)
class GrantTransition:
    """What happened when a promotion was asked for, or a grant re-checked."""

    granted: bool
    state: str
    source: str
    refusals: tuple[Refusal, ...]
    evidence: dict[str, Any]
    changed: bool

    @property
    def refusal_values(self) -> list[str]:
        return [refusal.value for refusal in self.refusals]

    def as_dict(self) -> dict[str, Any]:
        return {
            "granted": self.granted,
            "state": self.state,
            "source": self.source,
            "is_override": self.source == GrantSource.OPERATOR_OVERRIDE.value,
            "refusals": self.refusal_values,
            "evidence": self.evidence,
            "changed": self.changed,
        }


def _validate_scope(scope_kind: str, scope_key: str, capability: str) -> None:
    """Refuse anything outside the vocabulary both services share.

    A grant naming a capability no code path consults is indistinguishable
    from autonomy that works, right up until somebody relies on it.
    """
    if scope_kind not in SCOPE_KINDS:
        raise GrantScopeError(f"scope_kind must be one of {list(SCOPE_KINDS)}")
    if capability not in CAPABILITIES:
        raise GrantScopeError(f"capability must be one of {list(CAPABILITIES)}")
    if not scope_key or len(scope_key) > 200:
        raise GrantScopeError("scope_key must be between 1 and 200 characters")


async def _shadow_enabled(db: AsyncSession, tenant_id: uuid.UUID | str, scope_kind: str, scope_key: str) -> bool:
    """Whether this scope was ever being measured.

    Only meaningful for an alert class. A response verb's track record is the
    triage verdicts behind the alerts it would act on, which is the tenant's
    shadow mode as a whole, so an action-verb scope asks whether anything at
    all is being measured.
    """
    if scope_kind == "alert_class":
        classes = [scope_key, "*"]
    else:
        classes = None

    if classes is None:
        row = (
            (
                await db.execute(
                    text("SELECT bool_or(enabled) AS enabled FROM aisoc_shadow_mode WHERE tenant_id = :tenant_id"),
                    {"tenant_id": str(tenant_id)},
                )
            )
            .mappings()
            .first()
        )
    else:
        row = (
            (
                await db.execute(
                    text(
                        """
                    SELECT bool_or(enabled) AS enabled
                    FROM aisoc_shadow_mode
                    WHERE tenant_id = :tenant_id AND alert_class = ANY(:classes)
                    """
                    ),
                    {"tenant_id": str(tenant_id), "classes": classes},
                )
            )
            .mappings()
            .first()
        )
    return bool(row and row["enabled"])


async def _snapshot(
    db: AsyncSession,
    tenant_id: uuid.UUID | str,
    *,
    scope_kind: str,
    scope_key: str,
    capability: str,
    thresholds: PromotionThresholds,
    refusals: tuple[Refusal, ...],
    now: datetime | None = None,
) -> tuple[EvidenceSnapshot, TransitionDecision, bool]:
    """Read the evidence for one scope and judge it.

    Returns the snapshot, the promotion verdict and whether shadow mode was
    on, because the caller needs all three and reading the evidence twice
    would risk judging one window and recording another.
    """
    # An action-verb grant is judged on the tenant's whole track record: the
    # verdicts behind the alerts that verb would act on are not filed under
    # the verb's name, and inventing a per-verb slice of triage agreement
    # would be a number with nothing behind it.
    evidence_scope = "alert_class" if scope_kind == "alert_class" else "tenant"
    evidence = await agreement_for(
        db,
        tenant_id,
        scope_kind=evidence_scope,
        scope_key=scope_key if evidence_scope == "alert_class" else "*",
        thresholds=thresholds,
        now=now,
        with_provenance=True,
    )
    shadow_on = await _shadow_enabled(db, tenant_id, scope_kind, scope_key)
    verdict = evaluate_promotion(
        window=evidence.window,
        recent=evidence.recent,
        thresholds=thresholds,
        shadow_enabled=shadow_on,
    )
    snapshot = EvidenceSnapshot(
        scope_kind=scope_kind,
        scope_key=scope_key,
        capability=capability,
        window=evidence.window,
        recent=evidence.recent,
        thresholds=thresholds,
        window_start=evidence.window_start,
        window_end=evidence.window_end,
        refusals=refusals or verdict.refusals,
        first_decision_id=evidence.provenance.first_decision_id,
        last_decision_id=evidence.provenance.last_decision_id,
        models=evidence.provenance.models,
        resolution_sources=evidence.provenance.resolution_sources,
    )
    return snapshot, verdict, shadow_on


async def request_promotion(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID | str,
    actor_id: uuid.UUID | None,
    actor_email: str | None,
    scope_kind: str,
    scope_key: str,
    capability: str,
    override: bool = False,
    override_reason: str | None = None,
    thresholds: PromotionThresholds | None = None,
    request: Request | None = None,
    now: datetime | None = None,
) -> GrantTransition:
    """Grant the capability if the evidence earns it, or if a human overrules.

    ``override`` never changes what the gate decides. It changes what happens
    to the refusals: without it they are returned and nothing is written, with
    it they are written into the snapshot beside a grant whose ``source`` says
    it was overruled. The verdict is computed first and identically either
    way, which is why the source cannot be faked by the caller.
    """
    _validate_scope(scope_kind, scope_key, capability)
    limits = thresholds or PromotionThresholds()

    snapshot, verdict, _ = await _snapshot(
        db,
        tenant_id,
        scope_kind=scope_kind,
        scope_key=scope_key,
        capability=capability,
        thresholds=limits,
        refusals=(),
        now=now,
    )

    if not verdict.allowed and not override:
        # Refused. Nothing is written: a refusal is not a state change, and a
        # row recording every time somebody asked would bury the transitions
        # that matter.
        logger.info(
            "autonomy_grants.refused",
            tenant_id=str(tenant_id),
            scope_kind=scope_kind,
            scope_key=scope_key,
            capability=capability,
            refusals=verdict.refusal_values,
        )
        return GrantTransition(
            granted=False,
            state=GrantState.SHADOW.value,
            source=GrantSource.EARNED.value,
            refusals=verdict.refusals,
            evidence=snapshot.as_dict(),
            changed=False,
        )

    source = GrantSource.EARNED if verdict.allowed else GrantSource.OPERATOR_OVERRIDE
    payload = snapshot.as_dict()

    await db.execute(
        text(
            """
            INSERT INTO aisoc_autonomy_grants
                (tenant_id, scope_kind, scope_key, capability, state, source,
                 evidence, granted_at, granted_by, override_reason, updated_at)
            VALUES
                (:tenant_id, :scope_kind, :scope_key, :capability, 'granted', :source,
                 CAST(:evidence AS JSONB), now(), :granted_by, :override_reason, now())
            ON CONFLICT (tenant_id, scope_kind, scope_key, capability) DO UPDATE SET
                state = 'granted',
                source = EXCLUDED.source,
                evidence = EXCLUDED.evidence,
                granted_at = now(),
                granted_by = EXCLUDED.granted_by,
                override_reason = EXCLUDED.override_reason,
                -- Cleared, because they describe the previous demotion and a
                -- row showing both a current grant and a demotion reason
                -- invites the reader to think the grant is still revoked.
                demoted_at = NULL,
                demoted_reason = NULL,
                updated_at = now()
            """
        ),
        {
            "tenant_id": str(tenant_id),
            "scope_kind": scope_kind,
            "scope_key": scope_key,
            "capability": capability,
            "source": source.value,
            "evidence": _json(payload),
            "granted_by": str(actor_id) if actor_id else None,
            "override_reason": override_reason if source is GrantSource.OPERATOR_OVERRIDE else None,
        },
    )

    await emit_audit(
        db=db,
        tenant_id=_as_uuid(tenant_id),
        actor_id=actor_id,
        actor_email=actor_email,
        action=AUDIT_GRANTED if source is GrantSource.EARNED else AUDIT_OVERRIDDEN,
        resource="autonomy_grant",
        resource_id=f"{scope_kind}:{scope_key}:{capability}",
        changes={
            "state": GrantState.GRANTED.value,
            "source": source.value,
            "override_reason": override_reason,
            # On an override these are the refusals that were overruled. On an
            # earned grant the list is empty, which is itself the record that
            # nothing had to be waived.
            "waived_refusals": verdict.refusal_values if source is GrantSource.OPERATOR_OVERRIDE else [],
            "evidence": payload,
        },
        request=request,
    )
    await db.commit()

    logger.info(
        "autonomy_grants.granted",
        tenant_id=str(tenant_id),
        scope_kind=scope_kind,
        scope_key=scope_key,
        capability=capability,
        source=source.value,
        waived=verdict.refusal_values if source is GrantSource.OPERATOR_OVERRIDE else [],
    )
    return GrantTransition(
        granted=True,
        state=GrantState.GRANTED.value,
        source=source.value,
        refusals=verdict.refusals,
        evidence=payload,
        changed=True,
    )


async def reconcile_grants(
    db: AsyncSession,
    tenant_id: uuid.UUID | str,
    *,
    thresholds: PromotionThresholds | None = None,
    request: Request | None = None,
    now: datetime | None = None,
) -> list[GrantTransition]:
    """Re-check every standing grant and demote the ones that no longer hold.

    Demotion is automatic in the sense that nobody has to ask for it: this
    runs whenever the grants are read and whenever the dispatch path refreshes
    its view, so a grant cannot outlive its evidence by more than the interval
    between those.

    An override is re-checked too, and demoted on the same floors. An operator
    overruling a refusal is saying "I accept this today", not "stop measuring";
    exempting overrides would make the override permanent, which is the one
    thing that would turn it into a settings toggle after all.
    """
    limits = thresholds or PromotionThresholds()
    rows = (
        (
            await db.execute(
                text(
                    """
                SELECT scope_kind, scope_key, capability, source
                FROM aisoc_autonomy_grants
                WHERE tenant_id = :tenant_id AND state = 'granted'
                ORDER BY scope_kind, scope_key, capability
                """
                ),
                {"tenant_id": str(tenant_id)},
            )
        )
        .mappings()
        .all()
    )

    transitions: list[GrantTransition] = []
    for row in rows:
        evidence_scope = "alert_class" if row["scope_kind"] == "alert_class" else "tenant"
        evidence = await agreement_for(
            db,
            tenant_id,
            scope_kind=evidence_scope,
            scope_key=row["scope_key"] if evidence_scope == "alert_class" else "*",
            thresholds=limits,
            now=now,
            with_provenance=True,
        )
        verdict = evaluate_demotion(window=evidence.window, recent=evidence.recent, thresholds=limits)
        if verdict.allowed:
            continue

        snapshot = EvidenceSnapshot(
            scope_kind=row["scope_kind"],
            scope_key=row["scope_key"],
            capability=row["capability"],
            window=evidence.window,
            recent=evidence.recent,
            thresholds=limits,
            window_start=evidence.window_start,
            window_end=evidence.window_end,
            refusals=verdict.refusals,
            first_decision_id=evidence.provenance.first_decision_id,
            last_decision_id=evidence.provenance.last_decision_id,
            models=evidence.provenance.models,
            resolution_sources=evidence.provenance.resolution_sources,
        )
        payload = snapshot.as_dict()
        reason = ", ".join(verdict.refusal_values)

        await db.execute(
            text(
                """
                UPDATE aisoc_autonomy_grants
                   SET state = 'demoted',
                       evidence = CAST(:evidence AS JSONB),
                       demoted_at = now(),
                       demoted_reason = :reason,
                       updated_at = now()
                 WHERE tenant_id = :tenant_id
                   AND scope_kind = :scope_kind
                   AND scope_key = :scope_key
                   AND capability = :capability
                """
            ),
            {
                "tenant_id": str(tenant_id),
                "scope_kind": row["scope_kind"],
                "scope_key": row["scope_key"],
                "capability": row["capability"],
                "evidence": _json(payload),
                "reason": reason,
            },
        )
        await emit_audit(
            db=db,
            tenant_id=_as_uuid(tenant_id),
            # No actor: nobody asked for this. An actor id here would name
            # whoever happened to load the page as the person who revoked it.
            actor_id=None,
            actor_email=None,
            action=AUDIT_DEMOTED,
            resource="autonomy_grant",
            resource_id=f"{row['scope_kind']}:{row['scope_key']}:{row['capability']}",
            changes={
                "state": GrantState.DEMOTED.value,
                "previous_source": row["source"],
                "refusals": verdict.refusal_values,
                "evidence": payload,
            },
            request=request,
        )
        transitions.append(
            GrantTransition(
                granted=False,
                state=GrantState.DEMOTED.value,
                source=row["source"],
                refusals=verdict.refusals,
                evidence=payload,
                changed=True,
            )
        )
        logger.warning(
            "autonomy_grants.demoted",
            tenant_id=str(tenant_id),
            scope_kind=row["scope_kind"],
            scope_key=row["scope_key"],
            capability=row["capability"],
            refusals=verdict.refusal_values,
        )

    if transitions:
        await db.commit()
    return transitions


async def revoke_grant(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID | str,
    actor_id: uuid.UUID | None,
    actor_email: str | None,
    scope_kind: str,
    scope_key: str,
    capability: str,
    request: Request | None = None,
) -> bool:
    """Hand a capability back. Returns whether a standing grant was revoked.

    Deliberately not the same audit action as a demotion. A human deciding to
    stop and the evidence deciding for them are different events, and folding
    them together would make "was this taken away because the numbers slipped"
    unanswerable from the log.
    """
    _validate_scope(scope_kind, scope_key, capability)
    result = await db.execute(
        text(
            """
            UPDATE aisoc_autonomy_grants
               SET state = 'shadow',
                   demoted_at = now(),
                   demoted_reason = 'revoked by operator',
                   updated_at = now()
             WHERE tenant_id = :tenant_id
               AND scope_kind = :scope_kind
               AND scope_key = :scope_key
               AND capability = :capability
               AND state = 'granted'
            """
        ),
        {
            "tenant_id": str(tenant_id),
            "scope_kind": scope_kind,
            "scope_key": scope_key,
            "capability": capability,
        },
    )
    if not result.rowcount:
        return False

    await emit_audit(
        db=db,
        tenant_id=_as_uuid(tenant_id),
        actor_id=actor_id,
        actor_email=actor_email,
        action=AUDIT_REVOKED,
        resource="autonomy_grant",
        resource_id=f"{scope_kind}:{scope_key}:{capability}",
        changes={"state": GrantState.SHADOW.value},
        request=request,
    )
    await db.commit()
    return True


async def list_grants(db: AsyncSession, tenant_id: uuid.UUID | str) -> list[GrantRow]:
    """Every grant this tenant holds or has held, current state first."""
    rows = (
        (
            await db.execute(
                text(
                    """
                SELECT id::text AS id, scope_kind, scope_key, capability, state, source,
                       evidence, granted_at, demoted_at, demoted_reason, override_reason
                FROM aisoc_autonomy_grants
                WHERE tenant_id = :tenant_id
                ORDER BY state, scope_kind, scope_key, capability
                """
                ),
                {"tenant_id": str(tenant_id)},
            )
        )
        .mappings()
        .all()
    )
    return [
        GrantRow(
            id=row["id"],
            scope_kind=row["scope_kind"],
            scope_key=row["scope_key"],
            capability=row["capability"],
            state=row["state"],
            source=row["source"],
            evidence=row["evidence"],
            granted_at=row["granted_at"].isoformat() if row["granted_at"] else None,
            demoted_at=row["demoted_at"].isoformat() if row["demoted_at"] else None,
            demoted_reason=row["demoted_reason"],
            override_reason=row["override_reason"],
        )
        for row in rows
    ]


def _json(payload: dict[str, Any]) -> str:
    import json  # noqa: PLC0415 - only needed on the write path

    return json.dumps(payload, sort_keys=True, default=str)


def _as_uuid(value: uuid.UUID | str) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
