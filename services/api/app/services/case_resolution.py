"""The resolution contract: what `resolved` has to mean (WS7.2).

`resolved` was a free transition — the PATCH gate checked only the status
ladder, the war-room chat decision and the inbound ITSM mirror checked
nothing, and the hourly sweep then auto-closed whatever arrived. This module
is the **one shared checker**, the way `case_status` is the one vocabulary:
every writer that can produce `resolved` consults :func:`resolution_gaps`
and refuses (or demotes, where a vendor webhook cannot be refused) while
requirements are unmet.

The contract, when a tenant's policy enforces it:

* **containment** — verified by a named probe/action reference, or waived
  with a written reason;
* **eradication and recovery** — both recorded;
* **root cause** — the WS7.1 record exists with status ``determined`` or
  ``undetermined`` (whose missing-telemetry reason its own contract already
  requires). A ``hypothesis`` does not satisfy: that status exists precisely
  to say "nothing verified this";
* **affected entities** — at least one recorded on the case or its alerts;
* **customer notified** — channel and time.

**Off by default, per tenant** (rule 14: new enforcement is opt-in). No
policy row, or ``enforce = false``, means no gaps — a deployment keeps its
workflow until the tenant turns the contract on. When the policy row cannot
be read at decision time the transition is refused naming the read failure:
"configured but unavailable" must refuse, and silently waving a resolution
through because a table was unreachable is the kill-switch defect again.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

ContainmentState = Literal["verified", "not_required"]


class ResolutionValidationError(ValueError):
    """Facts that violate their own conditional requirements."""


class ResolutionPolicy(BaseModel):
    enforce: bool = False
    require_containment: bool = True
    require_eradication_recovery: bool = True
    require_root_cause: bool = True
    require_entities: bool = True
    require_notification: bool = True


class ResolutionFactsIn(BaseModel):
    containment_state: ContainmentState | None = None
    #: Required when ``containment_state == "verified"``: the action/probe
    #: that proved it (an action id, a probe result reference) — a bare
    #: "verified" with nothing behind it is an assertion, not a fact.
    containment_reference: str | None = Field(default=None, max_length=500)
    #: Required when ``containment_state == "not_required"``.
    containment_reason: str | None = Field(default=None, max_length=2000)
    eradication: str | None = Field(default=None, max_length=8000)
    recovery: str | None = Field(default=None, max_length=8000)
    customer_notified_channel: str | None = Field(default=None, max_length=200)
    customer_notified_at: datetime | None = None


def validate_facts(facts: ResolutionFactsIn) -> None:
    """Conditional requirements, named in the refusal."""
    if facts.containment_state == "verified" and not (facts.containment_reference or "").strip():
        raise ResolutionValidationError(
            "containment_state='verified' requires the verification reference — the action or probe that proved it"
        )
    if facts.containment_state == "not_required" and not (facts.containment_reason or "").strip():
        raise ResolutionValidationError("containment_state='not_required' requires the reason it was not required")
    has_channel = bool((facts.customer_notified_channel or "").strip())
    has_time = facts.customer_notified_at is not None
    if has_channel != has_time:
        raise ResolutionValidationError(
            "a customer notification is recorded as channel and time together; one without the other is half a fact"
        )


def compute_gaps(
    policy: ResolutionPolicy | None,
    facts: ResolutionFactsIn | None,
    *,
    root_cause_status: str | None,
    entity_count: int,
) -> list[str]:
    """The unmet requirements, each phrased for the analyst who reads it.

    Pure: the loaders feed it, the tests drive it directly. An empty list
    means the transition may proceed.
    """
    if policy is None or not policy.enforce:
        return []

    gaps: list[str] = []

    if policy.require_containment:
        state = facts.containment_state if facts else None
        if state not in ("verified", "not_required"):
            gaps.append("containment is neither verified nor waived — record a verified probe/action reference, or waive it with a reason")

    if policy.require_eradication_recovery:
        eradication = (facts.eradication or "").strip() if facts else ""
        recovery = (facts.recovery or "").strip() if facts else ""
        if not eradication or not recovery:
            gaps.append("eradication and recovery steps are not both recorded")

    if policy.require_root_cause:
        if root_cause_status == "hypothesis":
            gaps.append(
                "root cause is a hypothesis — a hypothesis is an unverified lead; "
                "resolve requires determined, or undetermined with the missing "
                "telemetry named"
            )
        elif root_cause_status not in ("determined", "undetermined"):
            gaps.append(
                "the root cause is not recorded — a determined record, or an undetermined one naming the missing telemetry, is required"
            )

    if policy.require_entities and entity_count < 1:
        gaps.append("no affected entities are recorded on the case or its alerts")

    if policy.require_notification:
        has_notification = bool(facts and (facts.customer_notified_channel or "").strip() and facts.customer_notified_at)
        if not has_notification:
            gaps.append("the customer notification (channel and time) is not recorded")

    return gaps


# ---------------------------------------------------------------------------
# Loaders — explicit tenant predicates on every statement, the cases-family
# convention, on top of the RLS the new tables carry.
# ---------------------------------------------------------------------------


async def fetch_policy(db: AsyncSession, tenant_id: uuid.UUID) -> ResolutionPolicy | None:
    row = (
        await db.execute(
            text(
                """
                SELECT enforce, require_containment, require_eradication_recovery,
                       require_root_cause, require_entities, require_notification
                FROM case_resolution_policies
                WHERE tenant_id = :tenant_id
                """
            ),
            {"tenant_id": str(tenant_id)},
        )
    ).fetchone()
    if row is None:
        return None
    return ResolutionPolicy(
        enforce=bool(row.enforce),
        require_containment=bool(row.require_containment),
        require_eradication_recovery=bool(row.require_eradication_recovery),
        require_root_cause=bool(row.require_root_cause),
        require_entities=bool(row.require_entities),
        require_notification=bool(row.require_notification),
    )


async def upsert_policy(db: AsyncSession, tenant_id: uuid.UUID, policy: ResolutionPolicy) -> None:
    await db.execute(
        text(
            """
            INSERT INTO case_resolution_policies
                (tenant_id, enforce, require_containment, require_eradication_recovery,
                 require_root_cause, require_entities, require_notification)
            VALUES
                (:tenant_id, :enforce, :rc, :rer, :rrc, :re, :rn)
            ON CONFLICT (tenant_id) DO UPDATE SET
                enforce = EXCLUDED.enforce,
                require_containment = EXCLUDED.require_containment,
                require_eradication_recovery = EXCLUDED.require_eradication_recovery,
                require_root_cause = EXCLUDED.require_root_cause,
                require_entities = EXCLUDED.require_entities,
                require_notification = EXCLUDED.require_notification,
                updated_at = now()
            """
        ),
        {
            "tenant_id": str(tenant_id),
            "enforce": policy.enforce,
            "rc": policy.require_containment,
            "rer": policy.require_eradication_recovery,
            "rrc": policy.require_root_cause,
            "re": policy.require_entities,
            "rn": policy.require_notification,
        },
    )


async def fetch_facts(db: AsyncSession, tenant_id: uuid.UUID, case_id: uuid.UUID) -> ResolutionFactsIn | None:
    row = (
        await db.execute(
            text(
                """
                SELECT containment_state, containment_reference, containment_reason,
                       eradication, recovery, customer_notified_channel,
                       customer_notified_at
                FROM case_resolution_facts
                WHERE tenant_id = :tenant_id AND case_id = :case_id
                """
            ),
            {"tenant_id": str(tenant_id), "case_id": str(case_id)},
        )
    ).fetchone()
    if row is None:
        return None
    return ResolutionFactsIn(
        containment_state=row.containment_state,
        containment_reference=row.containment_reference,
        containment_reason=row.containment_reason,
        eradication=row.eradication,
        recovery=row.recovery,
        customer_notified_channel=row.customer_notified_channel,
        customer_notified_at=row.customer_notified_at,
    )


async def upsert_facts(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    case_id: uuid.UUID,
    facts: ResolutionFactsIn,
    updated_by: str | None,
) -> None:
    await db.execute(
        text(
            """
            INSERT INTO case_resolution_facts
                (tenant_id, case_id, containment_state, containment_reference,
                 containment_reason, eradication, recovery,
                 customer_notified_channel, customer_notified_at, updated_by)
            VALUES
                (:tenant_id, :case_id, :cs, :cref, :creason, :erad, :rec,
                 :nchan, :nat, :by)
            ON CONFLICT (tenant_id, case_id) DO UPDATE SET
                containment_state = EXCLUDED.containment_state,
                containment_reference = EXCLUDED.containment_reference,
                containment_reason = EXCLUDED.containment_reason,
                eradication = EXCLUDED.eradication,
                recovery = EXCLUDED.recovery,
                customer_notified_channel = EXCLUDED.customer_notified_channel,
                customer_notified_at = EXCLUDED.customer_notified_at,
                updated_by = EXCLUDED.updated_by,
                updated_at = now()
            """
        ),
        {
            "tenant_id": str(tenant_id),
            "case_id": str(case_id),
            "cs": facts.containment_state,
            "cref": facts.containment_reference,
            "creason": facts.containment_reason,
            "erad": facts.eradication,
            "rec": facts.recovery,
            "nchan": facts.customer_notified_channel,
            "nat": facts.customer_notified_at,
            "by": updated_by,
        },
    )


async def count_affected_entities(db: AsyncSession, tenant_id: uuid.UUID, case_id: uuid.UUID) -> int:
    """Entities recorded on the case or its linked alerts — derived, never
    self-attested: the requirement is that the case *names who was hit*.

    Counts observable-graph nodes on the case plus the distinct affected
    users/hosts/IPs on its linked alerts, in one statement.
    """
    row = (
        await db.execute(
            text(
                """
                SELECT
                    COALESCE(jsonb_array_length(c.observable_graph -> 'nodes'), 0)
                    + COALESCE((
                        SELECT COUNT(*)
                        FROM alerts a,
                             LATERAL (
                                 SELECT jsonb_array_elements_text(
                                     COALESCE(a.affected_users, '[]'::jsonb)
                                     || COALESCE(a.affected_hosts, '[]'::jsonb)
                                     || COALESCE(a.affected_ips, '[]'::jsonb)
                                 ) AS entity
                             ) e
                        WHERE a.tenant_id = :tenant_id
                          AND a.id = ANY(c.alert_ids)
                    ), 0) AS n
                FROM aisoc_cases c
                WHERE c.tenant_id = :tenant_id AND c.id = :case_id
                """
            ),
            {"tenant_id": str(tenant_id), "case_id": str(case_id)},
        )
    ).fetchone()
    return int(row.n) if row is not None else 0


async def fetch_root_cause_status(db: AsyncSession, tenant_id: uuid.UUID, case_id: uuid.UUID) -> str | None:
    row = (
        await db.execute(
            text("SELECT status FROM case_root_cause_records WHERE tenant_id = :tenant_id AND case_id = :case_id"),
            {"tenant_id": str(tenant_id), "case_id": str(case_id)},
        )
    ).fetchone()
    return str(row.status) if row is not None else None


async def resolution_gaps(db: AsyncSession, tenant_id: uuid.UUID, case_id: uuid.UUID) -> list[str]:
    """The shared checker every `resolved` writer consults.

    Loads the tenant policy, the case facts, the WS7.1 root-cause status and
    the derived entity count, and hands them to :func:`compute_gaps`. No
    policy row means no enforcement (opt-in); a policy read that *fails*
    propagates — refusing on an unreadable policy is the caller's job, and
    waving the transition through is the one wrong answer.
    """
    policy = await fetch_policy(db, tenant_id)
    if policy is None or not policy.enforce:
        return []
    facts = await fetch_facts(db, tenant_id, case_id)
    root_cause_status = await fetch_root_cause_status(db, tenant_id, case_id)
    entity_count = await count_affected_entities(db, tenant_id, case_id) if policy.require_entities else 0
    return compute_gaps(policy, facts, root_cause_status=root_cause_status, entity_count=entity_count)


def build_resolution_summary(
    *,
    case_title: str,
    facts: ResolutionFactsIn | None,
    root_cause: dict[str, Any] | None,
) -> str:
    """The customer-facing summary, from persisted rows only.

    Renders what is recorded and says plainly what is not — never invents a
    step, and labels a hypothesis as a hypothesis (the WS7.1 rule carried
    into prose).
    """
    lines: list[str] = [f"# Resolution summary — {case_title}", ""]

    if root_cause is None:
        lines.append("**Root cause:** no root-cause record exists for this case.")
    else:
        status = root_cause.get("status")
        if status == "hypothesis":
            lines.append("**Root cause (hypothesis — unverified):** " + str(root_cause.get("summary", "")))
        elif status == "undetermined":
            lines.append("**Root cause:** undetermined. " + str(root_cause.get("summary", "")))
            missing = root_cause.get("missing_telemetry")
            if missing:
                lines.append(f"**Missing telemetry:** {missing}")
        else:
            lines.append("**Root cause (determined):** " + str(root_cause.get("summary", "")))
            for citation in root_cause.get("citations") or []:
                lines.append(f"- cited: {citation.get('description', '')} (ledger {citation.get('run_id', '')}#{citation.get('seq', '')})")

    lines.append("")
    if facts is None:
        lines.append("**Containment / eradication / recovery:** not recorded.")
    else:
        if facts.containment_state == "verified":
            lines.append(f"**Containment:** verified — {facts.containment_reference}")
        elif facts.containment_state == "not_required":
            lines.append(f"**Containment:** not required — {facts.containment_reason}")
        else:
            lines.append("**Containment:** not recorded.")
        lines.append(f"**Eradication:** {facts.eradication or 'not recorded.'}")
        lines.append(f"**Recovery:** {facts.recovery or 'not recorded.'}")
        if facts.customer_notified_channel and facts.customer_notified_at:
            lines.append(f"**Customer notified:** {facts.customer_notified_channel} at {facts.customer_notified_at.isoformat()}")
        else:
            lines.append("**Customer notified:** not recorded.")

    return "\n".join(lines)
