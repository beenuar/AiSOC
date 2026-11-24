"""The co-managed responsibility matrix: who owns which act.

A co-managed SOC splits work between the managing provider and the
customer's own team. The platform could not even SAY that — every analyst
with a role's permissions could act wherever the role reached. This module
is the saying and the enforcing, under one rule that keeps it safe:

**A matrix row can only narrow.** The check runs AFTER the ordinary
permission check and can refuse an act the role would have allowed; it can
never grant one the role refused. A tenant with no rows gets exactly the
behaviour they had before the table existed — which is also why an
unreadable matrix refuses nothing rather than everything: the matrix is a
narrowing overlay, and "overlay unavailable" must degrade to the base
authorization, not to a tenant-wide outage. (Contrast the kill switch,
where "configured but unavailable" must refuse — that control's absence is
what fails open; this one's absence is the pre-existing base.)

Party resolution
----------------
``party_for`` answers which side of the engagement a caller is on, from
the MSSP relationship the tenant tree already records
(`tenants.parent_tenant_id`):

* the caller's home tenant IS the target tenant → ``customer``;
* the caller's home tenant is the target's managing parent → ``provider``;
* anything else that legitimately reached the tenant (delegated support,
  platform operator) → ``provider``, because "not the customer's own
  team" is the conservative reading for a matrix whose point is keeping
  provider hands off customer-reserved acts.

Specificity
-----------
The most specific matching row wins: rows are scored by how many non-
wildcard dimensions they match (verb > severity > alert_class as the
tiebreak order, matching the matrix's unique key). One row saying
"actions: provider" and a sharper row saying "actions on critical:
customer" behave the way the tenant who wrote them meant.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("aisoc.responsibility")

PARTIES = ("provider", "customer", "shared")
ACTIVITIES = ("triage", "approval", "action")

_MATRIX_SQL = text(
    """
    SELECT activity, alert_class, severity, verb, owner
    FROM responsibility_matrix
    WHERE tenant_id = :tenant_id AND activity = :activity
    """
)

_PARENT_SQL = text("SELECT parent_tenant_id FROM tenants WHERE id = :tenant_id")


@dataclass(frozen=True)
class ResponsibilityDecision:
    allowed: bool
    #: The matched row, rendered for the refusal message — an analyst told
    #: "no" must be told by which rule.
    rule: str | None = None
    owner: str | None = None
    party: str | None = None

    @property
    def refusal_detail(self) -> str:
        return (
            f"the responsibility matrix assigns this to {self.owner!r} and the "
            f"caller acts as {self.party!r} (rule: {self.rule}). A matrix row "
            "narrows only; ask the tenant's administrator to adjust it under "
            "Settings → Responsibility."
        )


async def party_for(db: AsyncSession, *, caller_home_tenant: uuid.UUID, target_tenant: uuid.UUID) -> str:
    """Which side of the engagement the caller is on, from the tenant tree."""
    if caller_home_tenant == target_tenant:
        return "customer"
    parent = (await db.execute(_PARENT_SQL, {"tenant_id": str(target_tenant)})).scalar_one_or_none()
    if parent is not None and parent == caller_home_tenant:
        return "provider"
    return "provider"


def _match_score(row: tuple, *, alert_class: str, severity: str, verb: str) -> int | None:
    """Specificity score, or None when the row does not match at all."""
    _activity, r_class, r_severity, r_verb, _owner = row
    score = 0
    if r_verb != "*":
        if r_verb != verb:
            return None
        score += 4
    if r_severity != "*":
        if r_severity != severity:
            return None
        score += 2
    if r_class != "*":
        if r_class != alert_class:
            return None
        score += 1
    return score


async def check(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    activity: str,
    party: str,
    alert_class: str = "*",
    severity: str = "*",
    verb: str = "*",
) -> ResponsibilityDecision:
    """Narrow-only enforcement: refuse when the most specific matching row
    assigns the activity to the other party. No rows — or an unreadable
    matrix — means no narrowing, never a grant the base check refused."""
    if activity not in ACTIVITIES:
        raise ValueError(f"activity must be one of {ACTIVITIES}, got {activity!r}")
    try:
        rows = (await db.execute(_MATRIX_SQL, {"tenant_id": str(tenant_id), "activity": activity})).fetchall()
    except Exception as exc:  # noqa: BLE001 — the overlay degrades to the base authorization
        # Both interpolations are re-derived from trusted constants so the
        # log line provably carries no request bytes: the tenant id is
        # round-tripped through the UUID constructor (whose output cannot
        # contain control characters) and the activity is read back out of
        # the enumerating tuple itself.
        safe_tenant = uuid.UUID(str(tenant_id))
        safe_activity = ACTIVITIES[ACTIVITIES.index(activity)]
        logger.warning(
            "responsibility.matrix_unreadable tenant=%s activity=%s err=%s",
            safe_tenant,
            safe_activity,
            type(exc).__name__,
        )
        return ResponsibilityDecision(allowed=True, party=party)

    best: tuple[int, tuple] | None = None
    for row in rows:
        score = _match_score(row, alert_class=alert_class, severity=severity, verb=verb)
        if score is None:
            continue
        if best is None or score > best[0]:
            best = (score, row)

    if best is None:
        return ResponsibilityDecision(allowed=True, party=party)

    r_activity, r_class, r_severity, r_verb, owner = best[1]
    allowed = owner == "shared" or owner == party
    rule = f"{r_activity}/{r_class}/{r_severity}/{r_verb} -> {owner}"
    return ResponsibilityDecision(allowed=allowed, rule=rule, owner=owner, party=party)
