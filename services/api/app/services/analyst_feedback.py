"""Analyst disagreement as structured data, compiled into organisation memory.

When an analyst overturns a verdict, the platform records the new
disposition and discards the only part that generalises: *why*. Free-text
notes do not generalise either — nobody queries them, and the next identical
alert is triaged with no knowledge that this one was overturned.

The useful unit is the reason, and there are not many of them. An analyst
saying "benign, known admin tool" and an analyst saying "benign, approved
penetration test" are teaching the platform two different things: the first
is permanent and about a binary, the second is temporary and about a window.
A free-text field flattens them into the same nothing.

So the taxonomy is closed and small, and each code carries its own scope and
lifetime. From a handful of tagged disagreements the platform compiles a
durable statement — "PowerShell launched by svc_backup on BACKUP01 is
expected during the 02:00 backup window" — which is organisation memory
rather than a fine-tune, and which an analyst can read, argue with and
delete.

Two things this deliberately does not do:

**It does not auto-suppress on one disagreement.** One analyst calling one
alert benign is an opinion; the same reason recurring is a pattern. The
corroboration threshold lives here rather than in the consumer so it cannot
be quietly lowered per caller.

**It does not let a reason code outlive its scope.** An approved penetration
test is true for a week. Baking it in permanently is how a SOC ends up with
a suppression nobody can explain and nobody dares remove.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("aisoc.analyst_feedback")


@dataclass(frozen=True)
class ReasonCode:
    """One way an analyst can disagree, and what it implies.

    ``generalises`` is the load-bearing field. "Bad detection logic" says
    something about the *rule* and should reach whoever owns it; "expected
    service account" says something about one principal on one host. Treating
    them alike either over-suppresses or wastes the signal.
    """

    code: str
    label: str
    description: str
    #: What the statement should be scoped to when compiled.
    scope: str  # rule | entity | binary | tenant
    #: Days before the derived memory expires. None means it does not.
    ttl_days: int | None
    #: How many independent analysts must say this before it is trusted.
    corroboration: int
    #: Whether this should open detection-engineering work rather than a
    #: suppression. A noisy rule is not fixed by remembering it is noisy.
    routes_to_detection_engineering: bool = False


REASON_CODES: dict[str, ReasonCode] = {
    "known_admin_tool": ReasonCode(
        code="known_admin_tool",
        label="Known administrative tool",
        description="Legitimate admin tooling that resembles attacker tooling.",
        scope="binary",
        ttl_days=None,
        corroboration=2,
    ),
    "approved_pentest": ReasonCode(
        code="approved_pentest",
        label="Approved penetration test",
        description="Authorised offensive testing during an agreed window.",
        scope="tenant",
        # Deliberately short. A pentest exclusion that outlives the pentest
        # is an attacker's best friend, and nobody remembers to remove it.
        ttl_days=14,
        corroboration=1,
    ),
    "expected_service_account": ReasonCode(
        code="expected_service_account",
        label="Expected service-account behaviour",
        description="A service account doing what it is provisioned to do.",
        scope="entity",
        ttl_days=180,
        corroboration=2,
    ),
    "known_scanner": ReasonCode(
        code="known_scanner",
        label="Known vulnerability scanner",
        description="Authorised scanning infrastructure.",
        scope="entity",
        ttl_days=365,
        corroboration=1,
    ),
    "business_application": ReasonCode(
        code="business_application",
        label="Sanctioned business application",
        description="A sanctioned application whose behaviour resembles a threat.",
        scope="binary",
        ttl_days=365,
        corroboration=2,
    ),
    "bad_detection_logic": ReasonCode(
        code="bad_detection_logic",
        label="Bad detection logic",
        description="The rule is wrong, not the environment.",
        scope="rule",
        ttl_days=None,
        corroboration=2,
        # Suppressing a broken rule's output hides the defect and keeps
        # paying its cost on every future alert. Fix the rule.
        routes_to_detection_engineering=True,
    ),
    "missing_context": ReasonCode(
        code="missing_context",
        label="Missing context",
        description=("The verdict was reasonable given what the platform could see, and wrong given what the analyst could see."),
        scope="rule",
        ttl_days=None,
        corroboration=1,
        # The fix is a connector or a graph edge, not a suppression. This is
        # the most valuable code in the taxonomy and the easiest to waste.
        routes_to_detection_engineering=True,
    ),
    "true_positive_confirmed": ReasonCode(
        code="true_positive_confirmed",
        label="Confirmed true positive",
        description="The analyst agrees, or escalates a verdict the platform under-called.",
        scope="rule",
        ttl_days=None,
        corroboration=1,
    ),
}


@dataclass
class ContextStatement:
    """A durable, human-readable fact compiled from repeated disagreement.

    Readable on purpose. A suppression nobody can explain is one nobody dares
    remove, and it accumulates.
    """

    tenant_id: str
    statement: str
    reason_code: str
    scope: str
    scope_value: str
    observations: int
    expires_at: datetime | None
    routes_to_detection_engineering: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "statement": self.statement,
            "reason_code": self.reason_code,
            "scope": self.scope,
            "scope_value": self.scope_value,
            "observations": self.observations,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "routes_to_detection_engineering": self.routes_to_detection_engineering,
        }


def _scope_value(reason: ReasonCode, context: dict[str, Any]) -> str:
    """The thing a statement is about, per its scope."""
    if reason.scope == "rule":
        return str(context.get("rule_id") or context.get("rule_name") or "")
    if reason.scope == "binary":
        return str(context.get("process_name") or context.get("hash_sha256") or "")
    if reason.scope == "entity":
        return str(context.get("user_name") or context.get("hostname") or "")
    return "tenant"


def compose_statement(reason: ReasonCode, context: dict[str, Any]) -> str:
    """Render the durable sentence an analyst will read six months from now.

    Specific by construction. "PowerShell is expected" is a suppression
    waiting to hide an incident; "PowerShell launched by svc_backup on
    BACKUP01 is expected during the 02:00 backup window" is a fact.
    """
    process = context.get("process_name")
    user = context.get("user_name")
    host = context.get("hostname")
    window = context.get("time_window")
    rule = context.get("rule_name") or context.get("rule_id")

    subject_parts = []
    if process:
        subject_parts.append(str(process))
    if user:
        subject_parts.append(f"launched by {user}")
    if host:
        subject_parts.append(f"on {host}")
    subject = " ".join(subject_parts) or (f"alerts from rule {rule}" if rule else "this activity")

    if reason.code == "known_admin_tool":
        body = f"{subject} is sanctioned administrative tooling."
    elif reason.code == "approved_pentest":
        body = f"{subject} is authorised penetration testing."
    elif reason.code == "expected_service_account":
        body = f"{subject} is expected service-account behaviour"
        body += f" during the {window} window." if window else "."
    elif reason.code == "known_scanner":
        body = f"{subject} originates from authorised scanning infrastructure."
    elif reason.code == "business_application":
        body = f"{subject} belongs to a sanctioned business application."
    elif reason.code == "bad_detection_logic":
        body = (
            f"Rule {rule or 'unknown'} produces false positives on this pattern; the rule needs fixing rather than its output suppressing."
        )
    elif reason.code == "missing_context":
        body = (
            f"Verdicts on {subject} are wrong because the platform cannot see "
            f"the context an analyst can; a connector or graph edge is missing."
        )
    else:
        body = f"{subject} was confirmed as a genuine detection."

    return body


async def record_disagreement(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID | str,
    alert_id: uuid.UUID | str,
    ai_disposition: str,
    analyst_disposition: str,
    reason_code: str,
    analyst_id: str,
    context: dict[str, Any] | None = None,
    note: str = "",
) -> ContextStatement | None:
    """Record one disagreement; return a statement once it is corroborated.

    Returns ``None`` while the reason has not yet been seen enough times by
    enough distinct analysts. One analyst calling one alert benign is an
    opinion; the same reason recurring is a pattern, and the threshold lives
    here so a caller cannot quietly lower it.
    """
    reason = REASON_CODES.get(reason_code)
    if reason is None:
        raise ValueError(f"unknown reason code {reason_code!r}; must be one of {sorted(REASON_CODES)}")

    context = context or {}
    scope_value = _scope_value(reason, context)
    tid = str(tenant_id)

    await db.execute(
        text(
            "INSERT INTO aisoc_analyst_feedback "
            "(tenant_id, alert_id, ai_disposition, analyst_disposition, reason_code, "
            " scope, scope_value, analyst_id, note, context) "
            "VALUES (:tenant_id, :alert_id, :ai, :analyst, :reason, :scope, :scope_value, "
            "        :analyst_id, :note, CAST(:context AS JSONB))"
        ),
        {
            "tenant_id": tid,
            "alert_id": str(alert_id),
            "ai": ai_disposition,
            "analyst": analyst_disposition,
            "reason": reason.code,
            "scope": reason.scope,
            "scope_value": scope_value,
            "analyst_id": analyst_id,
            # Kept for a human reading the trail, never parsed. Free text is
            # why this data was useless before.
            "note": note[:2000],
            "context": _json(context),
        },
    )

    # Distinct analysts, not distinct rows: one person clicking the same
    # button ten times is still one opinion.
    corroborating = (
        await db.execute(
            text(
                "SELECT count(DISTINCT analyst_id) FROM aisoc_analyst_feedback "
                "WHERE tenant_id = :tenant_id AND reason_code = :reason "
                "  AND scope = :scope AND scope_value = :scope_value"
            ),
            {
                "tenant_id": tid,
                "reason": reason.code,
                "scope": reason.scope,
                "scope_value": scope_value,
            },
        )
    ).scalar_one()

    observations = int(corroborating)
    if observations < reason.corroboration:
        logger.info(
            "analyst_feedback.recorded tenant=%s reason=%s observations=%d/%d (not yet trusted)",
            tid,
            reason.code,
            observations,
            reason.corroboration,
        )
        return None

    expires_at = datetime.now(UTC) + timedelta(days=reason.ttl_days) if reason.ttl_days else None
    statement = ContextStatement(
        tenant_id=tid,
        statement=compose_statement(reason, context),
        reason_code=reason.code,
        scope=reason.scope,
        scope_value=scope_value,
        observations=observations,
        expires_at=expires_at,
        routes_to_detection_engineering=reason.routes_to_detection_engineering,
    )

    await db.execute(
        text(
            "INSERT INTO aisoc_context_statements "
            "(tenant_id, statement, reason_code, scope, scope_value, observations, expires_at) "
            "VALUES (:tenant_id, :statement, :reason, :scope, :scope_value, :observations, "
            "        :expires_at) "
            "ON CONFLICT (tenant_id, reason_code, scope, scope_value) DO UPDATE SET "
            "  statement = EXCLUDED.statement, "
            "  observations = EXCLUDED.observations, "
            "  expires_at = EXCLUDED.expires_at, "
            "  updated_at = now()"
        ),
        {
            "tenant_id": tid,
            "statement": statement.statement,
            "reason": reason.code,
            "scope": reason.scope,
            "scope_value": scope_value,
            "observations": observations,
            "expires_at": expires_at,
        },
    )
    logger.info(
        "analyst_feedback.statement tenant=%s reason=%s scope=%s:%s observations=%d",
        tid,
        reason.code,
        reason.scope,
        scope_value,
        observations,
    )
    return statement


async def active_statements(db: AsyncSession, tenant_id: uuid.UUID | str) -> list[dict[str, Any]]:
    """Unexpired organisation memory for a tenant, for the triage prompt.

    Expiry is applied in the query rather than by a cleanup job: a statement
    that should have expired must stop influencing verdicts at the moment it
    expires, not whenever a worker next runs.
    """
    rows = await db.execute(
        text(
            "SELECT statement, reason_code, scope, scope_value, observations, expires_at "
            "FROM aisoc_context_statements "
            "WHERE tenant_id = :tenant_id "
            "  AND (expires_at IS NULL OR expires_at > now()) "
            "ORDER BY observations DESC, updated_at DESC "
            "LIMIT 200"
        ),
        {"tenant_id": str(tenant_id)},
    )
    return [dict(row) for row in rows.mappings()]


def _json(value: Any) -> str:
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return "{}"
