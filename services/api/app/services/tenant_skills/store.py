"""Storage and lifecycle for tenant skills: draft, backtested, active, retired.

Gap-closure Phase 6.2.

The lifecycle is the point of this module, and the two rules that make it
worth having are both refusals.

**An edit un-backtests the skill.** Saving new text bumps the version and
drops the row back to ``draft``, discarding the attached reports. A backtest
is a statement about a specific body of text, and carrying it forward across
an edit is how a report comes to describe something nobody is running. The
cost is that an author who fixes a typo runs the backtest again; that is the
correct cost.

**Activation requires a backtest of the exact version being activated**, and
requires both halves of it, the baseline and the candidate. The plan asks for
"before and after metrics side by side", and a candidate score with no
baseline is a number rather than a comparison. The database constraint says
the same thing, so neither this module nor a later one can be the only place
the rule lives.

**Activation reads those two runs rather than only their ids.** Fix-pass 3.8.
An id and a version number say that a report was attached, not that it says
anything: two crashed runs, two queued ones, or two runs over a window holding
no alert this skill selects all satisfy the check above. So activation opens
both runs, requires that both completed, and compares them over the alerts the
skill's match block selects rather than over the whole window.
``app.services.tenant_skills.backtest`` explains why the subset is the point;
the short version is that a skill matching four alerts in two hundred cannot
move a headline either way, so the headline cannot be what activation rests
on. The gate is that the comparison exists, never that it is favourable.

What a backtest is here
-----------------------
Two Phase 1 replay evaluations over the same history window: one with the
tenant's active skills as they are, one with this skill added. Nothing in this
phase re-implements replay, scoring or reporting. ``services/api/app/services/
replay_evaluation/job.py`` runs both, and this module records which two runs
belong to which skill version.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tenant_skill import (
    ACTIVE,
    BACKTESTED,
    DRAFT,
    RETIRED,
    TenantSkillVersion,
)
from app.models.tenant_skill import (
    TenantSkill as TenantSkillRow,
)
from app.services.tenant_skills import backtest as backtest_reader
from app.services.tenant_skills.models import SkillParseError, TenantSkill, parse_skill_yaml, skill_from_body
from app.services.tenant_skills.tools import tool_inventory_for_tenant, validate_expected_pivots

logger = structlog.get_logger(__name__)

__all__ = [
    "SkillLifecycleError",
    "SkillNotFound",
    "activate_skill",
    "attach_backtest",
    "delete_skill",
    "get_skill",
    "list_skills",
    "list_versions",
    "resolve_active_skills",
    "retire_skill",
    "save_skill",
    "validate_yaml",
]


class SkillNotFound(LookupError):
    """No such skill for this tenant."""


class SkillLifecycleError(ValueError):
    """A lifecycle transition was refused. The message reaches the operator verbatim."""


async def _row(db: AsyncSession, tenant_id: uuid.UUID, skill_id: str) -> TenantSkillRow:
    row = (
        await db.execute(
            select(TenantSkillRow).where(
                TenantSkillRow.tenant_id == tenant_id,
                TenantSkillRow.skill_id == skill_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise SkillNotFound(f"no skill {skill_id!r} for this tenant")
    return row


async def list_skills(db: AsyncSession, tenant_id: uuid.UUID) -> list[TenantSkillRow]:
    return list(
        (await db.execute(select(TenantSkillRow).where(TenantSkillRow.tenant_id == tenant_id).order_by(TenantSkillRow.skill_id)))
        .scalars()
        .all()
    )


async def get_skill(db: AsyncSession, tenant_id: uuid.UUID, skill_id: str) -> TenantSkillRow:
    return await _row(db, tenant_id, skill_id)


async def list_versions(db: AsyncSession, tenant_id: uuid.UUID, skill_id: str) -> list[TenantSkillVersion]:
    """Every version of one skill, newest first.

    This is the read that turns the ``(skill_id, version)`` pair recorded on
    an investigation back into the text that was in force.
    """
    return list(
        (
            await db.execute(
                select(TenantSkillVersion)
                .where(
                    TenantSkillVersion.tenant_id == tenant_id,
                    TenantSkillVersion.skill_id == skill_id,
                )
                .order_by(TenantSkillVersion.version.desc())
            )
        )
        .scalars()
        .all()
    )


async def validate_yaml(db: AsyncSession, tenant_id: uuid.UUID, source_yaml: str) -> TenantSkill:
    """Parse and validate without writing anything.

    Backs the editor's validate button, and is the same call ``save_skill``
    makes, so what the editor says is what the save will do.
    """
    skill = parse_skill_yaml(source_yaml)
    inventory = await tool_inventory_for_tenant(db, tenant_id)
    validate_expected_pivots(skill, inventory)
    return skill


async def save_skill(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    author_id: uuid.UUID | None,
    source_yaml: str,
) -> tuple[TenantSkillRow, bool]:
    """Create or update a skill from its YAML. Returns the row and whether it is new.

    A save whose parsed body is byte-identical to the stored one is a no-op on
    the version: an author who reformats a comment has not changed what the
    agent reads, and bumping the version there would invalidate a backtest
    over nothing. Comparison is on the parsed body rather than on the YAML
    text for exactly that reason.
    """
    skill = await validate_yaml(db, tenant_id, source_yaml)
    body = skill.as_dict()
    now = datetime.now(UTC)

    try:
        row = await _row(db, tenant_id, skill.id)
    except SkillNotFound:
        row = TenantSkillRow(
            tenant_id=tenant_id,
            skill_id=skill.id,
            version=1,
            status=DRAFT,
            name=skill.name,
            owner=skill.owner,
            expires_at=skill.expires_at,
            body=body,
            source_yaml=skill.raw_yaml,
            created_by=author_id,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
        await db.flush()
        _record_version(db, row, authored_by=author_id, authored_at=now)
        logger.info("tenant_skill.created", tenant_id=str(tenant_id), skill_id=skill.id, version=1)
        return row, True

    if row.body == body:
        # Text-only change (comments, ordering, whitespace). Keep the version
        # and any attached backtest, and store the author's formatting.
        row.source_yaml = skill.raw_yaml
        row.updated_at = now
        return row, False

    row.version = int(row.version) + 1
    row.name = skill.name
    row.owner = skill.owner
    row.expires_at = skill.expires_at
    row.body = body
    row.source_yaml = skill.raw_yaml
    # The edit invalidates the backtest, so the row goes back to draft and the
    # reports are detached rather than silently carried onto new text.
    row.status = DRAFT
    row.backtest_evaluation_id = None
    row.backtest_baseline_id = None
    row.backtest_version = None
    row.activated_at = None
    row.activated_by = None
    row.updated_at = now

    _record_version(db, row, authored_by=author_id, authored_at=now)
    logger.info("tenant_skill.updated", tenant_id=str(tenant_id), skill_id=skill.id, version=row.version)
    return row, False


def _record_version(
    db: AsyncSession,
    row: TenantSkillRow,
    *,
    authored_by: uuid.UUID | None,
    authored_at: datetime,
) -> None:
    db.add(
        TenantSkillVersion(
            tenant_id=row.tenant_id,
            skill_row_id=row.id,
            skill_id=row.skill_id,
            version=row.version,
            name=row.name,
            owner=row.owner,
            expires_at=row.expires_at,
            body=dict(row.body or {}),
            source_yaml=row.source_yaml,
            authored_by=authored_by,
            authored_at=authored_at,
        )
    )


async def attach_backtest(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    skill_id: str,
    baseline_evaluation_id: uuid.UUID,
    candidate_evaluation_id: uuid.UUID,
) -> TenantSkillRow:
    """Record the two replay runs that graded the current version.

    Both ids, and they must differ. One evaluation used as its own baseline
    would produce a delta of exactly zero on every axis and read as "the skill
    changed nothing", which is a conclusion rather than an absence of one.
    """
    if baseline_evaluation_id == candidate_evaluation_id:
        raise SkillLifecycleError(
            "the baseline and candidate backtest runs are the same evaluation; a comparison needs two runs, "
            "one with this skill and one without"
        )
    row = await _row(db, tenant_id, skill_id)
    if row.status == RETIRED:
        raise SkillLifecycleError("this skill is retired; save it again to return it to draft before backtesting")

    row.backtest_baseline_id = baseline_evaluation_id
    row.backtest_evaluation_id = candidate_evaluation_id
    row.backtest_version = int(row.version)
    if row.status == DRAFT:
        row.status = BACKTESTED
    row.updated_at = datetime.now(UTC)

    await _stamp_version(
        db,
        row,
        baseline_evaluation_id=baseline_evaluation_id,
        candidate_evaluation_id=candidate_evaluation_id,
    )
    logger.info(
        "tenant_skill.backtest_attached",
        tenant_id=str(tenant_id),
        skill_id=skill_id,
        version=row.version,
    )
    return row


async def _stamp_version(
    db: AsyncSession,
    row: TenantSkillRow,
    *,
    baseline_evaluation_id: uuid.UUID | None = None,
    candidate_evaluation_id: uuid.UUID | None = None,
    activated_at: datetime | None = None,
    activated_by: uuid.UUID | None = None,
    retired_at: datetime | None = None,
) -> None:
    version_row = (
        await db.execute(
            select(TenantSkillVersion).where(
                TenantSkillVersion.tenant_id == row.tenant_id,
                TenantSkillVersion.skill_id == row.skill_id,
                TenantSkillVersion.version == row.version,
            )
        )
    ).scalar_one_or_none()
    if version_row is None:
        # Reachable only if history was purged under a live row. Say so rather
        # than carrying on: the history table is what makes a recorded version
        # resolvable, and continuing would leave a live skill with none.
        logger.warning(
            "tenant_skill.version_row_missing",
            skill_id=row.skill_id,
            version=row.version,
            hint="the recorded version will not resolve back to its text",
        )
        return
    if baseline_evaluation_id is not None:
        version_row.backtest_baseline_id = baseline_evaluation_id
    if candidate_evaluation_id is not None:
        version_row.backtest_evaluation_id = candidate_evaluation_id
    if activated_at is not None:
        version_row.activated_at = activated_at
        version_row.activated_by = activated_by
    if retired_at is not None:
        version_row.retired_at = retired_at


async def activate_skill(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    skill_id: str,
    actor_id: uuid.UUID | None,
    now: datetime | None = None,
) -> TenantSkillRow:
    """Put a backtested skill into service, refusing anything that would put untested guidance in front of alerts.

    Every refusal says which thing is wrong and what to do about it. They are
    deliberately not counted here: the count drifted the moment this function
    grew the two refusals fix-pass 3.8 added.
    """
    moment = now or datetime.now(UTC)
    row = await _row(db, tenant_id, skill_id)

    if row.backtest_evaluation_id is None or row.backtest_baseline_id is None:
        raise SkillLifecycleError(
            "this skill has no backtest attached. Run the backtest first: it replays the tenant's own "
            "closed findings with and without the skill and reports both, and activating without it "
            "puts untested guidance in front of every matching alert."
        )
    if row.backtest_version != int(row.version):
        raise SkillLifecycleError(
            f"the attached backtest graded version {row.backtest_version} and this skill is now at version "
            f"{row.version}. Re-run the backtest, or the report on the activation describes text nobody is running."
        )
    expires_at = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
    if expires_at <= moment:
        raise SkillLifecycleError(
            f"this skill expired at {expires_at.isoformat()}. Extend 'expires_at' and re-run the backtest: "
            f"the resolver drops an expired skill, so activating it would be a no-op that looks like a change."
        )
    if row.status == ACTIVE:
        raise SkillLifecycleError("this skill is already active")

    delta = await backtest_reader.matched_delta(
        db,
        tenant_id=tenant_id,
        match=backtest_reader.match_from_body(row.body or {}),
        baseline_evaluation_id=row.backtest_baseline_id,
        candidate_evaluation_id=row.backtest_evaluation_id,
    )
    if delta.blocked_reason is not None:
        raise SkillLifecycleError(delta.blocked_reason)

    row.status = ACTIVE
    row.activated_at = moment
    row.activated_by = actor_id
    row.updated_at = moment
    await _stamp_version(db, row, activated_at=moment, activated_by=actor_id)
    logger.info(
        "tenant_skill.activated",
        tenant_id=str(tenant_id),
        skill_id=skill_id,
        version=row.version,
        backtest_evaluation_id=str(row.backtest_evaluation_id),
        **delta.as_log_fields(),
    )
    return row


async def retire_skill(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    skill_id: str,
    now: datetime | None = None,
) -> TenantSkillRow:
    """Take a skill out of service, keeping its history."""
    moment = now or datetime.now(UTC)
    row = await _row(db, tenant_id, skill_id)
    row.status = RETIRED
    row.updated_at = moment
    await _stamp_version(db, row, retired_at=moment)
    logger.info("tenant_skill.retired", tenant_id=str(tenant_id), skill_id=skill_id, version=row.version)
    return row


async def delete_skill(db: AsyncSession, *, tenant_id: uuid.UUID, skill_id: str) -> bool:
    """Remove a skill and, by cascade, its version history.

    Offered because an operator who created a skill by mistake should not have
    to keep it forever. An operator taking a *working* skill out of service
    wants :func:`retire_skill`, which keeps the history that explains verdicts
    the skill already steered.
    """
    try:
        row = await _row(db, tenant_id, skill_id)
    except SkillNotFound:
        return False
    await db.delete(row)
    return True


async def resolve_active_skills(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Active, unexpired skills for the agents service, newest activation first.

    Expiry is applied **in the query**, the same choice
    ``analyst_feedback.active_statements`` makes: a skill stops steering the
    moment it expires rather than whenever a worker next restarts. A skill
    dropped for expiry is logged, because the operator-visible symptom is an
    agent that quietly stopped following their guidance.
    """
    moment = now or datetime.now(UTC)
    rows = list(
        (
            await db.execute(
                select(TenantSkillRow)
                .where(
                    TenantSkillRow.tenant_id == tenant_id,
                    TenantSkillRow.status == ACTIVE,
                )
                .order_by(TenantSkillRow.skill_id)
            )
        )
        .scalars()
        .all()
    )

    resolved: list[dict[str, Any]] = []
    expired: list[str] = []
    for row in rows:
        expires_at = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
        if expires_at <= moment:
            expired.append(row.skill_id)
            continue
        resolved.append(
            {
                "skill_id": row.skill_id,
                "version": int(row.version),
                "activated_at": row.activated_at.isoformat() if row.activated_at else None,
                "expires_at": expires_at.isoformat(),
                "body": dict(row.body or {}),
            }
        )

    if expired:
        logger.info(
            "tenant_skill.expired_not_served",
            tenant_id=str(tenant_id),
            skills=sorted(expired),
            hint="these skills are active but past their expiry, so they no longer steer investigations",
        )
    return resolved


def body_to_skill(body: dict[str, Any]) -> TenantSkill:
    """Rebuild a parsed skill from a stored body, for callers that want the dataclass."""
    try:
        return skill_from_body(body)
    except SkillParseError:  # pragma: no cover - a stored body was written by the parser
        raise
