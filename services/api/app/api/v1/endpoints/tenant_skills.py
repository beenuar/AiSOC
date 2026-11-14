"""Author, backtest and activate a tenant's own investigation skills.

Gap-closure Phase 6.1 and 6.2.

Seven routes. Six are the console's: list, read, validate, save, backtest,
activate, retire and delete. The seventh is internal and is how the agents
service reads the active set on the path of an investigation.

The tenant never appears in a request
--------------------------------------
Every console route takes ``user.tenant_id`` from the authenticated
principal. The skill id is the author's own slug and is scoped to that tenant
by the query, so naming another tenant's skill is a 404 rather than a read.
The internal route names a tenant explicitly for the same reason
``/mcp-servers/resolved`` does: a service token carries no tenant of its own,
so there is nothing to intersect it with.

Why the internal route accepts a service token and not a session
-----------------------------------------------------------------
Unlike ``/mcp-servers/resolved`` this one returns no credential, so the
narrow reason that route gives for refusing a session does not apply. It is
still service-token only, on a simpler ground: it exists for one caller, and a
route with one caller should accept one kind of credential. The console reads
the same rows through ``GET /tenant-skills``, which returns more, not less.

What the backtest route does, and does not, build
--------------------------------------------------
It starts **two Phase 1 replay evaluations** and records their ids against
the skill version. It contains no replay, no scoring and no report rendering:
all three are ``services/api/app/services/replay_evaluation`` and
``packages/aisoc-benchmark``, unchanged. The baseline run carries the tenant's
currently active skills; the candidate run carries those plus this one. Same
connector, same window, same seed, same resample count, so the only difference
between the two reports is the skill.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession
from app.api.v1.endpoints.alert_writeback import service_token_valid
from app.db.database import AsyncSessionLocal
from app.db.rls import TenantDBSession, set_rls_context
from app.models.connector import Connector
from app.models.tenant_skill import TenantSkill as TenantSkillRow
from app.models.tenant_skill import TenantSkillVersion
from app.services.replay_evaluation import store as replay_store
from app.services.replay_evaluation.job import (
    BOOTSTRAP_RESAMPLES,
    BOOTSTRAP_SEED,
    ReplayRequest,
    run_evaluation,
)
from app.services.replay_evaluation.vendors import UnsupportedConnector, vendor_for
from app.services.tenant_skills import store
from app.services.tenant_skills.models import SkillParseError
from app.services.tenant_skills.tools import tool_inventory_for_tenant

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/tenant-skills", tags=["tenant-skills"])

#: Same default window as an ordinary replay evaluation, and for the same
#: reason: long enough for most queues to hold enough labelled malicious cases
#: for a headline, short enough that the estate resembles today's.
DEFAULT_WINDOW_DAYS = 90

#: A skill document is guidance, not a corpus. The parser caps every field;
#: this is the transport-level bound so an oversized body is refused before it
#: is parsed rather than after.
MAX_YAML_BYTES = 32_768


# ---------------------------------------------------------------------------
# Wire models
# ---------------------------------------------------------------------------


class SkillModel(BaseModel):
    """One skill as the console sees it."""

    skill_id: str
    version: int
    status: str
    name: str
    owner: str
    expires_at: datetime
    expired: bool
    body: dict[str, Any]
    source_yaml: str
    backtest_evaluation_id: str | None = None
    backtest_baseline_id: str | None = None
    backtest_version: int | None = None
    activated_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class AvailableTools(BaseModel):
    """What an author may name in ``expected_pivots`` on this tenant today.

    Returned with the list so the editor can offer the vocabulary rather than
    making the author discover it by being refused. ``customer_unknown`` is
    part of the contract: an editor that read an unreachable action registry
    as "this tenant has no products" would grey out tools the tenant has.
    """

    builtin: list[str] = Field(default_factory=list)
    customer: list[str] = Field(default_factory=list)
    mcp: list[str] = Field(default_factory=list)
    customer_unknown: bool = False
    customer_unknown_reason: str = ""


class SkillListResponse(BaseModel):
    skills: list[SkillModel]
    available_tools: AvailableTools


class SkillVersionModel(BaseModel):
    """One immutable version, which is what a recorded ``skill@vN`` resolves to."""

    skill_id: str
    version: int
    name: str
    owner: str
    expires_at: datetime
    body: dict[str, Any]
    source_yaml: str
    backtest_evaluation_id: str | None = None
    backtest_baseline_id: str | None = None
    authored_at: datetime | None = None
    activated_at: datetime | None = None
    retired_at: datetime | None = None


class SaveSkillRequest(BaseModel):
    source_yaml: str = Field(..., min_length=1, max_length=MAX_YAML_BYTES)


class ValidateResponse(BaseModel):
    valid: bool
    skill_id: str | None = None
    name: str | None = None
    expected_pivots: list[str] = Field(default_factory=list)
    available_tools: AvailableTools = Field(default_factory=AvailableTools)
    error: str | None = None


class SkillBacktestRequest(BaseModel):
    """Which connector and window to grade the skill over."""

    connector_id: uuid.UUID
    since: datetime | None = None
    until: datetime | None = None
    train_fraction: float = Field(default=0.7, gt=0.0, lt=1.0)
    limit: int = Field(default=1000, ge=1, le=2000)
    bootstrap_seed: int = BOOTSTRAP_SEED
    bootstrap_resamples: int = BOOTSTRAP_RESAMPLES


class SkillBacktestResponse(BaseModel):
    """The two runs the console polls, and how to read them together."""

    skill_id: str
    version: int
    baseline_evaluation_id: str
    candidate_evaluation_id: str
    note: str


class ResolvedSkillModel(BaseModel):
    skill_id: str
    version: int
    activated_at: str | None = None
    expires_at: str | None = None
    body: dict[str, Any]


class ResolvedSkillsResponse(BaseModel):
    tenant_id: str
    skills: list[ResolvedSkillModel]


def _to_model(row: TenantSkillRow, *, now: datetime) -> SkillModel:
    expires_at = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
    return SkillModel(
        skill_id=row.skill_id,
        version=int(row.version),
        status=row.status,
        name=row.name,
        owner=row.owner,
        expires_at=expires_at,
        # Computed rather than left to the client. An active-but-expired skill
        # steers nothing, and a console that shows only "active" would report
        # a skill as working while the resolver silently drops it.
        expired=expires_at <= now,
        body=dict(row.body or {}),
        source_yaml=row.source_yaml,
        backtest_evaluation_id=str(row.backtest_evaluation_id) if row.backtest_evaluation_id else None,
        backtest_baseline_id=str(row.backtest_baseline_id) if row.backtest_baseline_id else None,
        backtest_version=row.backtest_version,
        activated_at=row.activated_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _version_model(row: TenantSkillVersion) -> SkillVersionModel:
    return SkillVersionModel(
        skill_id=row.skill_id,
        version=int(row.version),
        name=row.name,
        owner=row.owner,
        expires_at=row.expires_at,
        body=dict(row.body or {}),
        source_yaml=row.source_yaml,
        backtest_evaluation_id=str(row.backtest_evaluation_id) if row.backtest_evaluation_id else None,
        backtest_baseline_id=str(row.backtest_baseline_id) if row.backtest_baseline_id else None,
        authored_at=row.authored_at,
        activated_at=row.activated_at,
        retired_at=row.retired_at,
    )


def _not_found(skill_id: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"no skill {skill_id!r} for this tenant")


# ---------------------------------------------------------------------------
# Console routes
# ---------------------------------------------------------------------------


@router.get("", response_model=SkillListResponse, summary="Every skill this tenant has authored")
async def list_tenant_skills(user: AuthUser, db: TenantDBSession) -> SkillListResponse:
    await user.require_permission_db("settings:read", db)
    rows = await store.list_skills(db, user.tenant_id)
    inventory = await tool_inventory_for_tenant(db, user.tenant_id)
    now = datetime.now(UTC)
    return SkillListResponse(
        skills=[_to_model(r, now=now) for r in rows],
        available_tools=AvailableTools(**inventory.as_dict()),
    )


@router.get("/{skill_id}", response_model=SkillModel, summary="One skill")
async def get_tenant_skill(skill_id: str, user: AuthUser, db: TenantDBSession) -> SkillModel:
    await user.require_permission_db("settings:read", db)
    try:
        row = await store.get_skill(db, user.tenant_id, skill_id)
    except store.SkillNotFound as exc:
        raise _not_found(skill_id) from exc
    return _to_model(row, now=datetime.now(UTC))


@router.get(
    "/{skill_id}/versions",
    response_model=list[SkillVersionModel],
    summary="Every version of one skill, newest first",
)
async def list_skill_versions(skill_id: str, user: AuthUser, db: TenantDBSession) -> list[SkillVersionModel]:
    """Resolve a ``skill@vN`` recorded on an investigation back to its text.

    This is the read that makes the version recorded on a verdict mean
    something. Without it the pair is a number pointing at nothing.
    """
    await user.require_permission_db("settings:read", db)
    rows = await store.list_versions(db, user.tenant_id, skill_id)
    if not rows:
        raise _not_found(skill_id)
    return [_version_model(r) for r in rows]


@router.post("/validate", response_model=ValidateResponse, summary="Parse and validate without saving")
async def validate_tenant_skill(body: SaveSkillRequest, user: AuthUser, db: TenantDBSession) -> ValidateResponse:
    """Back the editor's validate button with the same call the save makes.

    A 200 carrying ``valid: false`` rather than a 422: the editor asks this on
    every keystroke pause, and an error status on a document the author is
    still typing is a failed request in their network tab every few seconds.
    The save route returns the 422.
    """
    await user.require_permission_db("settings:read", db)
    inventory = await tool_inventory_for_tenant(db, user.tenant_id)
    try:
        skill = await store.validate_yaml(db, user.tenant_id, body.source_yaml)
    except SkillParseError as exc:
        return ValidateResponse(valid=False, error=str(exc), available_tools=inventory.as_dict())
    return ValidateResponse(
        valid=True,
        skill_id=skill.id,
        name=skill.name,
        expected_pivots=list(skill.expected_pivots),
        available_tools=AvailableTools(**inventory.as_dict()),
    )


@router.put("", response_model=SkillModel, summary="Create or update a skill from its YAML")
async def save_tenant_skill(
    body: SaveSkillRequest,
    user: AuthUser,
    db: TenantDBSession,
) -> SkillModel:
    """Save the document. A content change bumps the version and drops to draft.

    ``PUT`` with no id in the path because the id is inside the document: a
    skill's identity is the author's slug, and taking it from a path as well
    would create two authorities that can disagree.
    """
    await user.require_permission_db("settings:write", db)
    try:
        row, created = await store.save_skill(
            db,
            tenant_id=user.tenant_id,
            author_id=user.user_id,
            source_yaml=body.source_yaml,
        )
    except SkillParseError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    await db.commit()
    await db.refresh(row)
    logger.info(
        "tenant_skill.saved",
        tenant_id=str(user.tenant_id),
        skill_id=row.skill_id,
        version=int(row.version),
        created=created,
    )
    return _to_model(row, now=datetime.now(UTC))


@router.post(
    "/{skill_id}/backtest",
    response_model=SkillBacktestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Grade this skill against the tenant's own closed findings, with and without it",
)
async def backtest_tenant_skill(
    skill_id: str,
    body: SkillBacktestRequest,
    background: BackgroundTasks,
    user: AuthUser,
    db: TenantDBSession,
) -> SkillBacktestResponse:
    """Start the two Phase 1 replay runs that grade this version.

    202 for the same reason ``POST /evaluations/replay`` is: replaying a few
    hundred findings through a model twice is not a request-response
    operation. The ids come back immediately and the console polls both.

    ``connectors:write`` rather than ``settings:write``, because what this
    actually does is reach a customer's own SIEM with stored credentials,
    which is the bar every other route that does that clears.
    """
    await user.require_permission_db("connectors:write", db)

    try:
        row = await store.get_skill(db, user.tenant_id, skill_id)
    except store.SkillNotFound as exc:
        raise _not_found(skill_id) from exc

    until = body.until or datetime.now(UTC)
    since = body.since or (until - timedelta(days=DEFAULT_WINDOW_DAYS))
    if until <= since:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"until ({until.isoformat()}) must be after since ({since.isoformat()})",
        )

    connector = (
        await db.execute(
            select(Connector).where(
                Connector.id == body.connector_id,
                Connector.tenant_id == user.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if connector is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such connector for this tenant")
    try:
        vendor = vendor_for(connector.connector_type)
    except UnsupportedConnector as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    # The tenant's currently active skills are the baseline's context, so the
    # comparison answers "what does adding this one change" rather than "what
    # do skills do at all". The candidate under test is excluded from that
    # set: a skill already active would otherwise appear on both sides and
    # the delta would be zero by construction.
    active = [s for s in await store.resolve_active_skills(db, user.tenant_id) if s["skill_id"] != skill_id]
    candidate = {
        "skill_id": row.skill_id,
        "version": int(row.version),
        "activated_at": row.activated_at.isoformat() if row.activated_at else None,
        "expires_at": row.expires_at.isoformat(),
        "body": dict(row.body or {}),
    }

    common = {
        "tenant_id": user.tenant_id,
        "connector_row_id": body.connector_id,
        "connector_type": connector.connector_type,
        "vendor": vendor,
        "window_start": since,
        "window_end": until,
        "train_fraction": body.train_fraction,
        "limit": body.limit,
        "bootstrap_seed": body.bootstrap_seed,
        "bootstrap_resamples": body.bootstrap_resamples,
    }

    baseline_id = await _queue_run(
        db,
        background,
        user=user,
        common=common,
        skills=tuple(active),
        skill_under_test=None,
    )
    candidate_id = await _queue_run(
        db,
        background,
        user=user,
        common=common,
        skills=tuple(active),
        skill_under_test=candidate,
    )

    await store.attach_backtest(
        db,
        tenant_id=user.tenant_id,
        skill_id=skill_id,
        baseline_evaluation_id=baseline_id,
        candidate_evaluation_id=candidate_id,
    )
    await db.commit()

    logger.info(
        "tenant_skill.backtest_queued",
        tenant_id=str(user.tenant_id),
        skill_id=skill_id,
        version=int(row.version),
        baseline=str(baseline_id),
        candidate=str(candidate_id),
    )
    return SkillBacktestResponse(
        skill_id=skill_id,
        version=int(row.version),
        baseline_evaluation_id=str(baseline_id),
        candidate_evaluation_id=str(candidate_id),
        note=(
            "Two runs over the same window, seed and resample count. The baseline carries this "
            "tenant's other active skills; the candidate carries those plus this one. Read them "
            "side by side at GET /evaluations/replay/{id}. This skill was authored after the window "
            "closed and is applied to it on purpose, so the result measures the skill against this "
            "window and is not a forecast of its accuracy on new alerts. "
            "Compare the two reports over the alerts this skill matches, not over their headline "
            "figures: a skill selecting a handful of a few hundred findings cannot move a headline "
            "in either direction, so a headline that barely moved says nothing about the skill. "
            "Activation applies the same rule and refuses a backtest whose window holds no alert "
            "this skill matches. "
            "A skill reaches triage only when the alert takes the LLM path, so a run with no model "
            "configured for this tenant, or one started with AISOC_DETERMINISTIC=1, produces two "
            "identical reports because the skill was never applied -- which is a different fact "
            "from a skill that was applied and changed nothing."
        ),
    )


async def _queue_run(
    db: TenantDBSession,
    background: BackgroundTasks,
    *,
    user: AuthUser,
    common: dict[str, Any],
    skills: tuple[dict[str, Any], ...],
    skill_under_test: dict[str, Any] | None,
) -> uuid.UUID:
    evaluation_id = await replay_store.create_evaluation(
        db,
        tenant_id=common["tenant_id"],
        connector_id=str(common["connector_row_id"]),
        vendor=common["vendor"],
        window_start=common["window_start"],
        window_end=common["window_end"],
        train_fraction=common["train_fraction"],
        bootstrap_seed=common["bootstrap_seed"],
        bootstrap_resamples=common["bootstrap_resamples"],
        requested_by=user.user_id,
    )
    background.add_task(
        _run_detached,
        ReplayRequest(
            evaluation_id=evaluation_id,
            skills=skills,
            skill_under_test=skill_under_test,
            **common,
        ),
    )
    return evaluation_id


async def _run_detached(request: ReplayRequest) -> None:
    """Run one evaluation on its own session.

    The request's session closes when the response returns, so the background
    task opens its own. ``run_evaluation`` never raises: every failure lands
    on the row as a reason.
    """
    async with AsyncSessionLocal() as session:
        await run_evaluation(session, request)


@router.post("/{skill_id}/activate", response_model=SkillModel, summary="Put a backtested skill into service")
async def activate_tenant_skill(skill_id: str, user: AuthUser, db: TenantDBSession) -> SkillModel:
    """Activate, refusing anything that would put untested guidance in front of alerts.

    The refusals live in the store and are restated by the database
    constraint, so neither this route nor a future caller can be the only
    place the rule holds.
    """
    await user.require_permission_db("settings:write", db)
    try:
        row = await store.activate_skill(
            db,
            tenant_id=user.tenant_id,
            skill_id=skill_id,
            actor_id=user.user_id,
        )
    except store.SkillNotFound as exc:
        raise _not_found(skill_id) from exc
    except store.SkillLifecycleError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await db.commit()
    await db.refresh(row)
    return _to_model(row, now=datetime.now(UTC))


@router.post("/{skill_id}/retire", response_model=SkillModel, summary="Take a skill out of service, keeping its history")
async def retire_tenant_skill(skill_id: str, user: AuthUser, db: TenantDBSession) -> SkillModel:
    await user.require_permission_db("settings:write", db)
    try:
        row = await store.retire_skill(db, tenant_id=user.tenant_id, skill_id=skill_id)
    except store.SkillNotFound as exc:
        raise _not_found(skill_id) from exc
    await db.commit()
    await db.refresh(row)
    return _to_model(row, now=datetime.now(UTC))


@router.delete("/{skill_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None, summary="Delete a skill and its history")
async def delete_tenant_skill(skill_id: str, user: AuthUser, db: TenantDBSession) -> None:
    """For a skill created by mistake. To stop using a working one, retire it.

    Deleting removes the version history, which is what explains verdicts the
    skill already steered. The docs say so beside this route.
    """
    await user.require_permission_db("settings:write", db)
    removed = await store.delete_skill(db, tenant_id=user.tenant_id, skill_id=skill_id)
    if not removed:
        raise _not_found(skill_id)
    await db.commit()


# ---------------------------------------------------------------------------
# Internal route: the agents service, and nothing else
# ---------------------------------------------------------------------------


@router.get("/resolved/active", response_model=ResolvedSkillsResponse, include_in_schema=False)
async def resolve_tenant_skills(
    db: DBSession,
    tenant_id: uuid.UUID,
    x_aisoc_service_token: Annotated[str | None, Header()] = None,
) -> ResolvedSkillsResponse:
    """Active, unexpired skills for the agents service.

    The token is checked in band rather than through a bearer dependency, the
    same shape ``/mcp-servers/resolved`` and ``/feedback/context-statements``
    use, because the caller is a service with no session.
    ``service_token_valid`` compares in constant time and fails closed when the
    shared secret is unset, so an unconfigured deployment has this route shut.

    ``tenant_id`` is required and is the scope rather than a narrowing of one:
    a service token carries no tenant, so there is nothing to intersect it
    with, and defaulting an omitted parameter to "every tenant" would serve
    one customer's guidance into another's investigation.

    ``TenantDBSession`` cannot be used here because it resolves the tenant
    from a session this caller does not have, so the RLS context is set from
    the named tenant explicitly. The query layer filters on the same value, so
    the two agree by construction rather than by convention.
    """
    if not service_token_valid(x_aisoc_service_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="this route is reachable only by an AiSOC service holding the shared service token",
        )

    await set_rls_context(db, tenant_id)
    skills = await store.resolve_active_skills(db, tenant_id)
    logger.info("tenant_skill.resolved_for_agent", tenant_id=str(tenant_id), skills=len(skills))
    return ResolvedSkillsResponse(
        tenant_id=str(tenant_id),
        skills=[ResolvedSkillModel(**s) for s in skills],
    )
