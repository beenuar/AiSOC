"""Analyst override feedback + retroactive re-disposition — Tier 1.5.

Pipeline
--------
1. ``POST /feedback/alert-override`` — analyst corrects an AI verdict.
   * Persists the corrected ``disposition`` on the alert.
   * Records the lesson in ``aisoc_institutional_memory`` (so future
     investigations of similar alerts pull this up).
   * Returns *retroactive candidates* — past alerts in the same tenant
     that share the alert's signature and would now be re-dispositioned.
2. ``POST /feedback/redisposition/apply`` — analyst opts in (or auto-
   applies via UI) to update the disposition on a chosen subset of
   those candidates.
3. ``GET  /feedback/overrides`` — lists every override the agent has
   "learned" for this tenant.
4. ``GET  /feedback/summary`` — counts of dispositions for the FPR card.
5. ``GET  /feedback/context-statements`` — the organisation memory compiled
   from tagged disagreements, which the triage prompt reads.

Organisation memory (``app/services/analyst_feedback.py``)
----------------------------------------------------------
``reason`` on an override is free text, and the module next door exists
because free text does not generalise: nobody queries it, and the next
identical alert is triaged knowing nothing about the last one being
overturned. That module compiles a **closed** reason vocabulary into durable,
readable statements — "PowerShell launched by svc_backup on BACKUP01 is
expected during the 02:00 backup window".

It had no callers. Not one: ``record_disagreement`` was never invoked, so the
table stayed empty, and ``active_statements`` was never read, so an empty
table was never noticed. Both ends are wired here — the optional
``reason_code`` on an override writes, and ``/context-statements`` reads —
because wiring only the read would have been a query against a table nothing
populates, which is the same defect wearing a different hat.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select, update

from app.api.v1.deps import AuthUser, CurrentUser, DBSession
from app.api.v1.endpoints.alert_writeback import optional_user, service_token_valid
from app.models.alert import Alert
from app.services.analyst_feedback import (
    REASON_CODES,
    active_statements,
    record_disagreement,
)
from app.services.memory_poisoning import plan_redisposition
from app.services.override_learning import (
    apply_redisposition,
    find_redisposition_candidates,
    list_overrides,
    record_override,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/feedback", tags=["feedback"])

# ``benign_true_positive`` (#526): a valid detection of authorized/expected
# activity. Kept distinct from ``false_positive`` so BTP never inflates a rule's
# false-positive rate. Existing ``benign`` records stay valid (no migration).
_VALID_VERDICTS = {
    "true_positive",
    "benign_true_positive",
    "false_positive",
    "benign",
    "escalate",
}


def _statement_context(alert: Alert) -> dict[str, Any]:
    """The facts a compiled statement is allowed to name.

    Scoping is the whole point of the taxonomy: a `binary`-scoped reason keys
    on the process, an `entity`-scoped one on the principal or host, a
    `rule`-scoped one on the rule. Handing over a thin context produces
    "PowerShell is expected", which is a suppression waiting to hide an
    incident rather than a fact.

    The alert row denormalises host and user into `affected_hosts` /
    `affected_users` lists and carries process and hash only inside
    `raw_event`, so both are read here rather than assumed to be columns.
    """
    raw = alert.raw_event if isinstance(alert.raw_event, dict) else {}

    def _from_raw(*keys: str) -> str | None:
        for key in keys:
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()[:256]
        return None

    def _first(values: object) -> str | None:
        if isinstance(values, list):
            for value in values:
                if isinstance(value, str) and value.strip():
                    return value.strip()[:256]
        return None

    return {
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "hostname": _first(alert.affected_hosts) or _from_raw("hostname", "host"),
        "user_name": _first(alert.affected_users) or _from_raw("username", "user"),
        "process_name": _from_raw("process_name", "process", "image", "exe"),
        "hash_sha256": _from_raw("sha256", "file_hash"),
    }


def _coerce_uuid(value: str, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{field} must be a valid UUID",
        ) from exc


class AlertOverrideRequest(BaseModel):
    alert_id: str
    original_verdict: str = Field(..., description="The AI-generated verdict being overridden")
    corrected_verdict: str = Field(
        ...,
        description="Analyst's verdict: true_positive | benign_true_positive | false_positive | benign | escalate",
    )
    reason: str | None = Field(None, description="Optional free-text justification")
    reason_code: str | None = Field(
        None,
        description=(
            "Optional code from the closed disagreement vocabulary "
            "(known_admin_tool, approved_pentest, expected_service_account, "
            "known_scanner, business_application, bad_detection_logic, "
            "missing_context, true_positive_confirmed). Supplying one lets the "
            "platform compile durable organisation memory from repeated "
            "disagreement; free text alone cannot generalise."
        ),
    )


class RedispositionCandidateModel(BaseModel):
    alert_id: str
    title: str
    severity: str
    current_disposition: str | None
    proposed_disposition: str
    event_time: str


class AlertOverrideResponse(BaseModel):
    alert_id: str
    corrected_verdict: str
    recorded_at: str
    memory_key: str | None = None
    redisposition_candidates: list[RedispositionCandidateModel] = Field(default_factory=list)
    # Blast-radius controls for retroactive apply (Phase 1.2). The client must
    # echo confirmation_token back to /redisposition/apply; quarantined means a
    # poisoning flag or over-cap match requires human clearance before apply.
    redisposition_confirmation_token: str | None = None
    redisposition_capped: bool = False
    redisposition_quarantined: bool = False
    redisposition_total_matched: int = 0
    #: The organisation-memory statement this disagreement completed, if it
    #: crossed the corroboration threshold. ``None`` means recorded but not yet
    #: trusted — one analyst calling one alert benign is an opinion.
    context_statement: str | None = None


@router.post("/alert-override", response_model=AlertOverrideResponse)
async def submit_alert_override(
    payload: AlertOverrideRequest,
    user: AuthUser,
    db: DBSession,
) -> AlertOverrideResponse:
    """Record an analyst verdict correction on an alert and surface
    retroactive re-disposition candidates."""
    if payload.corrected_verdict not in _VALID_VERDICTS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"corrected_verdict must be one of: {', '.join(sorted(_VALID_VERDICTS))}",
        )
    if payload.reason_code is not None and payload.reason_code not in REASON_CODES:
        # Refused rather than silently ignored: an analyst who mistypes a code
        # would otherwise believe they had taught the platform something.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"reason_code must be one of: {', '.join(sorted(REASON_CODES))}",
        )
    alert_uuid = _coerce_uuid(payload.alert_id, "alert_id")

    alert = await db.scalar(
        select(Alert).where(
            Alert.id == alert_uuid,
            Alert.tenant_id == user.tenant_id,
        )
    )
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    now = datetime.now(UTC)
    await db.execute(
        update(Alert)
        .where(Alert.id == alert_uuid, Alert.tenant_id == user.tenant_id)
        .values(disposition=payload.corrected_verdict, updated_at=now)
    )
    await db.commit()

    # Persist into institutional memory.
    signature = await record_override(
        db,
        tenant_id=user.tenant_id,
        alert=alert,
        original_verdict=payload.original_verdict,
        corrected_verdict=payload.corrected_verdict,
        analyst_id=user.user_id,
        reason=payload.reason,
    )

    # Find similar past alerts that would now disposition differently.
    candidates: list[RedispositionCandidateModel] = []
    memory_key: str | None = None
    plan = None
    if signature is not None:
        memory_key = signature.memory_key()
        raw_candidates = await find_redisposition_candidates(
            db,
            tenant_id=user.tenant_id,
            signature=signature,
            corrected_verdict=payload.corrected_verdict,
            exclude_alert_id=alert_uuid,
        )
        candidates = [RedispositionCandidateModel(**c.to_dict()) for c in raw_candidates]
        plan = plan_redisposition(
            [c.alert_id for c in raw_candidates],
            payload.corrected_verdict,
        )

    # Structured disagreement, when the analyst tagged one. Fails soft: the
    # override itself is already committed above and is the operator-visible
    # outcome, so a memory-compilation problem must not turn a successful
    # correction into a 500.
    statement_text: str | None = None
    if payload.reason_code:
        try:
            statement = await record_disagreement(
                db,
                tenant_id=user.tenant_id,
                alert_id=alert_uuid,
                ai_disposition=payload.original_verdict,
                analyst_disposition=payload.corrected_verdict,
                reason_code=payload.reason_code,
                analyst_id=str(user.user_id),
                context=_statement_context(alert),
                note=payload.reason or "",
            )
            await db.commit()
            statement_text = statement.statement if statement else None
        except Exception as exc:  # noqa: BLE001 — never fail a recorded override
            await db.rollback()
            logger.warning(
                "analyst.disagreement_not_recorded",
                tenant_id=str(user.tenant_id),
                reason_code=payload.reason_code,
                error=str(exc),
            )

    logger.info(
        "analyst.override",
        tenant_id=str(user.tenant_id),
        alert_id=payload.alert_id,
        analyst_id=str(user.user_id),
        original_verdict=payload.original_verdict,
        corrected_verdict=payload.corrected_verdict,
        reason=payload.reason,
        memory_key=memory_key,
        candidate_count=len(candidates),
        recorded_at=now.isoformat(),
    )

    return AlertOverrideResponse(
        alert_id=payload.alert_id,
        corrected_verdict=payload.corrected_verdict,
        recorded_at=now.isoformat(),
        memory_key=memory_key,
        redisposition_candidates=candidates,
        redisposition_confirmation_token=plan.confirmation_token if plan else None,
        redisposition_capped=plan.capped if plan else False,
        redisposition_quarantined=plan.quarantined if plan else False,
        redisposition_total_matched=plan.total_matched if plan else 0,
        context_statement=statement_text,
    )


class RedispositionApplyRequest(BaseModel):
    alert_ids: list[str]
    new_disposition: str
    confirmation_token: str = Field(
        ...,
        description="Token from the /alert-override preview over this exact alert set (Phase 1.2 blast-radius control)",
    )


class RedispositionApplyResponse(BaseModel):
    updated: int
    new_disposition: str


@router.post("/redisposition/apply", response_model=RedispositionApplyResponse)
async def apply_redisposition_endpoint(
    payload: RedispositionApplyRequest,
    user: AuthUser,
    db: DBSession,
) -> RedispositionApplyResponse:
    """Bulk-update the disposition on past alerts the analyst confirmed.

    Requires the confirmation token from the preview; a stale/tampered set or a
    batch over the cap is rejected rather than silently flipping history.
    """
    if payload.new_disposition not in _VALID_VERDICTS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"new_disposition must be one of: {', '.join(sorted(_VALID_VERDICTS))}",
        )
    if not payload.alert_ids:
        return RedispositionApplyResponse(updated=0, new_disposition=payload.new_disposition)

    ids = [_coerce_uuid(aid, "alert_ids") for aid in payload.alert_ids]
    try:
        rowcount = await apply_redisposition(
            db,
            tenant_id=user.tenant_id,
            alert_ids=ids,
            new_disposition=payload.new_disposition,
            analyst_id=user.user_id,
            confirmation_token=payload.confirmation_token,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return RedispositionApplyResponse(updated=rowcount, new_disposition=payload.new_disposition)


class OverrideEntryModel(BaseModel):
    key: str
    tags: list[str]
    reason: str | None
    created_at: str | None
    value: dict


@router.get("/overrides", response_model=list[OverrideEntryModel])
async def list_overrides_endpoint(
    user: AuthUser,
    db: DBSession,
    limit: int = 100,
) -> list[OverrideEntryModel]:
    """List analyst-override entries the agent has 'learned' from."""
    rows = await list_overrides(db, tenant_id=user.tenant_id, limit=limit)
    return [OverrideEntryModel(**r) for r in rows]


class OverrideSummaryResponse(BaseModel):
    total_overrides: int
    false_positive_corrections: int
    true_positive_corrections: int
    # Counted separately from false_positive so a valid detection of authorized
    # activity never inflates the false-positive rate on the FPR card (#526).
    benign_true_positive_corrections: int = 0
    benign_corrections: int
    escalate_corrections: int


@router.get("/summary", response_model=OverrideSummaryResponse)
async def get_override_summary(
    user: AuthUser,
    db: DBSession,
) -> OverrideSummaryResponse:
    """Return a summary of analyst overrides for this tenant."""
    counts: dict[str, int] = {
        "true_positive": 0,
        "benign_true_positive": 0,
        "false_positive": 0,
        "benign": 0,
        "escalate": 0,
    }
    rows = await db.execute(
        select(Alert.disposition, func.count())
        .where(
            and_(
                Alert.tenant_id == user.tenant_id,
                Alert.disposition.isnot(None),
            )
        )
        .group_by(Alert.disposition)
    )
    total = 0
    for disp, cnt in rows.all():
        if disp in counts:
            counts[disp] = int(cnt or 0)
        total += int(cnt or 0)

    return OverrideSummaryResponse(
        total_overrides=total,
        false_positive_corrections=counts["false_positive"],
        true_positive_corrections=counts["true_positive"],
        benign_true_positive_corrections=counts["benign_true_positive"],
        benign_corrections=counts["benign"],
        escalate_corrections=counts["escalate"],
    )


class ContextStatementModel(BaseModel):
    statement: str
    reason_code: str
    scope: str
    scope_value: str
    observations: int
    expires_at: str | None = None


class ContextStatementsResponse(BaseModel):
    tenant_id: str
    statements: list[ContextStatementModel]


@router.get("/context-statements", response_model=ContextStatementsResponse)
async def get_context_statements(
    user: Annotated[CurrentUser | None, Depends(optional_user)],
    db: DBSession,
    tenant_id: uuid.UUID | None = None,
    x_aisoc_service_token: Annotated[str | None, Header()] = None,
) -> ContextStatementsResponse:
    """Unexpired organisation memory for a tenant.

    Dual-mode for the same reason ``/alerts/{id}/source-writeback`` is: the
    consumer is the agents service's triage worker, which has no session, and
    the API owns the tenant-scoped database session. A session caller's tenant
    comes from the session and the ``tenant_id`` parameter is ignored — taking
    the client's copy would let any authenticated user read another tenant's
    memory.
    """
    if user is not None:
        scoped = user.tenant_id
    elif service_token_valid(x_aisoc_service_token):
        if tenant_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="a service caller must name the tenant it is acting for",
            )
        scoped = tenant_id
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="a session or a valid service token is required",
        )

    rows = await active_statements(db, scoped)
    return ContextStatementsResponse(
        tenant_id=str(scoped),
        statements=[
            ContextStatementModel(
                statement=str(r["statement"]),
                reason_code=str(r["reason_code"]),
                scope=str(r["scope"]),
                scope_value=str(r["scope_value"] or ""),
                observations=int(r["observations"] or 0),
                expires_at=r["expires_at"].isoformat() if r.get("expires_at") else None,
            )
            for r in rows
        ],
    )
