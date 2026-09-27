"""Autonomy policy admin endpoints — Tier 1 capability 1.3.

Surfaces the three-tier per-action confidence thresholds (auto / review /
escalation) the agent uses when deciding whether to execute, queue for
review, escalate, or reject a proposed action.

Threshold resolution (low → high precedence) when the agent loads a policy:

    hard-coded defaults  →  YAML site policy  →  DB tenant overrides

This module manages the **DB tenant overrides** layer. Reads return the
*effective* policy after merging defaults + DB so the admin UI can show a
single coherent view; writes only persist to the DB layer.

All endpoints are tenant-scoped and require ``settings:read`` /
``settings:write`` permissions (typically held only by the ``tenant_admin``
role — see ``services/api/app/core/security.py``).
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import text

from app._vendor.autonomy_evidence_rules import PromotionThresholds
from app.api.v1.deps import AuthUser, DBSession
from app.db.rls import TenantDBSession
from app.services.shadow_agreement import (
    SCOPE_COLUMNS,
    agreement_for,
    breakdown_for,
    reconcile_local_closures,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/autonomy-policy", tags=["autonomy-policy"])


# ---------------------------------------------------------------------------
# Hard-coded reference policy (kept in sync with
# services/agents/app/policy/guardrails.py::_DEFAULT_THRESHOLDS).
#
# Duplicated rather than imported because the API service must not depend on
# the agents service package — they ship as separate containers. A small CI
# test catches drift between the two copies.
# ---------------------------------------------------------------------------
_DEFAULTS: dict[str, tuple[float, float, float]] = {
    # Read / enrichment — autonomous by default
    "lookup_ip": (0.0, 0.0, 0.0),
    "lookup_domain": (0.0, 0.0, 0.0),
    "search_logs": (0.0, 0.0, 0.0),
    "enrich_alert": (0.0, 0.0, 0.0),
    "mitre_lookup": (0.0, 0.0, 0.0),
    "get_alert_context": (0.0, 0.0, 0.0),
    # Case workflow — moderate autonomy
    "add_alert_tag": (0.50, 0.30, 0.10),
    "close_alert": (0.60, 0.40, 0.20),
    "create_case": (0.50, 0.30, 0.10),
    "add_case_comment": (0.40, 0.20, 0.05),
    "assign_case": (0.60, 0.40, 0.20),
    # Containment — high blast radius
    "quarantine_file": (0.85, 0.65, 0.40),
    "block_ip": (0.90, 0.70, 0.40),
    "isolate_host": (0.92, 0.72, 0.45),
    "disable_user_account": (0.90, 0.70, 0.40),
    "revoke_session": (0.80, 0.60, 0.30),
    "delete_object": (0.95, 0.80, 0.50),
    "firewall_rule_add": (0.88, 0.68, 0.40),
    "firewall_rule_remove": (0.90, 0.70, 0.40),
}

_BLAST_RADIUS = {
    "lookup_ip": "read",
    "lookup_domain": "read",
    "search_logs": "read",
    "enrich_alert": "read",
    "mitre_lookup": "read",
    "get_alert_context": "read",
    "add_alert_tag": "low",
    "close_alert": "low",
    "create_case": "low",
    "add_case_comment": "low",
    "assign_case": "low",
    "quarantine_file": "high",
    "block_ip": "high",
    "isolate_host": "high",
    "disable_user_account": "high",
    "revoke_session": "medium",
    "delete_object": "critical",
    "firewall_rule_add": "high",
    "firewall_rule_remove": "high",
}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ThresholdTriple(BaseModel):
    """Three confidence cutoffs for one action.

    Invariant: ``escalation <= review <= auto`` and all are in ``[0.0, 1.0]``.
    """

    auto: float = Field(..., ge=0.0, le=1.0)
    review: float = Field(..., ge=0.0, le=1.0)
    escalation: float = Field(..., ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _enforce_ordering(self) -> ThresholdTriple:
        if self.review > self.auto:
            raise ValueError("review threshold must be <= auto threshold")
        if self.escalation > self.review:
            raise ValueError("escalation threshold must be <= review threshold")
        return self


class ActionPolicy(BaseModel):
    action: str
    blast_radius: str
    thresholds: ThresholdTriple
    default_thresholds: ThresholdTriple
    overridden: bool
    override_source: str | None = None
    last_updated_at: str | None = None
    last_updated_by: str | None = None
    last_reason: str | None = None


class AutonomyPolicyResponse(BaseModel):
    tenant_id: str
    actions: list[ActionPolicy]


class ThresholdUpdateRequest(BaseModel):
    auto: float = Field(..., ge=0.0, le=1.0)
    review: float = Field(..., ge=0.0, le=1.0)
    escalation: float = Field(..., ge=0.0, le=1.0)
    reason: str | None = Field(
        None,
        max_length=500,
        description="Free-text justification — surfaced in the audit log.",
    )

    @model_validator(mode="after")
    def _enforce_ordering(self) -> ThresholdUpdateRequest:
        if self.review > self.auto:
            raise ValueError("review threshold must be <= auto threshold")
        if self.escalation > self.review:
            raise ValueError("escalation threshold must be <= review threshold")
        return self


class ThresholdUpdateResponse(BaseModel):
    action: str
    thresholds: ThresholdTriple
    updated_at: str
    updated_by: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _default_triple(action: str) -> ThresholdTriple:
    a, r, e = _DEFAULTS.get(action, (1.0, 1.0, 1.0))
    return ThresholdTriple(auto=a, review=r, escalation=e)


async def _fetch_overrides(db, tenant_id: str) -> dict[str, dict]:
    """Return ``{action_name: row_dict}`` from the DB, or ``{}`` if the table
    is missing or unreachable. Falls back to the legacy single-column shape
    if the migration 021 columns aren't present yet."""
    try:
        result = await db.execute(
            text(
                """
                SELECT action_name,
                       min_confidence,
                       review_confidence,
                       escalation_confidence,
                       updated_by,
                       updated_at,
                       source,
                       reason
                FROM aisoc_autonomy_thresholds
                WHERE tenant_id = :tenant_id
                """
            ),
            {"tenant_id": str(tenant_id)},
        )
        rows = result.mappings().all()
    except Exception:
        # Pre-021 schema or table missing — try the minimal legacy shape.
        try:
            result = await db.execute(
                text(
                    """
                    SELECT action_name,
                           min_confidence,
                           updated_by,
                           updated_at
                    FROM aisoc_autonomy_thresholds
                    WHERE tenant_id = :tenant_id
                    """
                ),
                {"tenant_id": str(tenant_id)},
            )
            rows = result.mappings().all()
        except Exception as exc:
            logger.warning(
                "autonomy_policy.fetch_overrides_unavailable",
                tenant_id=str(tenant_id),
                error=str(exc),
            )
            return {}
    return {r["action_name"]: dict(r) for r in rows}


def _row_to_triple(row: dict) -> ThresholdTriple:
    auto = float(row["min_confidence"])
    review = row.get("review_confidence")
    escalation = row.get("escalation_confidence")
    review_v = float(review) if review is not None else max(0.0, auto - 0.1)
    escalation_v = float(escalation) if escalation is not None else max(0.0, review_v - 0.2)
    # Clamp into a valid ordering — older legacy rows may not satisfy it.
    review_v = min(review_v, auto)
    escalation_v = min(escalation_v, review_v)
    return ThresholdTriple(auto=auto, review=review_v, escalation=escalation_v)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=AutonomyPolicyResponse)
async def get_autonomy_policy(
    user: AuthUser,
    db: DBSession,
) -> AutonomyPolicyResponse:
    """Return the effective autonomy policy for the calling tenant.

    For each known action we surface the merged thresholds (defaults + DB
    overrides), the hard-coded defaults, and an ``overridden`` flag the UI
    uses to render a "modified from default" badge.
    """
    await user.require_permission_db("settings:read", db)

    overrides = await _fetch_overrides(db, str(user.tenant_id))

    actions: list[ActionPolicy] = []
    seen: set[str] = set()
    for action in _DEFAULTS:
        seen.add(action)
        defaults = _default_triple(action)
        row = overrides.get(action)
        if row is not None:
            thresholds = _row_to_triple(row)
            actions.append(
                ActionPolicy(
                    action=action,
                    blast_radius=_BLAST_RADIUS.get(action, "unknown"),
                    thresholds=thresholds,
                    default_thresholds=defaults,
                    overridden=True,
                    override_source=row.get("source") or "admin_ui",
                    last_updated_at=row["updated_at"].isoformat() if row.get("updated_at") else None,
                    last_updated_by=row.get("updated_by"),
                    last_reason=row.get("reason"),
                )
            )
        else:
            actions.append(
                ActionPolicy(
                    action=action,
                    blast_radius=_BLAST_RADIUS.get(action, "unknown"),
                    thresholds=defaults,
                    default_thresholds=defaults,
                    overridden=False,
                )
            )

    # Surface any DB rows for actions we don't recognise (custom tenant
    # actions) so the admin can still see and clear them.
    for action, row in overrides.items():
        if action in seen:
            continue
        thresholds = _row_to_triple(row)
        actions.append(
            ActionPolicy(
                action=action,
                blast_radius="custom",
                thresholds=thresholds,
                default_thresholds=ThresholdTriple(auto=1.0, review=1.0, escalation=1.0),
                overridden=True,
                override_source=row.get("source") or "admin_ui",
                last_updated_at=row["updated_at"].isoformat() if row.get("updated_at") else None,
                last_updated_by=row.get("updated_by"),
                last_reason=row.get("reason"),
            )
        )

    actions.sort(key=lambda a: (a.blast_radius, a.action))
    return AutonomyPolicyResponse(tenant_id=str(user.tenant_id), actions=actions)


@router.put("/{action}", response_model=ThresholdUpdateResponse)
async def upsert_action_threshold(
    action: str,
    payload: ThresholdUpdateRequest,
    user: AuthUser,
    db: DBSession,
) -> ThresholdUpdateResponse:
    """Set (or update) the three-tier thresholds for one action.

    The new policy takes effect after the agent's tenant-cache TTL expires
    or the cache is reset (``services/agents/app/policy/__init__.py``
    ``reset_tenant_cache``).
    """
    await user.require_permission_db("settings:write", db)

    if not action or len(action) > 100 or not action.replace("_", "").isalnum():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="action name must be alphanumeric/underscore, ≤ 100 chars",
        )

    now = datetime.now(UTC)
    try:
        # We always SET min_confidence; the new columns are silently ignored
        # if they don't exist yet because the migration adds them as NULLable.
        await db.execute(
            text(
                """
                INSERT INTO aisoc_autonomy_thresholds (
                    tenant_id, action_name, min_confidence,
                    review_confidence, escalation_confidence,
                    updated_by, updated_at, source, reason
                )
                VALUES (
                    :tenant_id, :action, :auto,
                    :review, :escalation,
                    :updated_by, :updated_at, 'admin_ui', :reason
                )
                ON CONFLICT (tenant_id, action_name) DO UPDATE SET
                    min_confidence = EXCLUDED.min_confidence,
                    review_confidence = EXCLUDED.review_confidence,
                    escalation_confidence = EXCLUDED.escalation_confidence,
                    updated_by = EXCLUDED.updated_by,
                    updated_at = EXCLUDED.updated_at,
                    source = EXCLUDED.source,
                    reason = EXCLUDED.reason
                """
            ),
            {
                "tenant_id": str(user.tenant_id),
                "action": action,
                "auto": payload.auto,
                "review": payload.review,
                "escalation": payload.escalation,
                "updated_by": user.email,
                "updated_at": now,
                "reason": payload.reason,
            },
        )
        await db.commit()
    except Exception as exc:
        await db.rollback()
        # Retry against the legacy schema if the new columns aren't there.
        try:
            await db.execute(
                text(
                    """
                    INSERT INTO aisoc_autonomy_thresholds (
                        tenant_id, action_name, min_confidence,
                        updated_by, updated_at
                    )
                    VALUES (:tenant_id, :action, :auto, :updated_by, :updated_at)
                    ON CONFLICT (tenant_id, action_name) DO UPDATE SET
                        min_confidence = EXCLUDED.min_confidence,
                        updated_by = EXCLUDED.updated_by,
                        updated_at = EXCLUDED.updated_at
                    """
                ),
                {
                    "tenant_id": str(user.tenant_id),
                    "action": action,
                    "auto": payload.auto,
                    "updated_by": user.email,
                    "updated_at": now,
                },
            )
            await db.commit()
            logger.warning(
                "autonomy_policy.legacy_schema_used",
                tenant_id=str(user.tenant_id),
                action=action,
                reason="pre-021 schema; review/escalation tiers will be derived",
            )
        except Exception as final_exc:
            await db.rollback()
            logger.error(
                "autonomy_policy.upsert_failed",
                tenant_id=str(user.tenant_id),
                action=action,
                error=str(final_exc),
                first_error=str(exc),
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to persist autonomy threshold",
            ) from final_exc

    logger.info(
        "autonomy_policy.threshold_updated",
        tenant_id=str(user.tenant_id),
        action=action,
        auto=payload.auto,
        review=payload.review,
        escalation=payload.escalation,
        updated_by=user.email,
        reason_set=payload.reason is not None,
    )

    return ThresholdUpdateResponse(
        action=action,
        thresholds=ThresholdTriple(auto=payload.auto, review=payload.review, escalation=payload.escalation),
        updated_at=now.isoformat(),
        updated_by=user.email,
    )


@router.delete("/{action}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def reset_action_threshold(
    action: str,
    user: AuthUser,
    db: DBSession,
) -> None:
    """Reset a single action back to the hard-coded / YAML default."""
    await user.require_permission_db("settings:write", db)

    try:
        await db.execute(
            text(
                """
                DELETE FROM aisoc_autonomy_thresholds
                WHERE tenant_id = :tenant_id AND action_name = :action
                """
            ),
            {"tenant_id": str(user.tenant_id), "action": action},
        )
        await db.commit()
    except Exception as exc:
        await db.rollback()
        logger.error(
            "autonomy_policy.reset_failed",
            tenant_id=str(user.tenant_id),
            action=action,
            error=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset autonomy threshold",
        ) from exc

    logger.info(
        "autonomy_policy.threshold_reset",
        tenant_id=str(user.tenant_id),
        action=action,
        reset_by=user.email,
    )


# ---------------------------------------------------------------------------
# Shadow mode and rolling agreement (gap-closure Phase 2.1 and 2.2)
#
# The thresholds above answer "how confident must the agent be". These answer
# a different question the same admin screen has to carry: "has it earned the
# right to be believed". They live in this module rather than beside it
# because an operator raising an autonomy threshold and an operator reading
# the track record that justifies it are the same person on the same visit,
# and splitting the two across routers would mean neither surface shows both.
# ---------------------------------------------------------------------------

#: Matches every class. What a tenant turns on first, before they know which
#: classes their own queue contains.
WILDCARD = "*"

#: An alert class is an `alerts.category` value. Constrained here so a caller
#: cannot write a 2 KB string into a primary key, and lower-cased so `Identity`
#: and `identity` are not two classes with half the evidence each.
_MAX_CLASS_LEN = 100


class ShadowModeEntry(BaseModel):
    alert_class: str
    enabled: bool
    enabled_at: str | None = None
    updated_at: str | None = None
    updated_by: str | None = None


class ShadowModeResponse(BaseModel):
    tenant_id: str
    entries: list[ShadowModeEntry]


class ShadowModeUpdateRequest(BaseModel):
    enabled: bool


class AgreementWindowModel(BaseModel):
    """Counts, and the rates derived from them.

    Every rate is optional and is ``null`` when its denominator was zero. The
    console renders that as "not measured". A zero here would say the agent
    was wrong every time, which is a different fact with a different remedy,
    and it is the more flattering of the two to print by accident in the
    abstention column and the more damning in the agreement column.
    """

    resolved: int
    labelled: int
    unlabeled: int
    answered: int
    abstained: int
    agreed: int
    malicious_support: int
    malicious_caught: int
    agreement_rate: float | None = None
    malicious_recall: float | None = None
    abstention_rate: float | None = None


class AgreementScopeModel(BaseModel):
    key: str
    window: AgreementWindowModel


class AgreementResponse(BaseModel):
    tenant_id: str
    scope_kind: str
    scope_key: str
    window: AgreementWindowModel
    #: The trailing slice of the most recent decisions, scored separately.
    #: A window average is where a gradual decline hides, so the surface that
    #: justifies a promotion has to show both or it is showing the flattering
    #: half.
    recent: AgreementWindowModel
    window_start: str
    window_end: str
    thresholds: dict[str, float | int]
    reconciled: int
    by_alert_class: list[AgreementScopeModel]
    by_rule: list[AgreementScopeModel]
    by_source: list[AgreementScopeModel]
    by_model: list[AgreementScopeModel]


def _normalise_class(value: str) -> str:
    cleaned = (value or "").strip().lower()
    if cleaned == WILDCARD:
        return WILDCARD
    if not cleaned or len(cleaned) > _MAX_CLASS_LEN or not cleaned.replace("_", "").replace("-", "").isalnum():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"alert class must be '{WILDCARD}' or an alphanumeric category name of at most {_MAX_CLASS_LEN} characters",
        )
    return cleaned


@router.get("/shadow-mode", response_model=ShadowModeResponse)
async def get_shadow_mode(
    user: AuthUser,
    db: TenantDBSession,
) -> ShadowModeResponse:
    """Which alert classes this tenant is measuring rather than acting on."""
    await user.require_permission_db("settings:read", db)

    rows = (
        (
            await db.execute(
                text(
                    """
                SELECT alert_class, enabled, enabled_at, updated_at, updated_by
                FROM aisoc_shadow_mode
                WHERE tenant_id = :tenant_id
                ORDER BY alert_class
                """
                ),
                {"tenant_id": str(user.tenant_id)},
            )
        )
        .mappings()
        .all()
    )

    return ShadowModeResponse(
        tenant_id=str(user.tenant_id),
        entries=[
            ShadowModeEntry(
                alert_class=row["alert_class"],
                enabled=bool(row["enabled"]),
                enabled_at=row["enabled_at"].isoformat() if row["enabled_at"] else None,
                updated_at=row["updated_at"].isoformat() if row["updated_at"] else None,
                updated_by=str(row["updated_by"]) if row["updated_by"] else None,
            )
            for row in rows
        ],
    )


@router.put("/shadow-mode/{alert_class}", response_model=ShadowModeEntry)
async def set_shadow_mode(
    alert_class: str,
    payload: ShadowModeUpdateRequest,
    user: AuthUser,
    db: TenantDBSession,
) -> ShadowModeEntry:
    """Start or stop measuring one alert class.

    ``enabled_at`` is stamped on the transition into shadow and cleared on the
    way out, rather than being set on every write. A promotion window that
    reaches further back than the day measurement started is reaching back
    before there was anything to measure, and the only way a later reader can
    tell is if this column records the real start.
    """
    await user.require_permission_db("settings:write", db)
    cleaned = _normalise_class(alert_class)

    row = (
        (
            await db.execute(
                text(
                    """
                INSERT INTO aisoc_shadow_mode (tenant_id, alert_class, enabled, enabled_at, updated_by, updated_at)
                VALUES (:tenant_id, :alert_class, :enabled, CASE WHEN :enabled THEN now() ELSE NULL END, :updated_by, now())
                ON CONFLICT (tenant_id, alert_class) DO UPDATE SET
                    enabled = EXCLUDED.enabled,
                    enabled_at = CASE
                        WHEN EXCLUDED.enabled AND NOT aisoc_shadow_mode.enabled THEN now()
                        WHEN EXCLUDED.enabled THEN aisoc_shadow_mode.enabled_at
                        ELSE NULL
                    END,
                    updated_by = EXCLUDED.updated_by,
                    updated_at = now()
                RETURNING alert_class, enabled, enabled_at, updated_at, updated_by
                """
                ),
                {
                    "tenant_id": str(user.tenant_id),
                    "alert_class": cleaned,
                    "enabled": payload.enabled,
                    "updated_by": str(user.user_id),
                },
            )
        )
        .mappings()
        .one()
    )
    await db.commit()

    logger.info(
        "autonomy_policy.shadow_mode_set",
        tenant_id=str(user.tenant_id),
        alert_class=cleaned,
        enabled=payload.enabled,
        updated_by=user.email,
    )
    return ShadowModeEntry(
        alert_class=row["alert_class"],
        enabled=bool(row["enabled"]),
        enabled_at=row["enabled_at"].isoformat() if row["enabled_at"] else None,
        updated_at=row["updated_at"].isoformat() if row["updated_at"] else None,
        updated_by=str(row["updated_by"]) if row["updated_by"] else None,
    )


@router.get("/agreement", response_model=AgreementResponse)
async def get_agreement(
    user: AuthUser,
    db: TenantDBSession,
    scope_kind: str = Query("tenant", description="tenant, alert_class, rule, source or model"),
    scope_key: str = Query(WILDCARD, max_length=200),
) -> AgreementResponse:
    """Rolling agreement between the agent and this tenant's own analysts.

    The tenant comes from the credential. ``scope_kind`` and ``scope_key``
    narrow *within* that tenant and cannot widen beyond it: the scope names a
    dimension from a fixed vocabulary, never a column, and the tenant
    predicate is applied whatever the scope says.

    Closures made in this console are reconciled on the way in rather than by
    a background job. The sweep is bounded and indexed, and doing it here
    means the number an operator is looking at includes the alert they closed
    a minute ago, which is exactly when they come to look.
    """
    await user.require_permission_db("settings:read", db)

    if scope_kind != "tenant" and scope_kind not in SCOPE_COLUMNS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"scope_kind must be 'tenant' or one of {sorted(SCOPE_COLUMNS)}",
        )

    reconciled = await reconcile_local_closures(db, user.tenant_id)
    if reconciled:
        await db.commit()

    thresholds = PromotionThresholds()
    evidence = await agreement_for(
        db,
        user.tenant_id,
        scope_kind=scope_kind,
        scope_key=scope_key,
        thresholds=thresholds,
    )

    breakdowns: dict[str, list[AgreementScopeModel]] = {}
    for dimension in ("alert_class", "rule", "source", "model"):
        rows = await breakdown_for(db, user.tenant_id, scope_kind=dimension, thresholds=thresholds)
        breakdowns[dimension] = [AgreementScopeModel(key=row.key, window=AgreementWindowModel(**row.window.as_dict())) for row in rows]

    return AgreementResponse(
        tenant_id=str(user.tenant_id),
        scope_kind=evidence.scope_kind,
        scope_key=evidence.scope_key,
        window=AgreementWindowModel(**evidence.window.as_dict()),
        recent=AgreementWindowModel(**evidence.recent.as_dict()),
        window_start=evidence.window_start.isoformat(),
        window_end=evidence.window_end.isoformat(),
        thresholds=thresholds.as_dict(),
        reconciled=reconciled,
        by_alert_class=breakdowns["alert_class"],
        by_rule=breakdowns["rule"],
        by_source=breakdowns["source"],
        by_model=breakdowns["model"],
    )
