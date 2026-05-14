"""Rule tuning workbench — projects ``DetectionRule`` rows into analyst-actionable
suggestions and persists tuning actions.

The tuning workbench is intentionally *cheap*: we do not recompute live false
positive rates on demand. Every projection is derived from already-materialised
fields on ``DetectionRule`` (``fp_rate``, ``total_hits``, ``confidence``,
``last_triggered``, ``status``) which are maintained by the ingestion and
detection pipelines. That keeps the workbench fast and lets analysts triage
hundreds of rules without hammering the alerts table.

Three verbs live here:

* **project** — classify each rule, score it, and surface a suggested action.
* **apply** — mechanically tighten a rule (raise threshold, add a placeholder
  suppression, disable) or simply acknowledge it. Every apply bumps
  ``DetectionRule.version`` and emits an audit event.
* **dismiss / auto_tune** — record analyst intent without changing rule
  semantics. Dismissed rules drop out of the default workbench view; auto_tune
  is a per-rule opt-in flag stored under ``suppression_config.auto_tune`` so
  future automated tuners know they're allowed to touch it.

All mutations land in ``suppression_config`` / ``threshold_config`` (both JSONB
``dict``s) and stay tenant-mutable — see
:mod:`app.services.detections.sigma_import` for the convention.
"""

from __future__ import annotations

import copy
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import AuthUser
from app.models.detection_rule import DetectionRule
from app.services.audit import emit_audit

# ─── Tuning heuristics ───────────────────────────────────────────────────────
#
# Thresholds are deliberately permissive so the workbench surfaces *some*
# signal even for small tenants. They live as module constants so tests and
# the docs page can reference the same numbers.

#: A rule with this fp_rate or higher is hot — suggest a suppression first.
TUNING_FP_RATE_NOISY = 0.20

#: Combined with ``TUNING_FP_RATE_NOISY`` for the ``raise_threshold`` lane —
#: noisy rules that *also* fire a lot are good threshold candidates.
TUNING_FP_RATE_BUMPABLE = 0.10

#: When fp_rate AND confidence both look bad and the rule is firing, we
#: suggest disabling it outright rather than papering over the noise.
TUNING_FP_RATE_DISABLE = 0.50

#: Anything under this confidence is considered "low" — analysts should
#: re-evaluate before they trust a high-rate alert from it.
TUNING_LOW_CONFIDENCE = 40

#: Threshold-bump candidates need enough hits that bumping by +1 is safe.
TUNING_MIN_HITS_FOR_THRESHOLD = 20

#: Stale = active rule that has not fired in this many days. (We also require
#: the rule itself to be older than this, otherwise brand-new rules look stale.)
TUNING_STALE_DAYS = 30

#: Hard cap on rows the projection walks per call. The classifier is pure
#: Python; we keep this bounded so a tenant with 50 000 imported Sigma rules
#: can't accidentally DoS the workbench.
TUNING_MAX_RULES_SCANNED = 1000


TuningSuggestion = Literal[
    "disable",
    "add_suppression",
    "raise_threshold",
    "tune_confidence",
    "review_stale",
    "healthy",
]

TuningAction = Literal[
    "raise_threshold",
    "add_suppression",
    "disable",
    "acknowledge",
]

# Suggestions that surface as "needs work" in the summary tile. Everything
# else (just ``healthy``) is folded into the healthy bucket.
ACTIONABLE_SUGGESTIONS: frozenset[TuningSuggestion] = frozenset(
    {"disable", "add_suppression", "raise_threshold", "tune_confidence", "review_stale"}
)

# Suggestion → ordering weight. Higher = surface first.
_SUGGESTION_WEIGHT: dict[TuningSuggestion, int] = {
    "disable": 500,
    "add_suppression": 400,
    "raise_threshold": 300,
    "tune_confidence": 200,
    "review_stale": 100,
    "healthy": 0,
}


# ─── Wire models ─────────────────────────────────────────────────────────────


class TuningEntry(BaseModel):
    """One row in the tuning workbench — what an analyst sees."""

    rule_id: str
    name: str
    description: str | None = None
    category: str
    severity: str
    status: str
    enabled: bool
    confidence: int
    fp_rate: float
    total_hits: int
    last_triggered_at: str | None = None
    tags: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    version: int
    updated_at: str

    suggestion: TuningSuggestion
    score: int
    reasons: list[str] = Field(default_factory=list)
    auto_tune: bool = False
    dismissed_at: str | None = None
    last_action: str | None = None
    last_action_at: str | None = None


class TuningSummary(BaseModel):
    """Top-line counts for the workbench header."""

    total_rules: int
    actionable: int
    healthy: int
    disable_count: int = 0
    add_suppression_count: int = 0
    raise_threshold_count: int = 0
    tune_confidence_count: int = 0
    review_stale_count: int = 0
    auto_tune_enabled: int = 0
    average_fp_rate: float = 0.0
    high_fp_count: int = 0


class TuningFilters(BaseModel):
    """Echo of the filters that built this response (handy for the UI)."""

    severity: str | None = None
    suggestion: str | None = None
    search: str | None = None
    enabled_only: bool = False
    include_dismissed: bool = False
    page: int = 1
    page_size: int = 50


class TuningResponse(BaseModel):
    """Wire shape for ``GET /detection/tuning``."""

    entries: list[TuningEntry]
    summary: TuningSummary
    filters: TuningFilters
    total: int
    generated_at: str


class ApplyTuningRequest(BaseModel):
    """Body for ``POST /detection/tuning/{rule_id}/apply``."""

    action: TuningAction
    note: str | None = None
    threshold: int | None = Field(
        default=None,
        ge=1,
        le=1_000_000,
        description="Override threshold to set when action='raise_threshold'.",
    )
    suppression_reason: str | None = Field(
        default=None,
        max_length=255,
        description="Free-text reason recorded with the suppression placeholder.",
    )


class DismissTuningRequest(BaseModel):
    """Body for ``POST /detection/tuning/{rule_id}/dismiss``."""

    reason: str | None = Field(default=None, max_length=255)


class AutoTuneRequest(BaseModel):
    """Body for ``POST /detection/tuning/{rule_id}/auto_tune``."""

    enabled: bool


# ─── Internal projection helpers ─────────────────────────────────────────────


@dataclass(frozen=True)
class _Classification:
    suggestion: TuningSuggestion
    reasons: list[str]


def _is_enabled(rule: DetectionRule) -> bool:
    """Mirror :func:`detection_compat._to_frontend`'s enabled mapping."""
    return rule.status == "active"


def _suppression_config(rule: DetectionRule) -> dict[str, Any]:
    """Return a *copy* of suppression_config so callers can mutate safely."""
    raw = rule.suppression_config or {}
    if not isinstance(raw, dict):
        return {}
    return copy.deepcopy(raw)


def _threshold_config(rule: DetectionRule) -> dict[str, Any]:
    raw = rule.threshold_config or {}
    if not isinstance(raw, dict):
        return {}
    return copy.deepcopy(raw)


def _auto_tune_enabled(rule: DetectionRule) -> bool:
    cfg = rule.suppression_config or {}
    if isinstance(cfg, dict):
        return bool(cfg.get("auto_tune"))
    return False


def _dismissed_at(rule: DetectionRule) -> str | None:
    cfg = rule.suppression_config or {}
    if isinstance(cfg, dict):
        value = cfg.get("tuning_dismissed_at")
        if isinstance(value, str):
            return value
    return None


def _last_action(rule: DetectionRule) -> tuple[str | None, str | None]:
    cfg = rule.suppression_config or {}
    if not isinstance(cfg, dict):
        return None, None
    action = cfg.get("tuning_last_action")
    at = cfg.get("tuning_last_action_at")
    return (action if isinstance(action, str) else None, at if isinstance(at, str) else None)


def _stale(rule: DetectionRule, now: datetime) -> bool:
    cutoff = now - timedelta(days=TUNING_STALE_DAYS)
    if rule.last_triggered is not None:
        return rule.last_triggered < cutoff
    # Never fired — only call stale once it's old enough that we'd expect a hit.
    if rule.created_at is None:
        return False
    return rule.created_at < cutoff


def classify_suggestion(rule: DetectionRule, now: datetime | None = None) -> _Classification:
    """Pure function: rule → suggestion + human-readable reasons.

    Order matters: the first matching lane wins, so heavier interventions
    (disable, suppression) take precedence over softer hints (review_stale).
    """
    moment = now or datetime.now(UTC)
    fp = rule.fp_rate or 0.0
    confidence = rule.confidence or 0
    hits = rule.total_hits or 0
    enabled = _is_enabled(rule)

    reasons: list[str] = []

    if enabled and fp >= TUNING_FP_RATE_DISABLE and confidence < TUNING_LOW_CONFIDENCE:
        reasons.append(f"FP rate {fp:.0%} ≥ {TUNING_FP_RATE_DISABLE:.0%} with confidence {confidence} < {TUNING_LOW_CONFIDENCE}")
        if hits:
            reasons.append(f"{hits} total hits — disable will reduce queue pressure immediately")
        return _Classification("disable", reasons)

    if enabled and fp >= TUNING_FP_RATE_NOISY:
        reasons.append(f"FP rate {fp:.0%} ≥ {TUNING_FP_RATE_NOISY:.0%} — add a suppression for the noisy entity")
        if hits:
            reasons.append(f"{hits} total hits over the rule's lifetime")
        return _Classification("add_suppression", reasons)

    if enabled and fp >= TUNING_FP_RATE_BUMPABLE and hits >= TUNING_MIN_HITS_FOR_THRESHOLD:
        reasons.append(f"FP rate {fp:.0%} with {hits} hits — bumping the threshold trims volume without losing the signal")
        return _Classification("raise_threshold", reasons)

    if confidence < TUNING_LOW_CONFIDENCE and hits >= TUNING_MIN_HITS_FOR_THRESHOLD:
        reasons.append(f"Confidence {confidence} < {TUNING_LOW_CONFIDENCE} despite {hits} hits — re-evaluate the rule body")
        return _Classification("tune_confidence", reasons)

    if enabled and _stale(rule, moment):
        if rule.last_triggered is None:
            reasons.append(f"No hits ever; rule has been live for {TUNING_STALE_DAYS}+ days")
        else:
            days = (moment - rule.last_triggered).days
            reasons.append(f"Last hit was {days} days ago (stale threshold is {TUNING_STALE_DAYS}d)")
        return _Classification("review_stale", reasons)

    return _Classification("healthy", reasons)


def _score(rule: DetectionRule, classification: _Classification) -> int:
    """Compose suggestion weight + fp_rate + hits into a single ordering key."""
    base = _SUGGESTION_WEIGHT[classification.suggestion]
    # fp_rate ∈ [0,1] → 0..100; total_hits scaled down so a runaway rule with
    # a million hits doesn't drown out the noisiest 1% rule with 50 hits.
    fp_part = int(round((rule.fp_rate or 0.0) * 100))
    hits_part = min(rule.total_hits or 0, 1000) // 10
    return base + fp_part + hits_part


def project_rule(rule: DetectionRule, now: datetime | None = None) -> TuningEntry:
    """Pure function: ORM row → wire entry. Safe to test in isolation."""
    moment = now or datetime.now(UTC)
    classification = classify_suggestion(rule, moment)
    last_action, last_action_at = _last_action(rule)

    mitre_techniques = [str(t) for t in (rule.mitre_techniques or [])]
    mitre_tactics = [str(t) for t in (rule.mitre_tactics or [])]

    return TuningEntry(
        rule_id=str(rule.id),
        name=rule.name,
        description=rule.description,
        category=rule.category,
        severity=rule.severity,
        status=rule.status,
        enabled=_is_enabled(rule),
        confidence=rule.confidence or 0,
        fp_rate=float(rule.fp_rate or 0.0),
        total_hits=rule.total_hits or 0,
        last_triggered_at=rule.last_triggered.isoformat() if rule.last_triggered else None,
        tags=list(rule.tags or []),
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        version=rule.version or 1,
        updated_at=rule.updated_at.isoformat() if rule.updated_at else moment.isoformat(),
        suggestion=classification.suggestion,
        score=_score(rule, classification),
        reasons=classification.reasons,
        auto_tune=_auto_tune_enabled(rule),
        dismissed_at=_dismissed_at(rule),
        last_action=last_action,
        last_action_at=last_action_at,
    )


def _summarise(entries: list[TuningEntry]) -> TuningSummary:
    if not entries:
        return TuningSummary(total_rules=0, actionable=0, healthy=0)

    counts: dict[TuningSuggestion, int] = dict.fromkeys(_SUGGESTION_WEIGHT, 0)
    auto_tune = 0
    fp_sum = 0.0
    high_fp = 0
    for entry in entries:
        counts[entry.suggestion] = counts.get(entry.suggestion, 0) + 1
        if entry.auto_tune:
            auto_tune += 1
        fp_sum += entry.fp_rate
        if entry.fp_rate >= TUNING_FP_RATE_NOISY:
            high_fp += 1

    actionable = sum(counts[s] for s in ACTIONABLE_SUGGESTIONS)
    healthy = counts.get("healthy", 0)
    total = len(entries)
    avg_fp = round(fp_sum / total, 4) if total else 0.0

    return TuningSummary(
        total_rules=total,
        actionable=actionable,
        healthy=healthy,
        disable_count=counts.get("disable", 0),
        add_suppression_count=counts.get("add_suppression", 0),
        raise_threshold_count=counts.get("raise_threshold", 0),
        tune_confidence_count=counts.get("tune_confidence", 0),
        review_stale_count=counts.get("review_stale", 0),
        auto_tune_enabled=auto_tune,
        average_fp_rate=avg_fp,
        high_fp_count=high_fp,
    )


# ─── Coordinator: build the workbench ────────────────────────────────────────


async def build_tuning(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    severity: str | None = None,
    suggestion: TuningSuggestion | None = None,
    search: str | None = None,
    enabled_only: bool = False,
    include_dismissed: bool = False,
    page: int = 1,
    page_size: int = 50,
    now: datetime | None = None,
) -> TuningResponse:
    """Project every (filtered) rule the tenant owns, then paginate.

    The summary is computed across the **entire classified population** —
    not just the current page — so the header counts stay stable as analysts
    page through results.
    """
    moment = now or datetime.now(UTC)
    page = max(1, page)
    page_size = max(1, min(page_size, 100))

    stmt = select(DetectionRule).where(or_(DetectionRule.tenant_id == tenant_id, DetectionRule.tenant_id.is_(None)))

    if severity:
        stmt = stmt.where(DetectionRule.severity == severity)
    if enabled_only:
        stmt = stmt.where(DetectionRule.status == "active")
    if search:
        like = f"%{search.lower()}%"
        stmt = stmt.where(
            or_(
                DetectionRule.name.ilike(like),
                DetectionRule.description.ilike(like),
                DetectionRule.category.ilike(like),
            )
        )

    # Pre-sort at the DB so the projection mostly hits the heaviest rules
    # first; final ordering is by Python-computed score below.
    stmt = stmt.order_by(
        DetectionRule.fp_rate.desc(),
        DetectionRule.total_hits.desc(),
        DetectionRule.updated_at.desc(),
    ).limit(TUNING_MAX_RULES_SCANNED)

    result = await db.execute(stmt)
    rules: list[DetectionRule] = list(result.scalars().all())

    projected: list[TuningEntry] = [project_rule(rule, moment) for rule in rules]

    if not include_dismissed:
        projected = [entry for entry in projected if entry.dismissed_at is None]

    summary = _summarise(projected)

    if suggestion:
        projected = [entry for entry in projected if entry.suggestion == suggestion]

    # Final sort: score DESC, then fp_rate, then total_hits, then name for stability.
    projected.sort(key=lambda e: (-e.score, -e.fp_rate, -e.total_hits, e.name.lower()))

    total = len(projected)
    start = (page - 1) * page_size
    end = start + page_size
    page_entries = projected[start:end]

    return TuningResponse(
        entries=page_entries,
        summary=summary,
        filters=TuningFilters(
            severity=severity,
            suggestion=suggestion,
            search=search,
            enabled_only=enabled_only,
            include_dismissed=include_dismissed,
            page=page,
            page_size=page_size,
        ),
        total=total,
        generated_at=moment.isoformat(),
    )


async def build_tuning_summary(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    now: datetime | None = None,
) -> TuningSummary:
    """Cheap summary-only call for sidebar badges and dashboard tiles."""
    moment = now or datetime.now(UTC)
    stmt = (
        select(DetectionRule)
        .where(or_(DetectionRule.tenant_id == tenant_id, DetectionRule.tenant_id.is_(None)))
        .order_by(
            DetectionRule.fp_rate.desc(),
            DetectionRule.total_hits.desc(),
        )
        .limit(TUNING_MAX_RULES_SCANNED)
    )
    result = await db.execute(stmt)
    rules: list[DetectionRule] = list(result.scalars().all())
    projected = [project_rule(rule, moment) for rule in rules]
    projected = [entry for entry in projected if entry.dismissed_at is None]
    return _summarise(projected)


# ─── Mutators: apply / dismiss / auto_tune ───────────────────────────────────


async def _load_rule_for_tenant(
    db: AsyncSession,
    *,
    rule_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> DetectionRule:
    """Resolve a rule the actor is allowed to tune.

    Builtin/platform rules (``tenant_id IS NULL``) are visible everywhere but
    aren't tuneable from inside a tenant — tuning a global rule from one
    tenant's workbench would leak the change to every other tenant. We let
    analysts *see* them in projections but reject mutations.
    """
    result = await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection rule not found")
    if rule.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Platform-wide rules can't be tuned from a tenant workbench",
        )
    if rule.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection rule not found")
    return rule


def _bumped_threshold(current: dict[str, Any], override: int | None) -> tuple[dict[str, Any], int, int]:
    """Return (new_config, old_threshold, new_threshold)."""
    next_config = dict(current)
    raw_existing = current.get("event_threshold") or current.get("threshold")
    try:
        existing = int(raw_existing) if raw_existing is not None else 1
    except (TypeError, ValueError):
        existing = 1
    new_value = override if override is not None else max(existing + 1, 2)
    next_config["event_threshold"] = new_value
    next_config["last_raised_at"] = datetime.now(UTC).isoformat()
    return next_config, existing, new_value


def _appended_suppression(
    current: dict[str, Any],
    *,
    reason: str | None,
    actor_email: str | None,
) -> dict[str, Any]:
    """Append a placeholder suppression record. The real suppression engine
    interprets ``suppression_config.rules`` — this just gives it a starting
    point that analysts can refine."""
    next_config = dict(current)
    rules_list = list(next_config.get("rules") or [])
    rules_list.append(
        {
            "kind": "tune_placeholder",
            "added_at": datetime.now(UTC).isoformat(),
            "added_by": actor_email or "system",
            "reason": reason or "Added from tuning workbench — refine the entity/window before relying on it",
        }
    )
    next_config["rules"] = rules_list
    next_config["last_tuned_at"] = datetime.now(UTC).isoformat()
    return next_config


def _stamp_last_action(
    current: dict[str, Any],
    *,
    action: TuningAction,
    actor_email: str | None,
    note: str | None,
) -> dict[str, Any]:
    next_config = dict(current)
    moment = datetime.now(UTC).isoformat()
    next_config["tuning_last_action"] = action
    next_config["tuning_last_action_at"] = moment
    next_config["tuning_last_action_by"] = actor_email or "system"
    if note:
        next_config["tuning_last_action_note"] = note
    # Clearing a stale dismissal: an apply implicitly un-dismisses the rule
    # because the analyst is engaging with it again.
    next_config.pop("tuning_dismissed_at", None)
    next_config.pop("tuning_dismissed_reason", None)
    return next_config


async def apply_tuning(
    db: AsyncSession,
    *,
    rule_id: uuid.UUID,
    actor: AuthUser,
    body: ApplyTuningRequest,
    request: Request | None = None,
    now: datetime | None = None,
) -> TuningEntry:
    """Mechanically apply a tuning suggestion and record an audit event.

    Returns the post-write projected entry so the UI can refresh in-place.
    """
    moment = now or datetime.now(UTC)
    rule = await _load_rule_for_tenant(db, rule_id=rule_id, tenant_id=actor.tenant_id)

    before: dict[str, Any] = {
        "status": rule.status,
        "confidence": rule.confidence,
        "threshold_config": _threshold_config(rule),
        "suppression_config": _suppression_config(rule),
    }

    changes_payload: dict[str, Any] = {"action": body.action}

    if body.action == "raise_threshold":
        next_threshold, old_value, new_value = _bumped_threshold(
            _threshold_config(rule),
            body.threshold,
        )
        rule.threshold_config = next_threshold
        changes_payload["threshold"] = {"before": old_value, "after": new_value}

    elif body.action == "add_suppression":
        rule.suppression_config = _appended_suppression(
            _suppression_config(rule),
            reason=body.suppression_reason or body.note,
            actor_email=actor.email,
        )
        changes_payload["suppression_reason"] = body.suppression_reason or body.note

    elif body.action == "disable":
        rule.status = "disabled"
        changes_payload["status"] = {"before": before["status"], "after": "disabled"}

    elif body.action == "acknowledge":
        # No mechanical change — just stamps last_action below.
        pass

    else:  # pragma: no cover — Pydantic Literal makes this unreachable.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown tuning action: {body.action!r}")

    rule.suppression_config = _stamp_last_action(
        rule.suppression_config or {},
        action=body.action,
        actor_email=actor.email,
        note=body.note,
    )
    rule.version = (rule.version or 1) + 1
    rule.updated_at = moment

    await emit_audit(
        db=db,
        tenant_id=actor.tenant_id,
        actor_id=actor.user_id,
        actor_email=actor.email,
        action="detection.tuning.apply",
        resource="detection_rule",
        resource_id=str(rule.id),
        changes={
            "rule_name": rule.name,
            "before": before,
            "after": {
                "status": rule.status,
                "confidence": rule.confidence,
                "threshold_config": rule.threshold_config,
                "suppression_config": rule.suppression_config,
            },
            "payload": changes_payload,
        },
        request=request,
    )

    await db.commit()
    await db.refresh(rule)
    return project_rule(rule, moment)


async def dismiss_tuning(
    db: AsyncSession,
    *,
    rule_id: uuid.UUID,
    actor: AuthUser,
    body: DismissTuningRequest,
    request: Request | None = None,
    now: datetime | None = None,
) -> TuningEntry:
    """Hide a rule from the default workbench view without changing semantics."""
    moment = now or datetime.now(UTC)
    rule = await _load_rule_for_tenant(db, rule_id=rule_id, tenant_id=actor.tenant_id)

    before = _suppression_config(rule)
    next_config = dict(before)
    next_config["tuning_dismissed_at"] = moment.isoformat()
    next_config["tuning_dismissed_by"] = actor.email or "system"
    if body.reason:
        next_config["tuning_dismissed_reason"] = body.reason
    else:
        next_config.pop("tuning_dismissed_reason", None)

    rule.suppression_config = next_config
    rule.updated_at = moment

    await emit_audit(
        db=db,
        tenant_id=actor.tenant_id,
        actor_id=actor.user_id,
        actor_email=actor.email,
        action="detection.tuning.dismiss",
        resource="detection_rule",
        resource_id=str(rule.id),
        changes={
            "rule_name": rule.name,
            "before": before,
            "after": next_config,
            "reason": body.reason,
        },
        request=request,
    )

    await db.commit()
    await db.refresh(rule)
    return project_rule(rule, moment)


async def set_auto_tune(
    db: AsyncSession,
    *,
    rule_id: uuid.UUID,
    actor: AuthUser,
    body: AutoTuneRequest,
    request: Request | None = None,
    now: datetime | None = None,
) -> TuningEntry:
    """Flip the per-rule auto-tune opt-in flag."""
    moment = now or datetime.now(UTC)
    rule = await _load_rule_for_tenant(db, rule_id=rule_id, tenant_id=actor.tenant_id)

    before = _suppression_config(rule)
    next_config = dict(before)
    previous = bool(next_config.get("auto_tune"))
    next_config["auto_tune"] = body.enabled
    next_config["auto_tune_updated_at"] = moment.isoformat()
    next_config["auto_tune_updated_by"] = actor.email or "system"

    rule.suppression_config = next_config
    rule.updated_at = moment

    await emit_audit(
        db=db,
        tenant_id=actor.tenant_id,
        actor_id=actor.user_id,
        actor_email=actor.email,
        action="detection.tuning.auto_tune",
        resource="detection_rule",
        resource_id=str(rule.id),
        changes={
            "rule_name": rule.name,
            "auto_tune": {"before": previous, "after": body.enabled},
        },
        request=request,
    )

    await db.commit()
    await db.refresh(rule)
    return project_rule(rule, moment)


__all__ = [
    "ACTIONABLE_SUGGESTIONS",
    "ApplyTuningRequest",
    "AutoTuneRequest",
    "DismissTuningRequest",
    "TUNING_FP_RATE_BUMPABLE",
    "TUNING_FP_RATE_DISABLE",
    "TUNING_FP_RATE_NOISY",
    "TUNING_LOW_CONFIDENCE",
    "TUNING_MAX_RULES_SCANNED",
    "TUNING_MIN_HITS_FOR_THRESHOLD",
    "TUNING_STALE_DAYS",
    "TuningAction",
    "TuningEntry",
    "TuningFilters",
    "TuningResponse",
    "TuningSuggestion",
    "TuningSummary",
    "apply_tuning",
    "build_tuning",
    "build_tuning_summary",
    "classify_suggestion",
    "dismiss_tuning",
    "project_rule",
    "set_auto_tune",
]
