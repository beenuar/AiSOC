"""Business Context Rules CRUD + dry-run preview — Track 3, T3.5.

A *business context rule* is a YAML predicate the operator authors on
``/settings/business-context``. It runs between the fusion pipeline
and the triage agent, mutating an alert (severity bump, route to a
specific tier, suppress, tag) based on customer-supplied context like
"prod tag during business hours".

Endpoints
---------

* ``GET    /v1/business-context/rules``           — return the tenant's
  rule set (YAML source + parsed view + engine version).
* ``POST   /v1/business-context/rules``           — replace the tenant's
  whole rule set with a new YAML document. Returns the parsed result so
  the editor can render the engine's view of what it just persisted.
* ``PUT    /v1/business-context/rules/{rule_id}`` — patch a single rule
  in-place; convenience for the side-panel rule builder which edits one
  rule at a time.
* ``DELETE /v1/business-context/rules/{rule_id}`` — delete one rule.
* ``POST   /v1/business-context/rules/preview``   — dry-run a candidate
  YAML against an alert sample (or the last-100 demo set) without
  persisting anything. Returns one before/after row per alert.

Persistence story
-----------------

v1 of T3.5 keeps the parsed rule set in the
:class:`BusinessContextEngine` process singleton. A
``# TODO(T3.5-followup)`` is wired in :func:`_persist_for` for the
``aisoc_business_context_rule_sets`` migration that adds JSONB +
versioning. Keeping persistence to a single helper means swapping in
the DB-backed store is a one-file change.

Feature flag
------------

The hot-path hook (post-fusion → pre-triage) is gated by
``AISOC_BUSINESS_CONTEXT_ENABLED`` (default on, tenant-overridable
via the ``business_context_enabled`` column on ``tenants``). The CRUD
endpoints themselves are *always* enabled — operators need to be able
to author rules even on a tenant where the hook is disabled.

Authorisation
-------------

Read = ``settings:read``; mutating endpoints require ``settings:write``,
matching the autonomy-policy admin surface. Tier-1 analysts cannot edit
rules; the rule set governs how their alerts are routed, which is a
tenant-admin concern.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
import yaml
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser, DBSession
from app.services.business_context import (
    BusinessContextRule,
    RuleParseError,
    load_rules_from_yaml,
)
from app.services.business_context.engine import (
    BusinessContextEngine,
    EngineSnapshot,
    get_engine,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/business-context", tags=["business-context"])

# Reasonable upper bounds — a tenant with > 200 rules has bigger
# problems than a server-side cap, but the limit keeps a runaway YAML
# blob from quietly degrading the dry-run preview latency.
_MAX_YAML_BYTES = 256 * 1024  # 256 KB of YAML is plenty for hundreds of rules.
_MAX_PREVIEW_ALERTS = 200


# ---------------------------------------------------------------------------
# Pydantic wire shapes
# ---------------------------------------------------------------------------


class RuleConditionWire(BaseModel):
    """Mirror of :class:`RuleCondition` for the wire / OpenAPI shape."""

    field: str | None = None
    op: str | None = None
    value: Any = None
    logical: str | None = None
    children: list[RuleConditionWire] = Field(default_factory=list)


class RuleActionWire(BaseModel):
    set_severity: str | None = None
    route_to: str | None = None
    tag: str | None = None
    suppress: bool = False


class RuleWire(BaseModel):
    id: str
    description: str = ""
    enabled: bool = True
    priority: int = 100
    when: RuleConditionWire
    then: RuleActionWire


class RulesEnvelope(BaseModel):
    """Response payload for ``GET /rules``.

    The editor needs *both* the YAML source (so Monaco can show
    formatting + comments) and the parsed view (so the rule-builder
    side-panel can render structured forms). ``version`` is the
    engine snapshot version the parsed view came from — a monotonic
    integer the UI uses to detect "someone else saved while I was
    editing".
    """

    tenant_id: str
    version: int
    yaml: str
    rules: list[RuleWire]
    enabled: bool
    updated_at: str


class ReplaceRulesRequest(BaseModel):
    yaml: str = Field(..., max_length=_MAX_YAML_BYTES)


class UpdateRuleRequest(BaseModel):
    yaml: str = Field(..., max_length=_MAX_YAML_BYTES)


class PreviewRequest(BaseModel):
    yaml: str = Field(..., max_length=_MAX_YAML_BYTES)
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    """Optional alert sample. When empty, the endpoint pulls the last
    50 alerts off ``aisoc_alerts``; when non-empty, the supplied
    alerts are used verbatim (useful for the editor's "preview against
    these three illustrative alerts" power-user flow).
    """


class PreviewRow(BaseModel):
    alert_id: str
    matched_rule_ids: list[str]
    before: dict[str, Any]
    after: dict[str, Any]
    suppressed: bool
    changed: bool


class PreviewResponse(BaseModel):
    sample_size: int
    changed_count: int
    suppressed_count: int
    elapsed_ms: float
    rows: list[PreviewRow]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _wire_condition(cond: Any) -> RuleConditionWire:
    return RuleConditionWire(
        field=cond.field,
        op=cond.op,
        value=cond.value,
        logical=cond.logical,
        children=[_wire_condition(c) for c in cond.children],
    )


def _wire_rule(rule: BusinessContextRule) -> RuleWire:
    return RuleWire(
        id=rule.id,
        description=rule.description,
        enabled=rule.enabled,
        priority=rule.priority,
        when=_wire_condition(rule.when),
        then=RuleActionWire(
            set_severity=rule.then.set_severity,
            route_to=rule.then.route_to,
            tag=rule.then.tag,
            suppress=rule.then.suppress,
        ),
    )


def _envelope(
    tenant_id: UUID,
    snapshot: EngineSnapshot,
    *,
    yaml_text: str,
    enabled: bool,
    updated_at: datetime,
) -> RulesEnvelope:
    return RulesEnvelope(
        tenant_id=str(tenant_id),
        version=snapshot.version,
        yaml=yaml_text,
        rules=[_wire_rule(r) for r in snapshot.rules],
        enabled=enabled,
        updated_at=updated_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# In-memory persistence shim
# ---------------------------------------------------------------------------
#
# v1 keeps the YAML source + the "engine enabled?" boolean in a
# per-process dict. Swapping this out for the JSONB-backed
# ``aisoc_business_context_rule_sets`` table is the
# T3.5-followup migration; isolating the read/write here means the
# call sites in the endpoint don't need to change when that lands.


_RuleStoreEntry = dict[str, Any]
_rule_store: dict[UUID, _RuleStoreEntry] = {}


def _persist_for(tenant_id: UUID, *, yaml_text: str, enabled: bool) -> datetime:
    now = datetime.now(UTC)
    _rule_store[tenant_id] = {
        "yaml": yaml_text,
        "enabled": enabled,
        "updated_at": now,
    }
    return now


def _load_for(tenant_id: UUID) -> _RuleStoreEntry:
    entry = _rule_store.get(tenant_id)
    if entry is None:
        return {
            "yaml": "",
            "enabled": True,  # default-on per spec
            "updated_at": datetime.now(UTC),
        }
    return entry


def _reset_store_for_tests() -> None:
    """Clear in-process state — only safe in test code."""
    _rule_store.clear()


def _engine() -> BusinessContextEngine:
    return get_engine()


# ---------------------------------------------------------------------------
# Sample-alert loader for the dry-run preview
# ---------------------------------------------------------------------------


async def _fetch_sample_alerts(
    db: Any,  # noqa: ANN401 — AsyncSession; kept loose so tests can stub
    tenant_id: UUID,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Pull the last ``limit`` alerts for the tenant.

    The dry-run preview surfaces "what would happen to my last 50
    alerts?" so the analyst gets a tangible feel for the rule before
    saving. Returns an empty list when the alerts table isn't reachable
    (test envs without the schema, demo Fly.io stack) — the UI then
    falls back to its built-in illustrative samples.
    """
    from sqlalchemy import text  # noqa: PLC0415

    try:
        result = await db.execute(
            text(
                """
                SELECT id, severity, title, source, src_ip, hostname, username,
                       tags, metadata
                FROM aisoc_alerts
                WHERE tenant_id = :tenant_id
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            {"tenant_id": str(tenant_id), "limit": int(limit)},
        )
        rows = result.mappings().all()
    except Exception as exc:
        logger.warning(
            "business_context.preview_fetch_unavailable",
            tenant_id=str(tenant_id),
            error=str(exc),
        )
        return []

    out: list[dict[str, Any]] = []
    for row in rows:
        d = dict(row)
        meta = d.pop("metadata", None) or {}
        # Promote the common fields the rule grammar references onto the
        # top level so authors can write `field: alert.severity` rather
        # than `field: alert.metadata.severity`.
        out.append(
            {
                "id": str(d.get("id")),
                "severity": d.get("severity"),
                "title": d.get("title"),
                "source": d.get("source"),
                "src_ip": d.get("src_ip"),
                "hostname": d.get("hostname"),
                "username": d.get("username"),
                "tags": list(d.get("tags") or []),
                "alert": {
                    "severity": d.get("severity"),
                    "source": d.get("source"),
                    "target": (meta.get("target") if isinstance(meta, dict) else {}) or {},
                    "time": (meta.get("time") if isinstance(meta, dict) else {}) or {},
                },
                "metadata": meta,
            }
        )
    return out


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/rules", response_model=RulesEnvelope)
async def get_rules(
    user: AuthUser,
    db: DBSession,
) -> RulesEnvelope:
    """Return the tenant's current rule set.

    Always returns a 200 — a tenant with no rules gets an empty list
    and an empty YAML body. The editor uses the ``enabled`` flag to
    show the "rules paused" banner so analysts aren't surprised when
    a saved rule isn't taking effect.
    """
    await user.require_permission_db("settings:read", db)

    entry = _load_for(user.tenant_id)
    yaml_text = entry["yaml"]
    enabled = entry["enabled"]

    rules = load_rules_from_yaml(yaml_text) if yaml_text else []
    snapshot = _engine().replace(user.tenant_id, rules)
    return _envelope(
        user.tenant_id,
        snapshot,
        yaml_text=yaml_text,
        enabled=enabled,
        updated_at=entry["updated_at"],
    )


@router.post(
    "/rules",
    response_model=RulesEnvelope,
    status_code=status.HTTP_200_OK,
)
async def replace_rules(
    payload: ReplaceRulesRequest,
    user: AuthUser,
    db: DBSession,
) -> RulesEnvelope:
    """Replace the tenant's whole rule set with a new YAML document.

    The engine snapshot is swapped atomically *before* the write
    "completes" from the caller's perspective, so the next evaluation
    on the same process sees the fresh rules within microseconds —
    well inside the 1s "save → preview" budget the task spec calls
    out. Multi-process deployments still honour the budget because the
    JSONB-backed reload (T3.5-followup) will SET version on save and
    every worker re-pulls on TTL miss.
    """
    await user.require_permission_db("settings:write", db)

    try:
        rules = load_rules_from_yaml(payload.yaml)
    except RuleParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    updated_at = _persist_for(
        user.tenant_id,
        yaml_text=payload.yaml,
        enabled=_load_for(user.tenant_id)["enabled"],
    )
    snapshot = _engine().replace(user.tenant_id, rules)

    logger.info(
        "business_context.rules.replace",
        tenant_id=str(user.tenant_id),
        rule_count=len(rules),
        version=snapshot.version,
    )
    return _envelope(
        user.tenant_id,
        snapshot,
        yaml_text=payload.yaml,
        enabled=_load_for(user.tenant_id)["enabled"],
        updated_at=updated_at,
    )


@router.put("/rules/{rule_id}", response_model=RulesEnvelope)
async def update_rule(
    rule_id: str,
    payload: UpdateRuleRequest,
    user: AuthUser,
    db: DBSession,
) -> RulesEnvelope:
    """Patch a single rule by id.

    The body is the YAML for *that one rule*; we splice it into the
    tenant's rule list, replacing the existing entry of the same id (or
    appending if it's a new id). Returns the same envelope shape as
    ``POST /rules`` so the editor can re-render in one round trip.
    """
    await user.require_permission_db("settings:write", db)

    try:
        candidates = load_rules_from_yaml(payload.yaml)
    except RuleParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    if len(candidates) != 1:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="PUT body must contain exactly one rule",
        )
    new_rule = candidates[0]
    if new_rule.id != rule_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(f"rule id in URL ({rule_id!r}) must match rule id in body " f"({new_rule.id!r})"),
        )

    existing_yaml = _load_for(user.tenant_id)["yaml"]
    existing_rules = load_rules_from_yaml(existing_yaml) if existing_yaml else []
    by_id = {r.id: r for r in existing_rules}
    by_id[new_rule.id] = new_rule
    next_yaml = _serialise_rules(list(by_id.values()))

    updated_at = _persist_for(
        user.tenant_id,
        yaml_text=next_yaml,
        enabled=_load_for(user.tenant_id)["enabled"],
    )
    snapshot = _engine().replace(user.tenant_id, by_id.values())

    logger.info(
        "business_context.rules.update",
        tenant_id=str(user.tenant_id),
        rule_id=rule_id,
        version=snapshot.version,
    )
    return _envelope(
        user.tenant_id,
        snapshot,
        yaml_text=next_yaml,
        enabled=_load_for(user.tenant_id)["enabled"],
        updated_at=updated_at,
    )


@router.delete(
    "/rules/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def delete_rule(
    rule_id: str,
    user: AuthUser,
    db: DBSession,
) -> None:
    await user.require_permission_db("settings:write", db)

    existing_yaml = _load_for(user.tenant_id)["yaml"]
    existing_rules = load_rules_from_yaml(existing_yaml) if existing_yaml else []
    remaining = [r for r in existing_rules if r.id != rule_id]
    if len(remaining) == len(existing_rules):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"rule {rule_id!r} not found",
        )

    next_yaml = _serialise_rules(remaining)
    _persist_for(
        user.tenant_id,
        yaml_text=next_yaml,
        enabled=_load_for(user.tenant_id)["enabled"],
    )
    _engine().replace(user.tenant_id, remaining)
    logger.info(
        "business_context.rules.delete",
        tenant_id=str(user.tenant_id),
        rule_id=rule_id,
    )


@router.post("/rules/preview", response_model=PreviewResponse)
async def preview_rules(
    payload: PreviewRequest,
    user: AuthUser,
    db: DBSession,
) -> PreviewResponse:
    """Dry-run the candidate YAML against a sample of alerts.

    Doesn't persist anything; doesn't modify the engine snapshot for
    the tenant. The response is shaped so the settings page can render
    a before/after table with a one-line "X of Y alerts changed" header.
    """
    await user.require_permission_db("settings:read", db)

    try:
        rules = load_rules_from_yaml(payload.yaml)
    except RuleParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    alerts = payload.alerts
    if not alerts:
        alerts = await _fetch_sample_alerts(db, user.tenant_id, limit=50)
    if len(alerts) > _MAX_PREVIEW_ALERTS:
        alerts = alerts[:_MAX_PREVIEW_ALERTS]

    start = time.perf_counter()
    evaluations = _engine().preview_against(user.tenant_id, alerts, rules=rules)
    elapsed_ms = (time.perf_counter() - start) * 1000

    rows = [
        PreviewRow(
            alert_id=ev.alert_id,
            matched_rule_ids=ev.matched_rule_ids,
            before=ev.before,
            after=ev.after,
            suppressed=ev.suppressed,
            changed=ev.changed,
        )
        for ev in evaluations
    ]
    return PreviewResponse(
        sample_size=len(rows),
        changed_count=sum(1 for r in rows if r.changed),
        suppressed_count=sum(1 for r in rows if r.suppressed),
        elapsed_ms=round(elapsed_ms, 3),
        rows=rows,
    )


# ---------------------------------------------------------------------------
# YAML round-trip
# ---------------------------------------------------------------------------


def _condition_to_dict(cond: Any) -> dict[str, Any]:
    """Inverse of :func:`_parse_condition` — used when an analyst PUTs
    a single rule and we need to splice it back into the tenant's
    full YAML doc.
    """
    if cond.logical == "all":
        return {"all": [_condition_to_dict(c) for c in cond.children]}
    if cond.logical == "any":
        return {"any": [_condition_to_dict(c) for c in cond.children]}
    if cond.logical == "not":
        return {"not": _condition_to_dict(cond.children[0])}

    base: dict[str, Any] = {"field": cond.field, "op": cond.op}
    if cond.op not in {"exists", "not_exists"}:
        base["value"] = cond.value
    return base


def _action_to_dict(action: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if action.set_severity is not None:
        out["set_severity"] = action.set_severity
    if action.route_to is not None:
        out["route_to"] = action.route_to
    if action.tag is not None:
        out["tag"] = action.tag
    if action.suppress:
        out["suppress"] = True
    return out


def _serialise_rules(rules: list[BusinessContextRule]) -> str:
    """Render a list of parsed rules back to YAML.

    Used when an analyst does a PUT-by-id and we want to refresh the
    canonical YAML blob the editor sees on next GET. The output isn't
    the verbatim YAML the analyst typed (comments + key ordering are
    lost) — but it's structurally lossless and stable, which is what
    the editor's diff view needs.
    """
    if not rules:
        return ""
    docs = [
        {
            "id": r.id,
            "description": r.description,
            "enabled": r.enabled,
            "priority": r.priority,
            "when": _condition_to_dict(r.when),
            "then": _action_to_dict(r.then),
        }
        for r in rules
    ]
    return yaml.safe_dump({"rules": docs}, sort_keys=False)
