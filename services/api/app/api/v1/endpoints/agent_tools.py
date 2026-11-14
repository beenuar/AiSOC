"""The typed surface an investigation agent reaches a customer's tools through.

Gap-closure Phase 4.1, 4.2 and 4.3.

Three routes, and the shape of each is a consequence of one rule: a model
supplies structured arguments and this service owns everything else. It owns
which SIEM, which field, which vendor, which credential and which tenant. The
model owns an indicator type, a value and a window.

``GET /agent-tools/backends``
    What this tenant can actually be asked. An agent binds its toolset from
    this, so a tenant with no CrowdStrike is never offered a CrowdStrike tool.

``POST /agent-tools/siem-search``
    One indicator, across every federated-capable SIEM the tenant has.

``POST /agent-tools/vendor-read``
    One read-only verb against the tenant's EDR, IdP or cloud audit trail.

Tenant comes from the credential
--------------------------------
Every route reads ``user.tenant_id``. There is no tenant field on any request
model, no tenant query parameter and no header that is honoured. A tool
argument named ``tenant_id`` would be the single most valuable thing on this
surface to prompt-inject, and the agents service authenticates with its own
API key precisely so the tenant is a property of the credential rather than of
the conversation.

Why ``actions:read`` rather than ``actions:execute``
---------------------------------------------------
``actions:execute`` gates the dry-run preview of a state-changing action.
These verbs change nothing, and the capability contract separates looking from
acting with its own ``actions:investigate`` permission for exactly this
reason: bundling them means anyone who can look can also act. ``actions:read``
is this service's closest analogue and is the narrower of the two.
"""

from __future__ import annotations

from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.db.clickhouse import (
    LakeQueryError,
    LakeQueryNotConfiguredError,
    LakeQueryTimeoutError,
    execute_lake_query,
)
from app.services import actions_client
from app.services.agent_tools import siem_search, vendor_reads
from app.services.agent_tools.indicators import INDICATOR_TYPES, IndicatorTypeError
from app.services.retro_hunt import hunt_plan_sql

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/agent-tools", tags=["agent-tools"])


# --------------------------------------------------------------------- models


class SiemSearchRequest(BaseModel):
    """A structured query. Deliberately not a query.

    There is no ``query`` field, no ``free_text`` field and no ``field``
    field, and their absence is the contract rather than an omission.
    ``indicator_type`` is validated against a closed set and ``value``
    against the shape that type requires, so a model cannot pass query text
    by claiming it is an indicator.
    """

    indicator_type: str = Field(description="One of the types GET /agent-tools/backends publishes.")
    value: str = Field(min_length=1, max_length=2048)
    since_hours: int = Field(default=24, ge=1, le=7 * 24)
    limit: int = Field(default=siem_search.MAX_ROWS, ge=1, le=siem_search.MAX_ROWS)


class VendorReadRequest(BaseModel):
    """One read-only verb against one entity.

    ``params`` is filtered against a per-verb allowlist before it travels,
    because by the time it reaches the actions service it is the same
    dictionary that carries the decrypted credential. An unfiltered
    pass-through would let a caller supply their own vendor credential and
    have the read run somewhere else entirely.
    """

    capability: str
    target: str = Field(min_length=1, max_length=512)
    vendor: str = Field(default="", max_length=64)
    params: dict[str, Any] = Field(default_factory=dict)


# ------------------------------------------------------------------- backends


@router.get("/backends", summary="Which agent tools this tenant has a backend for")
async def list_backends(
    user: Annotated[AuthUser, Depends(require_permission("connectors:read"))],
    db: DBSession,
) -> dict[str, Any]:
    """Enumerate what can be asked, so nothing else is advertised.

    ``registry_reachable`` is part of the contract. A caller that reads an
    unreachable action registry as "this tenant has no vendor tools" will
    bind a smaller toolset and then investigate confidently without it, which
    is the worst of the three outcomes. Reported as unknown instead.
    """
    siem_backends: list[dict[str, Any]] = []
    if siem_search.feature_enabled():
        from app.api.v1.endpoints.federated import _fetch_target_connectors

        for connector in await _fetch_target_connectors(db, user.tenant_id, requested_ids=None):
            siem_backends.append({"source": connector.connector_type, "name": connector.name})

    reads: list[dict[str, Any]] = []
    registry_reachable = True
    registry_error = ""
    try:
        reads = [entry.as_dict() for entry in await vendor_reads.available_reads(db, tenant_id=user.tenant_id)]
    except actions_client.ActionsServiceError as exc:
        registry_reachable = False
        registry_error = exc.upstream_detail
        logger.warning("agent_tools.backends.registry_unreachable", tenant_id=str(user.tenant_id))

    return {
        "siem_search": {
            "enabled": siem_search.feature_enabled(),
            "backends": siem_backends,
            "indicator_types": {name: spec.description for name, spec in sorted(INDICATOR_TYPES.items())},
        },
        "vendor_reads": reads,
        "registry_reachable": registry_reachable,
        "registry_error": registry_error,
    }


# ---------------------------------------------------------------- siem search


@router.post("/siem-search", summary="Search every configured SIEM for one indicator")
async def search_siem(
    request: SiemSearchRequest,
    user: Annotated[AuthUser, Depends(require_permission("connectors:read"))],
    db: DBSession,
) -> dict[str, Any]:
    """Run one typed indicator search across the tenant's SIEMs.

    The response separates three facts that an agent must not conflate: rows
    that matched, sources that answered, and sources that could not be
    searched. ``outcome`` is the single field a caller branches on.
    """
    if not siem_search.feature_enabled():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="federated search is disabled on this deployment (AISOC_FEATURE_FED_SEARCH=false)",
        )

    try:
        result = await siem_search.search_indicator(
            db,
            tenant_id=user.tenant_id,
            indicator_type=request.indicator_type,
            value=request.value,
            since_hours=request.since_hours,
            limit=request.limit,
            actor=user.email,
        )
    except IndicatorTypeError as exc:
        # A caller error, and never folded into an empty result: the caller
        # has to be able to tell "your query was wrong" from "nothing
        # matched", because only one of those is evidence.
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    sources = [source.as_dict() for source in result.sources]
    if not sources:
        outcome = "no_backend"
    elif not result.any_source_answered:
        outcome = "could_not_check"
    elif result.any_source_failed:
        outcome = "partial"
    else:
        outcome = "ok"

    return {
        "outcome": outcome,
        "indicator_type": request.indicator_type,
        "value": request.value,
        "since_hours": request.since_hours,
        "row_count": len(result.rows),
        "rows": result.rows,
        "sources": sources,
        "truncated_rows": result.truncated_rows,
        "truncated_bytes": result.truncated_bytes,
    }


# --------------------------------------------------------------- vendor reads


@router.post("/vendor-read", summary="Run one read-only vendor verb")
async def vendor_read(
    request: VendorReadRequest,
    user: Annotated[AuthUser, Depends(require_permission("actions:read"))],
    db: DBSession,
) -> dict[str, Any]:
    """Dispatch one read verb, under the capability contract.

    Refusals are 422 rather than a result with ``executed: false``, so a
    caller cannot mistake "this verb is not allowed here" for "the vendor had
    nothing". The one thing that is *not* a refusal is a vendor failure: that
    comes back 200 with ``executed: false`` and a reason, because the caller
    has to render it to a model as "could not check".
    """
    try:
        report = await vendor_reads.run_read(
            db,
            tenant_id=user.tenant_id,
            capability=request.capability,
            target=request.target,
            params=request.params,
            vendor_id=request.vendor,
            actor=user.email,
        )
    except vendor_reads.VendorReadError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    payload = report.as_dict()
    # `executed` is the only field that means a vendor was touched, and it is
    # taken from the report rather than derived from the status here. The
    # playbook dispatch module sets it explicitly at every construction site
    # precisely so a new status cannot inherit "a vendor answered".
    payload["executed"] = report.executed
    return payload


# ------------------------------------------------------------- hunt plan


class HuntPlanClause(BaseModel):
    """One predicate of a hunting agent's plan.

    Three typed strings and nothing else. There is no property here that can
    carry a query, a fragment of one, or free text, which is the property
    ``scripts/check_hunt_agent_boundary.py`` reads this model to check. The
    field and operator are validated against the closed sets in
    ``app.services.retro_hunt.hunt_plan_sql`` before anything is compiled.
    """

    field: str = Field(..., max_length=64)
    operator: str = Field(..., max_length=16)
    value: str = Field(..., max_length=512)


class HuntPlanExecuteRequest(BaseModel):
    clauses: list[HuntPlanClause] = Field(..., min_length=1, max_length=7)
    lookback_hours: int = Field(default=168, ge=1, le=2160)
    limit: int = Field(default=hunt_plan_sql.MAX_ROWS, ge=1, le=hunt_plan_sql.MAX_ROWS)


@router.post("/hunt-plan/execute", summary="Run a hunting agent's structured plan against the event lake")
async def execute_hunt_plan(
    request: HuntPlanExecuteRequest,
    # `lake:query`, the same permission the operator-facing lake API requires,
    # because this reads the same warehouse. Not a new permission: one that no
    # role grants makes the route a silent 403 on every deployment, which is
    # the class of defect this program keeps finding rather than adding.
    user: Annotated[AuthUser, Depends(require_permission("lake:query"))],
) -> dict[str, Any]:
    """Compile a validated plan and run it, tenant-scoped.

    The tenant comes from the credential, never from the request, which is why
    there is no tenant field on the model above. An unreachable lake is
    reported as ``available: false`` with a reason rather than as zero rows:
    an agent that reads the second as the first concludes an estate is clean
    on evidence nobody gathered.
    """
    try:
        compiled = hunt_plan_sql.compile_plan(
            [clause.model_dump() for clause in request.clauses],
            tenant_id=str(user.tenant_id),
            lookback_hours=request.lookback_hours,
            limit=request.limit,
        )
    except hunt_plan_sql.HuntPlanCompileError as exc:
        # A caller error the model can fix, surfaced verbatim so it can
        # correct the clause rather than concluding the data is absent.
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    try:
        result = await execute_lake_query(
            compiled.sql,
            params=compiled.params,
            timeout_seconds=30.0,
            extra_settings={"max_bytes_to_read": 8 * 1024 * 1024 * 1024},
        )
    except LakeQueryNotConfiguredError:
        return {
            "available": False,
            "reason": "No event lake is configured on this deployment, so the hunt was NOT run. This is not a result.",
        }
    except LakeQueryTimeoutError:
        return {
            "available": False,
            "reason": "The hunt exceeded its time budget, so the history was NOT fully searched. This is not a result.",
        }
    except LakeQueryError:
        return {
            "available": False,
            "reason": "The event lake refused or failed the hunt, so the history was NOT searched. This is not a result.",
        }

    rows = [dict(zip(result.columns, row, strict=False)) for row in result.rows]
    return {
        "available": True,
        "row_count": len(rows),
        "rows": rows,
        "fields_searched": list(compiled.fields_searched),
        "lookback_hours": request.lookback_hours,
        "truncated": len(rows) >= request.limit,
    }
