"""A tenant's own answer to "may AiSOC sweep my history, and how much".

Migration 070 creates `retro_hunt_settings` with `enabled` defaulting to FALSE
under a comment reading "Off until a tenant asks". Until this module existed
there was nowhere to ask: no route and no console surface touched the table, so
the only way to opt a tenant in was an UPDATE issued against the database by
hand. A feature that needs a direct SQL statement to enable is not a feature a
customer has.

Two switches, deliberately
--------------------------
`RETRO_HUNT_ENABLED` is the *operator's* switch and decides whether the
consumer runs at all. `enabled` here is the *tenant's*, and both must be on
before a sweep touches anything. They are separate because they answer
different questions: the operator is deciding whether this deployment spends
the compute, and the tenant is deciding whether its own history may be read
back over. Neither can speak for the other.

`include_federated` is split out for the same reason one layer down. A sweep
of AiSOC's own lake costs the customer nothing; a sweep that fans out into
their connected SIEMs may bill them per query.
"""

from __future__ import annotations

from typing import Annotated

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/retro-hunts", tags=["retro_hunts"])

#: The column CHECK is `BETWEEN 1 AND 365` and the sweep service clamps to the
#: same ceiling. Stating it here too means a caller gets a 422 naming the bound
#: rather than a 500 out of Postgres.
MIN_LOOKBACK_DAYS = 1
MAX_LOOKBACK_DAYS = 365


class RetroHuntSettingsOut(BaseModel):
    """What this tenant has agreed to, and what its budget has been spent on."""

    enabled: bool
    lookback_days: int
    include_federated: bool
    max_sweeps_per_hour: int
    max_sweeps_per_day: int

    sweeps_this_hour: int
    sweeps_today: int
    sweeps_skipped_budget: int
    """Sweeps declined because a budget was exhausted. Surfaced because a
    tenant whose budget is too small sees *silence*, which is indistinguishable
    from a feed with nothing to report."""


class RetroHuntSettingsIn(BaseModel):
    enabled: bool = Field(description="Whether AiSOC may sweep this tenant's history at all.")
    lookback_days: int = Field(
        default=30,
        ge=MIN_LOOKBACK_DAYS,
        le=MAX_LOOKBACK_DAYS,
        description="How far back a sweep looks. Bounded so no settings row can express 'scan everything'.",
    )
    include_federated: bool = Field(
        default=True,
        description=(
            "Whether to go beyond AiSOC's own lake into connected SIEMs. Separate from `enabled` "
            "because it is a separate cost: a lake sweep is free to you and a SIEM sweep may not be."
        ),
    )


_SELECT = text(
    """
    SELECT enabled, lookback_days, include_federated,
           max_sweeps_per_hour, max_sweeps_per_day,
           sweeps_this_hour, sweeps_today, sweeps_skipped_budget
      FROM retro_hunt_settings
     WHERE tenant_id = CAST(:tenant_id AS uuid)
    """
)

#: Insert-or-update in one statement. A tenant that has never opted in has no
#: row at all, so a plain UPDATE would silently affect nothing and report
#: success -- which is exactly the shape of defect this fix pass is about.
_UPSERT = text(
    """
    INSERT INTO retro_hunt_settings (tenant_id, enabled, lookback_days, include_federated)
    VALUES (CAST(:tenant_id AS uuid), :enabled, :lookback_days, :include_federated)
    ON CONFLICT (tenant_id) DO UPDATE
       SET enabled           = EXCLUDED.enabled,
           lookback_days     = EXCLUDED.lookback_days,
           include_federated = EXCLUDED.include_federated,
           updated_at        = now()
    RETURNING enabled, lookback_days, include_federated,
              max_sweeps_per_hour, max_sweeps_per_day,
              sweeps_this_hour, sweeps_today, sweeps_skipped_budget
    """
)


def _defaults() -> RetroHuntSettingsOut:
    """What a tenant with no row has agreed to, which is nothing.

    Returned rather than a 404 because "you have not opted in" is a state with
    a correct answer, and a 404 would read as "retro-hunts do not exist here".
    The values mirror the column defaults in migration 070.
    """
    return RetroHuntSettingsOut(
        enabled=False,
        lookback_days=30,
        include_federated=True,
        max_sweeps_per_hour=120,
        max_sweeps_per_day=1000,
        sweeps_this_hour=0,
        sweeps_today=0,
        sweeps_skipped_budget=0,
    )


@router.get(
    "/settings",
    response_model=RetroHuntSettingsOut,
    summary="This tenant's retro-hunt opt-in and budget",
)
async def get_retro_hunt_settings(
    db: TenantDBSession,
    user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
) -> RetroHuntSettingsOut:
    row = (await db.execute(_SELECT, {"tenant_id": str(user.tenant_id)})).mappings().first()
    if row is None:
        return _defaults()
    return RetroHuntSettingsOut(**dict(row))


@router.put(
    "/settings",
    response_model=RetroHuntSettingsOut,
    summary="Opt this tenant in or out of retro-hunt sweeps",
)
async def put_retro_hunt_settings(
    body: RetroHuntSettingsIn,
    db: TenantDBSession,
    user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
) -> RetroHuntSettingsOut:
    """Write the tenant's half of the switch.

    The budget columns are deliberately not writable here. They are the
    operator's ceiling on what one tenant can cost the deployment, and a tenant
    that could raise its own ceiling would not have one.
    """
    row = (
        (
            await db.execute(
                _UPSERT,
                {
                    "tenant_id": str(user.tenant_id),
                    "enabled": body.enabled,
                    "lookback_days": body.lookback_days,
                    "include_federated": body.include_federated,
                },
            )
        )
        .mappings()
        .first()
    )
    await db.commit()

    assert row is not None  # RETURNING on an upsert always yields a row
    logger.info(
        "retro_hunts.settings_updated",
        tenant_id=str(user.tenant_id),
        enabled=bool(body.enabled),
        lookback_days=int(body.lookback_days),
        include_federated=bool(body.include_federated),
    )
    return RetroHuntSettingsOut(**dict(row))


__all__ = ["router", "RetroHuntSettingsIn", "RetroHuntSettingsOut"]
