"""L0–L4 auto-remediation maturity tier endpoints.

Authorization
-------------
These routes are the tenant's autonomous-response control plane, not a
preference surface. ``remediation_maturity.maturity_tier`` and
``action_overrides`` are read by ``services/actions`` when it grades a
response action: ``force_auto`` becomes ``AutonomyMode.AUTO`` with an L4 tier
label, ``block`` becomes ``AutonomyMode.BLOCKED``, and a
``remediation_whitelist`` row is the artefact that lets L4 execute a high
blast-radius verb unattended.

Every route here authenticated and none of them authorized, so a ``viewer``
— a role holding five read permissions and nothing else — could raise the
tier, pre-approve a destructive verb against every target with no expiry, or
suppress a containment verb during an incident (GHSA-wj5c-88hg-5926).

Writes therefore require ``settings:write``, which only ``tenant_admin`` and
the wildcard roles hold. ``actions:execute`` was the other candidate and is
the wrong one: ``soc_lead`` and ``soc_analyst`` hold it, so it would let the
same principal who dispatches an action pre-approve its own future
dispatches, which is the separation of duties the approval path already
enforces. Reads require ``actions:read``, which every human role holds — an
analyst can see the posture they are working under — but ``api_service``
does not, so a machine key must be scoped for it deliberately.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import CurrentUser, require_permission
from app.db.database import get_db
from app.models.remediation import RemediationGateLog, RemediationMaturity, RemediationWhitelist

router = APIRouter(prefix="/remediation", tags=["remediation"])

#: Reading the tenant's response posture. Held by every human role.
_READ = "actions:read"

#: Changing it. Held by ``tenant_admin`` and the wildcard roles only.
_WRITE = "settings:write"

#: The only flags ``services/actions`` reads out of an action override
#: (``live_actions/dispatcher.py::_govern``). Anything else written here is
#: dead weight in a security-relevant row, so it is refused rather than stored.
_OVERRIDE_FLAGS = frozenset({"block", "force_auto"})

#: The shape of a response verb. Deliberately a shape rather than an import of
#: ``ActionType`` from ``services/actions``: the API service does not depend on
#: that package, and adding the import to validate a vocabulary would make this
#: service fail to start wherever the package is absent.
_ACTION_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


#: The two access levels, as FastAPI dependencies. Declared once so the
#: permission a route enforces is a property of the alias rather than repeated
#: at each signature, and so `require_permission` is called at import rather
#: than in an argument default.
ReadUser = Annotated[CurrentUser, Depends(require_permission(_READ))]
WriteUser = Annotated[CurrentUser, Depends(require_permission(_WRITE))]


def _isoformat(value: Any) -> Any:
    """Render a timestamp column as the ``str`` these schemas declare.

    The columns are ``DateTime`` and the schemas declare ``str``; Pydantic v2
    does not coerce between the two, so every response below raised
    ``ResponseValidationError`` *after* its handler had already committed —
    the write landed and the caller saw a 500. Normalising here rather than
    retyping the fields keeps the published OpenAPI schema unchanged.
    """
    return value.isoformat() if isinstance(value, datetime) else value


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class MaturityConfig(BaseModel):
    maturity_tier: int = Field(..., ge=0, le=4)
    action_overrides: dict[str, Any] = Field(default_factory=dict)

    @field_validator("action_overrides")
    @classmethod
    def _only_known_flags(cls, value: dict[str, Any]) -> dict[str, Any]:
        for action_type, override in value.items():
            if not _ACTION_TYPE_RE.match(action_type):
                raise ValueError(f"'{action_type}' is not a response action type")
            if not isinstance(override, dict):
                raise ValueError(f"override for '{action_type}' must be an object")
            unknown = set(override) - _OVERRIDE_FLAGS
            if unknown:
                raise ValueError(
                    f"override for '{action_type}' has unknown flag(s) {sorted(unknown)}; known flags are {sorted(_OVERRIDE_FLAGS)}"
                )
            for flag, flag_value in override.items():
                if not isinstance(flag_value, bool):
                    raise ValueError(f"'{action_type}.{flag}' must be true or false")
        return value


class MaturityOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    maturity_tier: int
    action_overrides: dict[str, Any]
    changed_at: str
    created_at: str

    model_config = ConfigDict(from_attributes=True)

    _normalise_timestamps = field_validator("changed_at", "created_at", mode="before")(_isoformat)


class GateLogOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    action_id: uuid.UUID
    action_type: str
    blast_radius: str
    maturity_tier: int
    decision: str
    rationale: str | None
    actor: str
    created_at: str

    model_config = ConfigDict(from_attributes=True)

    _normalise_timestamps = field_validator("created_at", mode="before")(_isoformat)


class WhitelistCreate(BaseModel):
    action_type: str
    blast_radius: str
    constraints: dict[str, Any] = Field(default_factory=dict)
    expires_at: datetime | None = None


class WhitelistOut(WhitelistCreate):
    id: uuid.UUID
    tenant_id: uuid.UUID
    approved_by: uuid.UUID | None
    created_at: str

    model_config = ConfigDict(from_attributes=True)

    _normalise_timestamps = field_validator("created_at", mode="before")(_isoformat)


# ---------------------------------------------------------------------------
# Maturity config endpoints
# ---------------------------------------------------------------------------


@router.get("/config", response_model=MaturityOut)
async def get_maturity_config(
    current_user: ReadUser,
    db: AsyncSession = Depends(get_db),
) -> RemediationMaturity:
    result = await db.execute(select(RemediationMaturity).where(RemediationMaturity.tenant_id == current_user.tenant_id))
    config = result.scalar_one_or_none()
    if not config:
        config = RemediationMaturity(
            tenant_id=current_user.tenant_id,
            maturity_tier=0,
        )
        db.add(config)
        await db.commit()
        await db.refresh(config)
    return config


@router.put("/config", response_model=MaturityOut)
async def update_maturity_config(
    body: MaturityConfig,
    current_user: WriteUser,
    db: AsyncSession = Depends(get_db),
) -> RemediationMaturity:
    result = await db.execute(select(RemediationMaturity).where(RemediationMaturity.tenant_id == current_user.tenant_id))
    config = result.scalar_one_or_none()
    if not config:
        config = RemediationMaturity(tenant_id=current_user.tenant_id)
        db.add(config)

    config.maturity_tier = body.maturity_tier  # type: ignore[assignment]
    config.action_overrides = body.action_overrides  # type: ignore[assignment]
    config.changed_by = current_user.user_id  # type: ignore[assignment]
    config.changed_at = datetime.now(UTC)  # type: ignore[assignment]
    await db.commit()
    await db.refresh(config)
    return config


# ---------------------------------------------------------------------------
# Gate log (audit trail)
# ---------------------------------------------------------------------------


@router.get("/gate-log", response_model=list[GateLogOut])
async def list_gate_log(
    current_user: ReadUser,
    decision: str | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[RemediationGateLog]:
    q = select(RemediationGateLog).where(RemediationGateLog.tenant_id == current_user.tenant_id)
    if decision:
        q = q.where(RemediationGateLog.decision == decision)
    q = q.order_by(RemediationGateLog.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Whitelist endpoints
# ---------------------------------------------------------------------------


@router.get("/whitelist", response_model=list[WhitelistOut])
async def list_whitelist(
    current_user: ReadUser,
    db: AsyncSession = Depends(get_db),
) -> list[RemediationWhitelist]:
    result = await db.execute(select(RemediationWhitelist).where(RemediationWhitelist.tenant_id == current_user.tenant_id))
    return list(result.scalars().all())


@router.post("/whitelist", response_model=WhitelistOut, status_code=status.HTTP_201_CREATED)
async def add_to_whitelist(
    body: WhitelistCreate,
    current_user: WriteUser,
    db: AsyncSession = Depends(get_db),
) -> RemediationWhitelist:
    entry = RemediationWhitelist(
        **body.model_dump(),
        tenant_id=current_user.tenant_id,
        approved_by=current_user.user_id,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry


@router.delete("/whitelist/{entry_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def remove_from_whitelist(
    entry_id: uuid.UUID,
    current_user: WriteUser,
    db: AsyncSession = Depends(get_db),
) -> None:
    entry = await db.get(RemediationWhitelist, entry_id)
    if not entry or entry.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Whitelist entry not found")
    await db.delete(entry)
    await db.commit()
