"""Operator-facing "what is actually running here".

``apps/docs/docs/operations/upgrades.md`` has told operators to "check
``/api/v1/system/version`` and see the same number" since the upgrade guide
was written. The route did not exist, so the documented way to confirm an
upgrade landed answered 404 — and had it existed it would have reported the
hardcoded ``0.1.0`` that every other version surface reported.

Authorization
-------------
``settings:read``. This names the build, the commit and the state of the
schema, which is deployment configuration rather than analyst work, and the
catalogue files that permission under ``admin``: it is held by ``admin``,
``platform_admin`` and ``tenant_admin``, and by no analyst role.

Note the shape — ``Annotated[AuthUser, Depends(require_permission(...))]``.
``Annotated[AuthUser, require_permission(...)]`` without ``Depends()`` is
valid Python, reads identically to a reviewer, and enforces nothing: FastAPI
honours only ``Depends``/``FieldInfo`` metadata, drops the rest, and
reinterprets the parameter as a required query parameter. Eleven routes
shipped that way.

Answering while degraded
------------------------
The schema verdict is read through ``probe_schema_current()``, which never
raises and reports ``unknown`` when it cannot establish an answer. This route
therefore returns 200 on a deployment whose database is unreachable — which
is exactly when an operator needs to know which build they are looking at.
Refusing to answer would withhold the diagnosis along with the fault.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser, require_permission
from app.core.config import settings
from app.core.version import resolve_revision
from app.services.schema_skew import probe_schema_current

router = APIRouter(prefix="/system", tags=["System"])


class SchemaMigrationState(BaseModel):
    """How the live schema compares with the migrations this build ships."""

    state: Literal["current", "skewed", "unknown"] = Field(
        description=(
            "'current' — every migration on disk is applied. 'skewed' — the two "
            "disagree; see pending and applied_not_on_disk. 'unknown' — the "
            "comparison could not be performed (no database, no tracking table, "
            "or a failed query). 'unknown' is never a pass."
        )
    )
    detail: str = Field(description="Why this verdict, in one sentence an operator can act on.")
    migrations_on_disk: int = Field(description="Migration files this build ships.")
    migrations_applied: int | None = Field(description="Rows in aisoc_schema_migrations, or null when they could not be read.")
    latest_applied: str | None = Field(description="Applied-migration high-water mark: the last applied migration in apply order.")
    pending: list[str] = Field(
        default_factory=list,
        description="On disk and not applied — new code against an old schema.",
    )
    applied_not_on_disk: list[str] = Field(
        default_factory=list,
        description="Applied but absent from this build — old code against a newer schema.",
    )


class SystemVersion(BaseModel):
    version: str = Field(
        description=(
            "The running release. Stamped into the image at build time; read from the "
            "repo-root VERSION file on a source checkout; the literal string 'unknown' "
            "when neither declared one. Never a placeholder version number."
        )
    )
    revision: str | None = Field(description="The commit this build came from, or null when the build was not stamped.")
    environment: str = Field(description="The deployment's configured environment name.")
    schema_migrations: SchemaMigrationState


@router.get("/version", response_model=SystemVersion)
async def get_system_version(
    user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
) -> SystemVersion:
    """Report the running build and whether its schema matches it."""
    skew = await probe_schema_current()
    return SystemVersion(
        version=settings.VERSION,
        revision=resolve_revision(),
        environment=settings.ENVIRONMENT,
        schema_migrations=SchemaMigrationState(
            state=skew.state,
            detail=skew.detail,
            migrations_on_disk=skew.on_disk_count,
            migrations_applied=skew.applied_count,
            latest_applied=skew.latest_applied,
            pending=skew.pending,
            applied_not_on_disk=skew.applied_not_on_disk,
        ),
    )
