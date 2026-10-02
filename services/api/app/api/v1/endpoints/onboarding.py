"""What a new tenant still has to do, and one button that gives them data.

Why the console needs this
---------------------------
A brand-new operator signed in and landed on `/dashboard`: every tile
zero, every panel an honest empty state, and no indication of what to do
next. The empty states were correct — that work is done — but correct and
*useful* are different things, and "0 connected sources" does not tell
anyone where the button is.

`GET /status` answers "what is set up and what is not" from the database
rather than from a flag, so it stays true if somebody connects a source
through the API, or deletes one, or arrives at a tenant that was
onboarded months ago.

`POST /sample-data` is the other half of the answer. An evaluator who has
not yet got credentials for their EDR still needs to see the product do
something, and the honest way to give them that is to run the real
pipeline rather than to insert rows — see `app/services/sample_data.py`
for why that distinction matters.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.services import sample_data

router = APIRouter()


class SetupStep(BaseModel):
    """One thing a tenant has or has not done."""

    key: str
    label: str
    done: bool
    #: What this unlocks, in the operator's terms rather than the
    #: product's. A checklist that does not say why is a chore list.
    why: str
    #: Where to go. Null when the step cannot be done from the console.
    href: str | None = None
    detail: str | None = None


class OnboardingStatus(BaseModel):
    first_run: bool = Field(
        description=(
            "True when this tenant has no connectors and no alerts. The console "
            "routes a first-run tenant to the setup wizard rather than to an "
            "empty dashboard."
        )
    )
    steps: list[SetupStep]
    connectors: int
    alerts: int
    sample_data_loaded: bool


class SampleDataResponse(BaseModel):
    accepted: int
    rejected: int
    scenarios: list[dict[str, Any]]
    note: str


async def _count(db: Any, sql: str, **params: Any) -> int:
    try:
        result = await db.execute(text(sql), params)
        return int(result.scalar() or 0)
    except Exception:  # noqa: BLE001
        # A table that does not exist yet on a half-migrated deployment
        # must not 500 the wizard that is trying to help the operator fix
        # it. Zero is also the honest answer: nothing is there.
        return 0


@router.get("/status", response_model=OnboardingStatus)
async def onboarding_status(
    user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: TenantDBSession,
) -> OnboardingStatus:
    """What this tenant has set up, derived from its data.

    Derived rather than stored. A `tenant.onboarded` boolean drifts the
    moment somebody connects a source through the API, deletes their last
    connector, or restores a backup — and a wizard that insists you are
    finished when your estate is empty is worse than no wizard.
    """
    tenant_id = str(user.tenant_id)

    connectors = await _count(
        db,
        "SELECT COUNT(*) FROM connectors WHERE tenant_id = CAST(:t AS uuid)",
        t=tenant_id,
    )
    alerts = await _count(
        db,
        "SELECT COUNT(*) FROM alerts WHERE tenant_id = CAST(:t AS uuid)",
        t=tenant_id,
    )
    sample_alerts = await _count(
        db,
        """
        SELECT COUNT(*) FROM alerts
         WHERE tenant_id = CAST(:t AS uuid)
           AND connector_type = :c
        """,
        t=tenant_id,
        c=sample_data.SAMPLE_CONNECTOR,
    )
    users = await _count(
        db,
        "SELECT COUNT(*) FROM users WHERE tenant_id = CAST(:t AS uuid)",
        t=tenant_id,
    )

    # A connector that is only *configured* is not a connector that is
    # working, so "data arriving" is a separate step. Conflating them is
    # how an operator ends up believing they are done while nothing has
    # ever been polled.
    real_alerts = alerts - sample_alerts

    steps = [
        SetupStep(
            key="admin",
            label="Administrator account",
            done=users > 0,
            why="You are signed in, so this one is already true.",
            href=None,
        ),
        SetupStep(
            key="connector",
            label="Connect a data source",
            done=connectors > 0,
            why=("AiSOC triages what your tools already see. Until something is connected there is nothing for it to work on."),
            href="/onboarding",
            detail=(f"{connectors} connected" if connectors else "Nothing connected yet"),
        ),
        SetupStep(
            key="data",
            label="Receive your first alert",
            done=real_alerts > 0,
            why=(
                "Proves the whole path end to end: your tool, ingest, correlation "
                "and triage. A connector that saves but never polls looks identical "
                "until an alert arrives."
            ),
            href="/alerts",
            detail=(f"{real_alerts} from your own sources" if real_alerts else "No alerts from a connected source yet"),
        ),
        SetupStep(
            key="try",
            label="Or try it with sample data",
            done=sample_alerts > 0,
            why=(
                "Pushes five scenarios through the same ingest endpoint a real "
                "connector uses, so you can see triage work before you have "
                "credentials for anything."
            ),
            href=None,
            detail=(f"{sample_alerts} sample alert(s) loaded" if sample_alerts else "Nothing loaded"),
        ),
    ]

    return OnboardingStatus(
        # Sample data deliberately does **not** clear first-run: somebody
        # who has only looked at samples still has nothing connected, and
        # telling them they are set up would be the fabrication this
        # product spends most of its effort avoiding.
        first_run=connectors == 0 and real_alerts == 0,
        steps=steps,
        connectors=connectors,
        alerts=alerts,
        sample_data_loaded=sample_alerts > 0,
    )


@router.post(
    "/sample-data",
    response_model=SampleDataResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def load_sample_data(
    user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
    db: TenantDBSession,
) -> SampleDataResponse:
    """Push five labelled scenarios through the real pipeline.

    Refuses on a tenant that already has real alerts. Sample rows in a
    live queue are indistinguishable from real ones at a glance, and an
    analyst who dismisses a genuine alert because they assumed it was
    sample data is a worse outcome than an evaluator having to use a
    second tenant.
    """
    tenant_id = str(user.tenant_id)

    real = await _count(
        db,
        """
        SELECT COUNT(*) FROM alerts
         WHERE tenant_id = CAST(:t AS uuid)
           AND (connector_type IS NULL OR connector_type <> :c)
        """,
        t=tenant_id,
        c=sample_data.SAMPLE_CONNECTOR,
    )
    if real > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"This tenant already has {real} alert(s) from real sources. Sample "
                "data is not loaded into an estate that is already working, because "
                "a sample alert sitting in a live queue is indistinguishable from a "
                "real one at a glance."
            ),
        )

    try:
        uuid.UUID(tenant_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The authenticated session carries no usable tenant.",
        ) from exc

    try:
        result = await sample_data.load(tenant_id=tenant_id)
    except sample_data.SampleDataError as exc:
        # 502, not 500: the API is fine and something it depends on is
        # not, and the message says which.
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    return SampleDataResponse(**result)
