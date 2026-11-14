"""War-room routes: one action opens a channel, a sweep keeps it current.

Depth plan 9.4.

* ``POST /war-rooms/cases/{case_id}``   open a channel for this case
* ``GET  /war-rooms/cases/{case_id}``   what rooms this case has, and their health
* ``POST /war-rooms/{id}/sync``         post whatever the room has not been told
* ``POST /war-rooms/{id}/close``        stop mirroring; the channel is left alone
* ``POST /war-rooms/{id}/decision``     **bot only** — a decision taken in chat

Why the decision route is service-token only, with no session fallback
----------------------------------------------------------------------
It is reached by the chat bot, which has already verified the vendor's
signature on the interaction. This service cannot re-verify it: it holds no
workspace secret. So the bot is trusted exactly as far as the shared
internal token, and the blast radius of that trust is the four verbs in
``CHANNEL_DECISIONS`` — none of which closes a case. A console session has
no business on this route, and accepting one would mean two paths to the
same write with different evidence behind them.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.alert_writeback import service_token_valid
from app.db.rls import TenantDBSession, set_rls_context
from app.services.audit import emit_audit
from app.services.war_room import (
    PROVIDERS,
    WarRoomError,
    apply_channel_decision,
    open_war_room,
    sync_war_room,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/war-rooms", tags=["war-rooms"])


class OpenWarRoomRequest(BaseModel):
    provider: str = Field(default="slack", description="slack | teams")
    #: Vendor user ids to invite. The caller supplies them because only the
    #: console knows which AiSOC user maps to which workspace member, and
    #: guessing from an email address is how a bot invites the wrong person.
    invite: list[str] = Field(default_factory=list, max_length=100)


class WarRoomModel(BaseModel):
    id: str
    case_id: str
    provider: str
    channel_id: str
    channel_name: str
    channel_url: str
    state: str
    opened_by: str
    #: ``None`` means the sweep has never run for this room, which is a
    #: different fact from "ran and had nothing to say". The console renders
    #: them differently.
    last_synced_at: str | None
    #: Empty on success. A war room that has silently stopped mirroring is
    #: worse than one that was never opened, so the reason is surfaced.
    last_error: str


class SyncResult(BaseModel):
    posted: int
    error: str | None


class ChannelDecisionRequest(BaseModel):
    decision: str
    actor: str = Field(default="", max_length=200)
    note: str = Field(default="", max_length=1_000)


def _model(row: Any) -> WarRoomModel:
    return WarRoomModel(
        id=str(row["id"]),
        case_id=str(row["case_id"]),
        provider=row["provider"],
        channel_id=row["channel_id"],
        channel_name=row["channel_name"],
        channel_url=row["channel_url"],
        state=row["state"],
        opened_by=row["opened_by"],
        last_synced_at=row["last_synced_at"].isoformat() if row["last_synced_at"] else None,
        last_error=row["last_error"],
    )


@router.post("/cases/{case_id}", response_model=WarRoomModel, status_code=status.HTTP_201_CREATED)
async def open_for_case(
    case_id: uuid.UUID,
    body: OpenWarRoomRequest,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("cases:write"))],
) -> WarRoomModel:
    """One action: create the channel, invite, post the header, record it.

    Fails loudly. The analyst pressed a button and is entitled to know when
    it did not work — a 202 "we'll try" here would be the toast-only control
    this console is not allowed to ship.
    """
    if body.provider not in PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"provider must be one of {list(PROVIDERS)}",
        )
    actor = current_user.api_key_prefix or current_user.email
    try:
        result = await open_war_room(
            db,
            tenant_id=current_user.tenant_id,
            case_id=case_id,
            provider=body.provider,
            opened_by=actor,
            invite=body.invite,
        )
    except WarRoomError as exc:
        # 502 rather than 500: the failure is a downstream one and the text
        # names which downstream. An operator reading "the slack bot is not
        # configured" knows what to do; "internal server error" does not.
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    if result["created"]:
        await emit_audit(
            db=db,
            tenant_id=current_user.tenant_id,
            actor_id=current_user.user_id,
            actor_email=current_user.email,
            api_key_prefix=getattr(current_user, "api_key_prefix", None),
            action="war_room:open",
            resource="case",
            resource_id=str(case_id),
            changes={"provider": body.provider, "channel_id": result["war_room"]["channel_id"]},
            request=request,
        )
    await db.commit()
    return _model(result["war_room"])


@router.get("/cases/{case_id}", response_model=list[WarRoomModel])
async def list_for_case(
    case_id: uuid.UUID,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("cases:read"))],
) -> list[WarRoomModel]:
    rows = (
        (
            await db.execute(
                text(
                    "SELECT * FROM aisoc_case_war_rooms WHERE tenant_id = :tenant_id AND case_id = :case_id ORDER BY created_at DESC"
                ).bindparams(tenant_id=current_user.tenant_id, case_id=case_id)
            )
        )
        .mappings()
        .all()
    )
    return [_model(row) for row in rows]


@router.post("/{war_room_id}/sync", response_model=SyncResult)
async def sync(
    war_room_id: uuid.UUID,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("cases:write"))],
) -> SyncResult:
    row = (
        (
            await db.execute(
                text("SELECT * FROM aisoc_case_war_rooms WHERE id = :id AND tenant_id = :tenant_id").bindparams(
                    id=war_room_id, tenant_id=current_user.tenant_id
                )
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such war room")
    result = await sync_war_room(db, tenant_id=current_user.tenant_id, war_room=dict(row))
    await db.commit()
    return SyncResult(posted=result["posted"], error=result["error"])


@router.post("/{war_room_id}/close", response_model=WarRoomModel)
async def close(
    war_room_id: uuid.UUID,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("cases:write"))],
) -> WarRoomModel:
    """Stop mirroring. The channel itself is left alone, deliberately.

    Archiving somebody's channel from a console button is a bigger action
    than it looks: the transcript is often the incident's own record and the
    people in it did not press anything.
    """
    row = (
        (
            await db.execute(
                text("UPDATE aisoc_case_war_rooms SET state = 'closed' WHERE id = :id AND tenant_id = :tenant_id RETURNING *").bindparams(
                    id=war_room_id, tenant_id=current_user.tenant_id
                )
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such war room")
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="war_room:close",
        resource="case",
        resource_id=str(row["case_id"]),
        changes={"channel_id": row["channel_id"]},
        request=request,
    )
    await db.commit()
    return _model(row)


@router.post("/{war_room_id}/decision")
async def channel_decision(
    war_room_id: uuid.UUID,
    body: ChannelDecisionRequest,
    # `DBSession`, not `TenantDBSession`: the latter depends on
    # `get_current_user`, and there is no user here. The tenant is read off
    # the war-room row and bound to the session below, which is also why the
    # request body has no tenant field to get wrong.
    db: DBSession,
    x_service_token: str | None = Header(default=None, alias="X-AiSOC-Service-Token"),
) -> dict[str, Any]:
    """A decision taken in the channel, delivered by the bot.

    Service-token only. See the module header: the bot has verified the
    vendor's signature and this service cannot, so the token is the whole
    trust relationship and ``CHANNEL_DECISIONS`` is its blast radius.
    """
    if not service_token_valid(x_service_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="service token required")

    row = (await db.execute(text("SELECT * FROM aisoc_case_war_rooms WHERE id = :id").bindparams(id=war_room_id))).mappings().one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such war room")

    # The tenant comes from the row the bot named, never from the request.
    # There is no tenant field in `ChannelDecisionRequest` to get wrong.
    await set_rls_context(db, row["tenant_id"])
    try:
        result = await apply_channel_decision(
            db,
            tenant_id=row["tenant_id"],
            war_room=dict(row),
            decision=body.decision,
            actor=body.actor or "a war-room participant",
            note=body.note,
        )
    except WarRoomError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    await emit_audit(
        db=db,
        tenant_id=row["tenant_id"],
        actor_email=body.actor or None,
        # The credential on this path is the bot's shared service token —
        # there is no session and no API key, and None records exactly that.
        # Which human decided is `actor_email`, as the bot reported it.
        api_key_prefix=None,
        action="war_room:decision",
        resource="case",
        resource_id=str(row["case_id"]),
        changes=result,
    )
    await db.commit()
    return result
