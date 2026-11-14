"""Open a Slack channel for a case, invite the people on it, keep it fed.

Depth plan 9.4. Before this, every outbound thing this service could do was
post one approval card into one pre-configured channel. It could not create
anything, so "open a war room" was a sentence in a playbook template and
nowhere else in the tree.

Why the channel call lives here and the decision lives in the API
-----------------------------------------------------------------
This service holds the workspace token, the Bolt client and the signature
verification; the API holds the case, the tenant session and the audit
chain. Neither can import the other. So the API posts here with the shared
internal token to create and to speak, and this service posts back to the
API when somebody presses a button — the same split ``siem_writeback`` uses,
with the direction reversed per call.

Three Slack facts this encodes, each of which is a failure if ignored
---------------------------------------------------------------------
* **Channel names are constrained**: lower case, no spaces, no dots, 80
  characters. ``conversations.create`` rejects anything else, and a case
  title is exactly the kind of string that violates all four.
* **`name_taken` is not an error here.** Re-opening a war room for a case
  whose channel already exists should find it, not fail. The handler looks
  the name up and returns the existing channel.
* **An invite failure is not a create failure.** A user id that is wrong, or
  a person who has left, must not undo a channel that now exists. Invites
  are attempted individually and the ones that failed are named in the
  reply, so the console can say "the room is open, these three were not
  added" instead of "something went wrong".
"""

from __future__ import annotations

import hmac
import re
from typing import Any

import structlog
from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.core.config import get_settings

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/internal", tags=["internal"])

#: Slack's own rule, encoded rather than discovered at runtime: lower case,
#: no spaces or periods, at most 80 characters.
_ILLEGAL = re.compile(r"[^a-z0-9_-]+")


def channel_name_for(case_number: str, title: str) -> str:
    """A legal Slack channel name that still says which case it is.

    The case number leads, because that is the thing an analyst searches
    for and it survives the truncation that a long title does not.
    """
    slug = _ILLEGAL.sub("-", f"{case_number}-{title}".lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    return f"aisoc-{slug}"[:80].rstrip("-")


class OpenWarRoomRequest(BaseModel):
    case_id: str
    case_number: str = ""
    title: str = ""
    severity: str = ""
    status: str = ""
    invite: list[str] = Field(default_factory=list)


class PostRequest(BaseModel):
    channel_id: str
    text: str
    case_id: str = ""


#: Slack's documented error codes, as a closed set.
#:
#: A regex over `str(exc)` was the first attempt and it was still a
#: *substring of the exception*, so the value returned to the caller was
#: derived from the API response however short it was — which is both the
#: `py/stack-trace-exposure` finding and, more to the point, true. This
#: returns a literal from the set below or a fixed string, so nothing
#: derived from the exception can reach a response at all.
#:
#: Unknown codes are deliberately not passed through. Slack adds error codes
#: and this list will go stale; "refused" plus a log line is the right
#: failure for that, because the alternative is a passthrough that reopens
#: the hole the day a new code appears.
_SLACK_REASONS: frozenset[str] = frozenset(
    {
        "name_taken",
        "restricted_action",
        "invalid_name",
        "invalid_name_specials",
        "invalid_name_maxlength",
        "invalid_name_punctuation",
        "invalid_name_required",
        "channel_not_found",
        "is_archived",
        "user_not_found",
        "users_not_found",
        "cant_invite_self",
        "cant_invite",
        "not_in_channel",
        "already_in_channel",
        "ura_max_channels",
        "too_many_users",
        "missing_scope",
        "not_authed",
        "invalid_auth",
        "account_inactive",
        "token_revoked",
        "no_permission",
        "ratelimited",
        "rate_limited",
        "fatal_error",
        "internal_error",
        "service_unavailable",
        "msg_too_long",
        "no_text",
    }
)

#: What a caller is told when Slack's code is not one this build knows.
_UNKNOWN_REASON = "refused"


def slack_reason(exc: BaseException) -> str:
    """A reason code from the closed set above, or a fixed string.

    Never a slice of the exception. The Slack SDK's error carries the whole
    API response, and a caller gets a code it can act on rather than a
    redacted copy of somebody else's HTTP body.
    """
    message = str(exc).lower()
    for code in sorted(_SLACK_REASONS):
        if code in message:
            return code
    return _UNKNOWN_REASON


def _authorized(supplied: str | None) -> bool:
    """Constant-time internal-token check, failing closed when unset.

    Same posture as ``notify.py``: an unset token refuses every internal
    call, with no dev-mode exemption, because a route that creates channels
    in somebody's workspace must not be open to whatever can reach the pod.
    """
    expected = get_settings().AISOC_INTERNAL_TOKEN.strip()
    if not expected:
        return False
    # `is not None`, not `bool(...)`: the two are equivalent at runtime and
    # only the first narrows the Optional, which is why the baseline gate
    # reported a `union-attr` here. Narrowing is the fix; a `type: ignore`
    # would hide the one thing that makes the next edit safe.
    return supplied is not None and hmac.compare_digest(supplied.strip(), expected)


async def _find_channel_by_name(bolt: Any, name: str) -> dict[str, Any] | None:
    """Look a channel up by name, paging until it is found or the list ends.

    Only used on `name_taken`, so the cost is paid once per re-open rather
    than on every create.
    """
    cursor: str | None = None
    for _ in range(20):  # bounded: a workspace with 20k channels is not a loop we own
        page = await bolt.client.conversations_list(
            exclude_archived=True,
            limit=1000,
            types="public_channel,private_channel",
            **({"cursor": cursor} if cursor else {}),
        )
        for channel in page.get("channels", []):
            if channel.get("name") == name:
                return channel
        cursor = (page.get("response_metadata") or {}).get("next_cursor") or ""
        if not cursor:
            return None
    return None


@router.post("/war-room", status_code=status.HTTP_201_CREATED)
async def open_war_room(
    body: OpenWarRoomRequest,
    request: Request,
    x_internal_token: str | None = Header(default=None, alias="X-AiSOC-Internal-Token"),
) -> dict[str, Any]:
    """Create the channel, invite, post the header. Returns the channel id."""
    if not _authorized(x_internal_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="internal token required")

    bolt = getattr(request.app.state, "bolt_app", None)
    if bolt is None:
        # 503 rather than a success with a flag: the caller is a button an
        # analyst pressed, and it needs to fail loudly.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="no Slack client; SLACK_BOT_TOKEN is unset on the slack-bot service",
        )

    settings = get_settings()
    name = channel_name_for(body.case_number or body.case_id[:8], body.title)

    channel: dict[str, Any] | None = None
    try:
        created = await bolt.client.conversations_create(name=name, is_private=False)
        channel = created.get("channel") or {}
    except Exception as exc:  # noqa: BLE001 — the SDK raises a vendor error type this service need not import
        if "name_taken" not in str(exc):
            # The vendor's own words go to the log, not to the response.
            # Slack's SDK raises an object whose `str()` carries the whole
            # API response, and returning that to a caller is an
            # information-exposure finding (`py/stack-trace-exposure`) as
            # well as being more than the caller can act on. The *reason*
            # code is what they can act on, so that is what travels.
            logger.warning("slack_bot.war_room_create_failed", case_id=body.case_id, name=name, error=str(exc))
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Slack refused to create #{name} ({slack_reason(exc)}).",
            ) from exc
        # Re-opening a war room whose channel already exists should find it.
        channel = await _find_channel_by_name(bolt, name)
        if channel is None:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Slack says #{name} is taken but it is not in the channel list; it may be archived or private to another user.",
            ) from exc

    channel_id = str(channel.get("id") or "")
    if not channel_id:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Slack returned a channel with no id")

    # Invites are per-user and a failure does not undo the channel.
    invited: list[str] = []
    not_invited: list[dict[str, str]] = []
    for user in body.invite:
        try:
            await bolt.client.conversations_invite(channel=channel_id, users=user)
            invited.append(user)
        except Exception as exc:  # noqa: BLE001
            # `already_in_channel` is a success from the caller's point of view.
            if "already_in_channel" in str(exc):
                invited.append(user)
                continue
            # A reason code, not `str(exc)`. The Slack SDK's error carries
            # the whole API response, and this list is returned to the
            # caller and rendered in the console — so the same rule as the
            # create failure above applies, and `py/stack-trace-exposure`
            # was right to report the earlier form.
            not_invited.append({"user": user, "reason": slack_reason(exc)})

    header = (
        f"*AiSOC case {body.case_number or body.case_id[:8]}* — {body.title or 'untitled'}\n"
        f"Severity `{body.severity or 'unknown'}` · status `{body.status or 'unknown'}`\n"
        f"{settings.AISOC_WEB_BASE_URL.rstrip('/')}/cases/{body.case_id}"
    )
    try:
        await bolt.client.chat_postMessage(channel=channel_id, text=header)
    except Exception as exc:  # noqa: BLE001
        # The channel exists and is recorded; a failed header is a degraded
        # room, not a failed open, and the reply says so.
        logger.warning("slack_bot.war_room_header_failed", channel_id=channel_id, error=str(exc))

    logger.info("slack_bot.war_room_opened", case_id=body.case_id, channel_id=channel_id, name=name)
    return {
        "channel_id": channel_id,
        "channel_name": channel.get("name") or name,
        "channel_url": f"slack://channel?id={channel_id}",
        "invited": invited,
        "not_invited": not_invited,
    }


@router.post("/war-room/post", status_code=status.HTTP_202_ACCEPTED)
async def post_to_war_room(
    body: PostRequest,
    request: Request,
    x_internal_token: str | None = Header(default=None, alias="X-AiSOC-Internal-Token"),
) -> dict[str, Any]:
    """Say one thing in a war room.

    Fails with a status the caller can act on rather than a flag: the API's
    sweep records `last_error` on the room from this, and an operator reading
    "channel_not_found" knows the channel was archived.
    """
    if not _authorized(x_internal_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="internal token required")
    bolt = getattr(request.app.state, "bolt_app", None)
    if bolt is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="no Slack client; SLACK_BOT_TOKEN is unset on the slack-bot service",
        )
    try:
        await bolt.client.chat_postMessage(channel=body.channel_id, text=body.text)
    except Exception as exc:  # noqa: BLE001
        logger.warning("slack_bot.war_room_post_failed", channel_id=body.channel_id, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Slack refused the message ({slack_reason(exc)}).",
        ) from exc
    return {"posted": True}
