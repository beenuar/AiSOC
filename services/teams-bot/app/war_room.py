"""Open a Teams channel for a case — and say plainly when it cannot.

Depth plan 9.4.

Teams is not Slack, and the difference is not cosmetic
------------------------------------------------------
Slack's ``conversations.create`` needs one bot token, which this project
already asks an operator for. Creating a Teams channel needs **Microsoft
Graph** with an Entra application registration holding
``Channel.Create.Group`` or ``Group.ReadWrite.All``, admin consent, and the
object id of the team to create it in. None of that is a token somebody
pastes into a box, and the incoming webhook this service already uses
cannot create anything at all — a webhook posts into one channel somebody
chose by hand.

So this route does the Graph call when an operator has done that work, and
**refuses with the specific missing piece named** when they have not. It
does not fall back to the webhook and report success: a war room that is
really one pre-existing channel shared by every case is worse than no war
room, because the next incident's traffic lands in the last one's thread.

That refusal is the honest state and it is the state a stock install is in.
``services/api``'s ``WarRoomError`` carries this sentence to the console
verbatim, so an analyst who presses "Open in Teams" on an unconfigured
deployment is told which three settings are missing rather than seeing
"something went wrong".
"""

from __future__ import annotations

import hmac
import os
import re
from typing import Any
from urllib.parse import quote

import httpx
import structlog
from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/internal", tags=["internal"])

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"

_TIMEOUT = httpx.Timeout(20.0, connect=5.0)

#: Teams channel names forbid these characters outright.
_ILLEGAL = re.compile(r'[~#%&*{}+/\\:<>?|\'"]')


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


def channel_name_for(case_number: str, title: str) -> str:
    """A Teams-legal display name that still says which case it is."""
    cleaned = _ILLEGAL.sub("-", f"AiSOC {case_number} {title}".strip())
    cleaned = re.sub(r"\s{2,}", " ", cleaned).strip(" .-")
    return cleaned[:50]


#: The shape Graph issues for a channel id: `19:<base64ish>@thread.tacv2`.
#: A `fullmatch` on it, not an escape. An escaped value that reaches Graph
#: and matches nothing reports a clean failure for a request that never ran;
#: refusing names the problem. This is also what stops `channel_id` — which
#: arrives over HTTP — from steering the URL path (`py/partial-ssrf`).
_CHANNEL_ID_RE = re.compile(r"^19:[A-Za-z0-9_+=/\-]{8,200}@thread\.(tacv2|skype)$")


def require_channel_id(candidate: str) -> str:
    """Return ``candidate`` when it is a Graph channel id, or refuse."""
    if not _CHANNEL_ID_RE.fullmatch(candidate or ""):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="channel_id is not a Microsoft Graph channel id (19:...@thread.tacv2).",
        )
    return candidate


def _authorized(supplied: str | None) -> bool:
    expected = os.environ.get("AISOC_INTERNAL_TOKEN", "").strip()
    if not expected:
        return False
    # `is not None`, not `bool(...)`: the two are equivalent at runtime and
    # only the first narrows the Optional, which is why the baseline gate
    # reported a `union-attr` here. Narrowing is the fix; a `type: ignore`
    # would hide the one thing that makes the next edit safe.
    return supplied is not None and hmac.compare_digest(supplied.strip(), expected)


def graph_config() -> tuple[str, str, str, str] | list[str]:
    """``(tenant, client_id, secret, team_id)`` or the list of what is missing.

    Returns the missing names rather than ``None`` so the refusal can say
    which three settings an operator has to supply. "Not configured" without
    naming the gap is a message that sends somebody to the documentation to
    guess.
    """
    values = {
        "MS_GRAPH_TENANT_ID": os.environ.get("MS_GRAPH_TENANT_ID", "").strip(),
        "MS_GRAPH_CLIENT_ID": os.environ.get("MS_GRAPH_CLIENT_ID", "").strip(),
        "MS_GRAPH_CLIENT_SECRET": os.environ.get("MS_GRAPH_CLIENT_SECRET", "").strip(),
        "MS_TEAMS_TEAM_ID": os.environ.get("MS_TEAMS_TEAM_ID", "").strip(),
    }
    missing = [name for name, value in values.items() if not value]
    if missing:
        return missing
    return (
        values["MS_GRAPH_TENANT_ID"],
        values["MS_GRAPH_CLIENT_ID"],
        values["MS_GRAPH_CLIENT_SECRET"],
        values["MS_TEAMS_TEAM_ID"],
    )


async def _graph_token(tenant: str, client_id: str, secret: str, http: httpx.AsyncClient) -> str:
    res = await http.post(
        f"{LOGIN}/{tenant}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
            "scope": "https://graph.microsoft.com/.default",
        },
    )
    if res.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Entra refused the client credentials ({res.status_code}). "
            "Check the application registration and that admin consent has been granted.",
        )
    token = res.json().get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Entra returned no access token")
    return str(token)


@router.post("/war-room", status_code=status.HTTP_201_CREATED)
async def open_war_room(
    body: OpenWarRoomRequest,
    x_internal_token: str | None = Header(default=None, alias="X-AiSOC-Internal-Token"),
) -> dict[str, Any]:
    if not _authorized(x_internal_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="internal token required")

    config = graph_config()
    if isinstance(config, list):
        # Named, specific, and deliberately a failure rather than a webhook
        # fallback. See the module header: one shared channel per deployment
        # is worse than none.
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                "Creating a Teams channel needs Microsoft Graph, which is not configured here. "
                f"Missing: {', '.join(config)}. The incoming webhook this service posts cards "
                "through cannot create a channel, and reusing one channel for every case would "
                "put the next incident's traffic in the last one's thread."
            ),
        )

    tenant, client_id, secret, team_id = config
    name = channel_name_for(body.case_number or body.case_id[:8], body.title)

    async with httpx.AsyncClient(timeout=_TIMEOUT) as http:
        token = await _graph_token(tenant, client_id, secret, http)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        res = await http.post(
            f"{GRAPH}/teams/{team_id}/channels",
            headers=headers,
            json={
                "displayName": name,
                "description": f"AiSOC case {body.case_number or body.case_id} — {body.title}"[:1024],
                "membershipType": "standard",
            },
        )
        if res.status_code == 409:
            # A channel with this display name already exists. Find it rather
            # than failing: re-opening a war room for a case that already has
            # one should hand back the same channel.
            listing = await http.get(f"{GRAPH}/teams/{team_id}/channels", headers=headers)
            existing = next(
                (c for c in listing.json().get("value", []) if c.get("displayName") == name),
                None,
            )
            if existing is None:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Graph says a channel named {name!r} exists but it is not in the team's channel list.",
                )
            channel = existing
        elif res.status_code >= 400:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Graph refused to create the channel ({res.status_code}): {res.text[:300]}",
            )
        else:
            channel = res.json()

        channel_id = str(channel.get("id") or "")
        if not channel_id:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Graph returned a channel with no id")

        header_text = (
            f"AiSOC case {body.case_number or body.case_id[:8]} — {body.title or 'untitled'}. "
            f"Severity {body.severity or 'unknown'}, status {body.status or 'unknown'}."
        )
        post = await http.post(
            f"{GRAPH}/teams/{team_id}/channels/{channel_id}/messages",
            headers=headers,
            json={"body": {"content": header_text}},
        )
        if post.status_code >= 400:
            # Degraded room, not a failed open — the channel exists and the
            # API is about to record it.
            logger.warning("teams_bot.war_room_header_failed", channel_id=channel_id, status=post.status_code)

    logger.info("teams_bot.war_room_opened", case_id=body.case_id, channel_id=channel_id)
    return {
        "channel_id": channel_id,
        "channel_name": channel.get("displayName") or name,
        "channel_url": channel.get("webUrl") or "",
        # Graph adds members to a *standard* channel from the team's own
        # membership, so there is nobody to invite and claiming otherwise
        # would be a reply the console renders as a list of people who were
        # never added.
        "invited": [],
        "not_invited": [],
    }


@router.post("/war-room/post", status_code=status.HTTP_202_ACCEPTED)
async def post_to_war_room(
    body: PostRequest,
    x_internal_token: str | None = Header(default=None, alias="X-AiSOC-Internal-Token"),
) -> dict[str, Any]:
    if not _authorized(x_internal_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="internal token required")

    config = graph_config()
    if isinstance(config, list):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Microsoft Graph is not configured; missing {', '.join(config)}.",
        )
    tenant, client_id, secret, team_id = config
    channel_id = require_channel_id(body.channel_id)
    # The taint tracker does not follow that guard across the function
    # boundary, so the same fullmatch is restated here, in the frame that
    # builds the URL: the value interpolated below is the regex's own match,
    # not the request's string.
    matched = _CHANNEL_ID_RE.fullmatch(channel_id)
    if matched is None:  # pragma: no cover — require_channel_id already raised
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="channel_id is not a Microsoft Graph channel id.")
    channel_id = matched.group(0)

    async with httpx.AsyncClient(timeout=_TIMEOUT) as http:
        token = await _graph_token(tenant, client_id, secret, http)
        # `channel_id` has already been through `require_channel_id`, which
        # is a `fullmatch` on the exact shape Graph issues, and it is then
        # percent-encoded with `safe=''`. CodeQL's taint tracker does not
        # follow a guard across a function boundary — the documented
        # behaviour that cost four attempts elsewhere in this tree — so the
        # suppression sits on the reported line and nowhere else. Any
        # *other* URL built from a request in this file still fails the
        # query.
        res = await http.post(
            f"{GRAPH}/teams/{team_id}/channels/{quote(channel_id, safe='')}/messages",  # codeql[py/partial-ssrf]
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"body": {"content": body.text}},
        )
    if res.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Graph refused the message ({res.status_code}): {res.text[:300]}",
        )
    return {"posted": True}
