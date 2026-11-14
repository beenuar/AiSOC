"""A case's chat channel: open it, keep it current, take decisions back.

Depth plan 9.4. Nothing in the tree opened a channel. Both bots could only
answer: ``services/slack-bot`` had exactly one outbound route (an approval
card) and ``services/teams-bot`` posts to a webhook somebody configured by
hand. The four grep hits for "war room" on ``main`` were all prose.

Where each half lives, and why
------------------------------
The vendor call belongs in the bot — it holds the workspace token, the Bolt
client and the signature verification, and this service holds neither. The
*decision* about what to say, and the record of what has already been said,
belong here, because this service holds the case, the tenant session and the
audit chain. So the shape is the one ``siem_writeback`` already uses in
reverse: this service posts to the bot's internal route over HTTP with the
shared internal token.

Idempotency is the design, not a refinement
-------------------------------------------
"Post the timeline and verdicts as they change" is a sweep. A sweep with no
record of what it has already sent re-posts the whole case history every
tick, which in a channel people are reading during an incident is not a
cosmetic problem. Every post is keyed by a fingerprint of the *event* and
the key is unique per room, so a retry after a timeout is a no-op and two
replicas running the sweep cannot double-post.

Failure posture
---------------
Opening a war room **fails loudly**: the analyst clicked a button and is
entitled to know it did not work. Syncing one **fails soft** and records
``last_error`` on the room, because a chat outage must not take down the
case surface — but the error is stored and rendered, because a war room that
has silently stopped mirroring is worse than one that was never opened.
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("aisoc.war_room")

PROVIDERS: tuple[str, ...] = ("slack", "teams")

_TIMEOUT = httpx.Timeout(15.0, connect=5.0)


class WarRoomError(RuntimeError):
    """A refusal or a vendor failure the caller should see, with the reason."""


@dataclass(frozen=True)
class BotTarget:
    base_url: str
    token: str


def bot_target(provider: str) -> BotTarget | None:
    """Where to reach the bot for ``provider``, or ``None`` when unconfigured.

    ``None`` rather than a guessed default. A guessed URL produces a
    connection error at click time, which reads to an operator as "the
    feature is broken" rather than "the chat bot is not deployed" — and the
    bots are in the ``chatops`` compose profile, so not running one is an
    ordinary, supported state rather than a misconfiguration.
    """
    env = {
        "slack": ("AISOC_SLACK_BOT_URL", "AISOC_INTERNAL_TOKEN"),
        "teams": ("AISOC_TEAMS_BOT_URL", "AISOC_INTERNAL_TOKEN"),
    }.get(provider)
    if env is None:
        return None
    url = os.environ.get(env[0], "").strip()
    token = os.environ.get(env[1], "").strip()
    if not url or not token:
        return None
    return BotTarget(base_url=url.rstrip("/"), token=token)


async def _call_bot(
    provider: str,
    path: str,
    payload: dict[str, Any],
    *,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    target = bot_target(provider)
    if target is None:
        raise WarRoomError(
            f"The {provider} bot is not configured. Set AISOC_{provider.upper()}_BOT_URL and "
            "AISOC_INTERNAL_TOKEN, and start the service — both bots are in the `chatops` "
            "compose profile and are not running by default."
        )
    owns = client is None
    http = client or httpx.AsyncClient(timeout=_TIMEOUT)
    try:
        res = await http.post(
            f"{target.base_url}{path}",
            json=payload,
            headers={"X-AiSOC-Internal-Token": target.token, "Content-Type": "application/json"},
        )
    except httpx.HTTPError as exc:
        raise WarRoomError(f"The {provider} bot was unreachable: {exc}") from exc
    finally:
        if owns:
            await http.aclose()
    if res.status_code >= 400:
        raise WarRoomError(f"The {provider} bot answered HTTP {res.status_code}: {res.text[:300]}")
    body = res.json() if res.content else {}
    if not isinstance(body, dict):
        raise WarRoomError(f"The {provider} bot returned {type(body).__name__}, not an object.")
    return body


# ---------------------------------------------------------------------------
# What the channel should be told
# ---------------------------------------------------------------------------


def case_events(case: dict[str, Any]) -> list[tuple[str, str]]:
    """``(event_key, text)`` for everything about this case worth saying.

    Derived from the case row rather than from a feed, so the sweep is a pure
    function of state and a missed tick cannot lose an event — the next tick
    still sees the same row and the key is still absent from the posts table.
    A feed-based sweep would have to track a cursor, and a cursor that
    advances past an unposted event loses it permanently.

    The keys embed the *value*, not just the field, so a status that goes
    `open → closed → open` posts three times rather than once. That matters:
    a re-opened case is news.
    """
    out: list[tuple[str, str]] = []
    status = (case.get("status") or "").strip()
    if status:
        out.append((f"status:{status}", f"*Status* is now `{status}`."))
    severity = (case.get("severity") or "").strip()
    if severity:
        out.append((f"severity:{severity}", f"*Severity* is `{severity}`."))
    assignee = (case.get("assignee") or "").strip()
    if assignee:
        out.append((f"assignee:{assignee}", f"*Assigned* to {assignee}."))
    resolution = (case.get("resolution") or "").strip()
    if resolution:
        # Bounded: a resolution can be an essay and a chat message should not
        # be. The case link in the channel header is where the full text is.
        out.append((f"resolution:{resolution[:64]}", f"*Resolution*: {resolution[:400]}"))
    verdict = (case.get("verdict") or "").strip()
    if verdict:
        confidence = case.get("confidence")
        suffix = f" (confidence {confidence})" if confidence is not None else ""
        out.append((f"verdict:{verdict}:{confidence}", f"*Verdict*: `{verdict}`{suffix}."))
    return out


# ---------------------------------------------------------------------------
# Open
# ---------------------------------------------------------------------------


async def open_war_room(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    case_id: uuid.UUID,
    provider: str,
    opened_by: str,
    invite: list[str],
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Create the channel, invite the assignees, post the case header.

    Fails loudly: the analyst pressed a button and is entitled to know when
    it did not work.
    """
    if provider not in PROVIDERS:
        raise WarRoomError(f"provider must be one of {list(PROVIDERS)}")

    case = (
        (
            await db.execute(
                text(
                    "SELECT id, case_number, title, status, severity, assignee, resolution "
                    "FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id"
                ).bindparams(id=case_id, tenant_id=tenant_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if case is None:
        raise WarRoomError("No such case in this tenant.")

    existing = (
        (
            await db.execute(
                text(
                    "SELECT * FROM aisoc_case_war_rooms "
                    "WHERE tenant_id = :tenant_id AND case_id = :case_id AND provider = :provider AND state = 'open'"
                ).bindparams(tenant_id=tenant_id, case_id=case_id, provider=provider)
            )
        )
        .mappings()
        .one_or_none()
    )
    if existing is not None:
        # Idempotent. Opening twice must not produce a second channel for one
        # case, which is the failure an analyst notices at the worst moment.
        return {"war_room": dict(existing), "created": False}

    number = case["case_number"] or str(case_id)[:8]
    reply = await _call_bot(
        provider,
        "/internal/war-room",
        {
            "case_id": str(case_id),
            "case_number": str(number),
            "title": case["title"],
            "severity": case["severity"],
            "status": case["status"],
            "invite": invite,
        },
        client=client,
    )
    channel_id = str(reply.get("channel_id") or "").strip()
    if not channel_id:
        raise WarRoomError(
            f"The {provider} bot reported success but returned no channel id ({reply!r}). Refusing to record a war room with no channel."
        )

    row = (
        (
            await db.execute(
                text(
                    "INSERT INTO aisoc_case_war_rooms "
                    "(tenant_id, case_id, provider, channel_id, channel_name, channel_url, opened_by) "
                    "VALUES (:tenant_id, :case_id, :provider, :channel_id, :channel_name, :channel_url, :opened_by) "
                    "RETURNING *"
                ).bindparams(
                    tenant_id=tenant_id,
                    case_id=case_id,
                    provider=provider,
                    channel_id=channel_id,
                    channel_name=str(reply.get("channel_name") or ""),
                    channel_url=str(reply.get("channel_url") or ""),
                    opened_by=opened_by,
                )
            )
        )
        .mappings()
        .one()
    )
    return {"war_room": dict(row), "created": True, "invited": reply.get("invited", [])}


# ---------------------------------------------------------------------------
# Sync
# ---------------------------------------------------------------------------


async def sync_war_room(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    war_room: dict[str, Any],
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Post whatever this room has not been told. Fails soft, records why.

    Returns ``{"posted": n, "error": str | None}``. The caller commits.
    """
    case = (
        (
            await db.execute(
                text(
                    "SELECT id, status, severity, assignee, resolution FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id"
                ).bindparams(id=war_room["case_id"], tenant_id=tenant_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if case is None:
        return {"posted": 0, "error": "the case no longer exists"}

    known = set(
        (await db.execute(text("SELECT event_key FROM aisoc_war_room_posts WHERE war_room_id = :id").bindparams(id=war_room["id"])))
        .scalars()
        .all()
    )
    pending = [(key, body) for key, body in case_events(dict(case)) if key not in known]
    if not pending:
        await db.execute(
            text("UPDATE aisoc_case_war_rooms SET last_synced_at = :now, last_error = '' WHERE id = :id").bindparams(
                now=datetime.now(UTC), id=war_room["id"]
            )
        )
        return {"posted": 0, "error": None}

    posted = 0
    error: str | None = None
    for key, body in pending:
        try:
            await _call_bot(
                war_room["provider"],
                "/internal/war-room/post",
                {"channel_id": war_room["channel_id"], "text": body, "case_id": str(war_room["case_id"])},
                client=client,
            )
        except WarRoomError as exc:
            # Stop at the first failure rather than pressing on: the rest of
            # the batch would almost certainly fail too, and the unposted
            # keys stay absent from the table so the next tick retries them
            # in order.
            error = str(exc)
            break
        await db.execute(
            text(
                "INSERT INTO aisoc_war_room_posts (tenant_id, war_room_id, event_key, summary) "
                "VALUES (:tenant_id, :room, :key, :summary) ON CONFLICT (war_room_id, event_key) DO NOTHING"
            ).bindparams(tenant_id=tenant_id, room=war_room["id"], key=key, summary=body[:400])
        )
        posted += 1

    await db.execute(
        text("UPDATE aisoc_case_war_rooms SET last_synced_at = :now, last_error = :err WHERE id = :id").bindparams(
            now=datetime.now(UTC), err=error or "", id=war_room["id"]
        )
    )
    return {"posted": posted, "error": error}


# ---------------------------------------------------------------------------
# Decisions coming back from the channel
# ---------------------------------------------------------------------------

#: What a channel may do to a case. Deliberately narrow: a chat message is
#: not an authenticated console session, and the set of verbs reachable from
#: one should be the set somebody has thought about. Anything else is refused
#: by name rather than ignored, so a user who tries gets told.
CHANNEL_DECISIONS: frozenset[str] = frozenset({"acknowledge", "escalate", "resolve", "note"})


async def apply_channel_decision(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    war_room: dict[str, Any],
    decision: str,
    actor: str,
    note: str,
) -> dict[str, Any]:
    """Write a decision taken in the channel back onto the case.

    The decision arrives from the bot, which has verified the vendor's
    signature on the interaction. This service does not re-verify it — it
    cannot, it has no workspace secret — so the bot is trusted exactly as far
    as the shared internal token, and the verb set above is the blast radius
    of that trust.
    """
    if decision not in CHANNEL_DECISIONS:
        raise WarRoomError(f"decision must be one of {sorted(CHANNEL_DECISIONS)}")

    now = datetime.now(UTC)
    case_id = war_room["case_id"]
    changed: dict[str, Any] = {}

    if decision == "acknowledge":
        await db.execute(
            text(
                "UPDATE aisoc_cases SET acknowledged_at = COALESCE(acknowledged_at, :now), updated_at = :now "
                "WHERE id = :id AND tenant_id = :tenant_id"
            ).bindparams(now=now, id=case_id, tenant_id=tenant_id)
        )
        changed["acknowledged_at"] = now.isoformat()
    elif decision == "escalate":
        await db.execute(
            text(
                "UPDATE aisoc_cases SET severity = 'critical', escalation_level = "
                "COALESCE(escalation_level, 0) + 1, updated_at = :now "
                "WHERE id = :id AND tenant_id = :tenant_id"
            ).bindparams(now=now, id=case_id, tenant_id=tenant_id)
        )
        changed["severity"] = "critical"
    elif decision == "resolve":
        # `resolved`, not `closed`. Closing is a terminal decision with SLA
        # and reporting consequences and belongs on an authenticated console
        # session; a chat button moves the case to the state a human then
        # confirms.
        await db.execute(
            text(
                "UPDATE aisoc_cases SET status = 'resolved', resolved_at = COALESCE(resolved_at, :now), "
                "resolution = COALESCE(NULLIF(resolution, ''), :note), updated_at = :now "
                "WHERE id = :id AND tenant_id = :tenant_id"
            ).bindparams(now=now, note=note or f"resolved from the war room by {actor}", id=case_id, tenant_id=tenant_id)
        )
        changed["status"] = "resolved"
    else:  # note
        changed["note"] = note[:400]

    # Recorded as a post so the channel's own history and the case's agree
    # about what happened, and so the sweep does not immediately echo the
    # change back into the channel that caused it.
    await db.execute(
        text(
            "INSERT INTO aisoc_war_room_posts (tenant_id, war_room_id, event_key, summary) "
            "VALUES (:tenant_id, :room, :key, :summary) ON CONFLICT (war_room_id, event_key) DO NOTHING"
        ).bindparams(
            tenant_id=tenant_id,
            room=war_room["id"],
            key=f"decision:{decision}:{now.isoformat()}",
            summary=f"{actor} chose {decision} in the channel: {note[:200]}",
        )
    )
    return {"decision": decision, "changed": changed}
