"""The stateful half of depth plan 2.4: sessions per principal.

`services/ingest/internal/activity/session.go` is the only producer of a
session key and its kind. It answers the one question that is answerable from
a single event and nowhere later: which session does this event belong to, and
how strongly do we know. Everything that needs more than one event — the
start, the last sighting, the event count, the walk up an assumed-role chain,
the idle gap that closes a derived session — is here.

One producer, three consumers
-----------------------------
This module, the lake writer and the Go graph writer all read the same
`activity.session` block and none of them re-derives it. ADR-0010 accepted
that arrangement on the condition that it is held by a gate rather than by a
comment, which is `scripts/check_session_projection.py`: it fails if a second
site in the tree derives a session key, and its self-test performs that exact
edit.

Why the id is deterministic
---------------------------
`uuidv5(namespace, tenant|source|key)` rather than a sequence. Three stores
have to agree on one identifier — this table, the ClickHouse row and the Neo4j
node — and the alternative is for two of them to wait on the third. It also
makes a Kafka replay idempotent: the same event upserts the same row instead
of minting a second session for events that already have one, which is the
defect that would show up as a slowly doubling session count and nothing else.

What this module refuses to do
------------------------------
It never invents a session. An event whose source names no session and which
has no principal, address and client to derive one from is recorded as having
no session, and every surface downstream renders that as "no session context"
rather than as a session of one event. A fabricated grouping is worse than an
absent one: it makes "what else did this session do" answerable with a number
that means nothing.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("aisoc.fusion.sessions")

#: Namespace for the deterministic session id. A fixed, arbitrary UUID — its
#: only job is to keep session ids from colliding with any other uuidv5 series
#: in the product. Changing it re-keys every session, so it never changes.
SESSION_NAMESPACE = uuid.UUID("6f1b0e2a-9a3d-5c7e-8b4f-1d2c3e4f5a6b")

#: The closed set `session.go` emits, in strength order. Mirrored here because
#: the CHECK constraint in migration 102 and this module must agree; the gate
#: compares both against the Go constants rather than letting three lists
#: drift independently.
KEY_KINDS: tuple[str, ...] = ("vendor_session", "vendor_credential", "vendor_flow", "derived")

#: How long a derived session may be idle before it is considered over.
#: Derived sessions are the only ones that need this: a vendor session ends
#: when the vendor says so. Thirty minutes matches the idle timeout Okta and
#: Entra default to, so a derived session's duration is comparable to a real
#: one rather than being an arbitrary number of this module's own choosing.
DERIVED_IDLE_SECONDS = 30 * 60


def session_id(tenant_id: str, source: str, key: str) -> uuid.UUID:
    """The id every store agrees on, without any of them coordinating."""
    return uuid.uuid5(SESSION_NAMESPACE, f"{tenant_id}|{source}|{key}")


@dataclass(frozen=True)
class SessionRef:
    """What an alert needs to carry about the session it came from.

    Deliberately not the whole row. The queue renders thousands of alerts and
    the only things that change what a row is allowed to *say* are the id, how
    strong the grouping is, and who is behind it.
    """

    id: uuid.UUID
    key: str
    key_kind: str
    source: str
    principal: str | None = None
    originating_human: str | None = None
    originating_human_source: str | None = None

    @property
    def is_vendor_grouping(self) -> bool:
        """True when the vendor grouped these events, rather than we did.

        A surface that says "17 other events in this session" means something
        different for each answer, and the difference is worth a word in the
        sentence rather than a footnote nobody reads.
        """
        return self.key_kind != "derived"


_UPSERT_SQL = """
INSERT INTO sessions (
    id, tenant_id, session_key, key_kind, key_source, source,
    principal, originating_human, originating_human_source,
    first_seen_at, last_seen_at, event_count, actor_kinds, source_ips
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, 1, $11::jsonb, $12::jsonb)
ON CONFLICT (id) DO UPDATE SET
    -- least()/greatest() rather than assignment: Kafka delivers out of order
    -- after a rebalance, so a late event must widen the window and never
    -- rewind `last_seen_at` to before an event already counted.
    first_seen_at = least(sessions.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at  = greatest(sessions.last_seen_at, EXCLUDED.last_seen_at),
    event_count   = sessions.event_count + 1,
    -- An identity learned later fills a blank; it never overwrites one we
    -- already have, because the first event to name a person is the one whose
    -- provenance we recorded alongside it.
    principal         = COALESCE(sessions.principal, EXCLUDED.principal),
    originating_human = COALESCE(sessions.originating_human, EXCLUDED.originating_human),
    originating_human_source =
        CASE WHEN sessions.originating_human IS NULL
             THEN EXCLUDED.originating_human_source
             ELSE sessions.originating_human_source END,
    actor_kinds = (
        SELECT COALESCE(jsonb_agg(DISTINCT k), '[]'::jsonb)
        FROM jsonb_array_elements(sessions.actor_kinds || EXCLUDED.actor_kinds) AS k
    ),
    source_ips = (
        SELECT COALESCE(jsonb_agg(DISTINCT ip), '[]'::jsonb)
        FROM (
            SELECT ip FROM jsonb_array_elements(sessions.source_ips || EXCLUDED.source_ips) AS ip
            LIMIT 64
        ) AS capped
    ),
    updated_at = now()
RETURNING id
"""

#: Link a child session to the one that issued it.
#:
#: The child row may not exist yet — an AssumeRole response names a credential
#: whose first *use* has not been consumed — so this inserts a placeholder
#: carrying everything the issuing call knew. `event_count` starts at 0, which
#: is the honest value: we know this session was created and have seen none of
#: its events.
_LINK_ISSUED_SQL = """
INSERT INTO sessions (
    id, tenant_id, session_key, key_kind, key_source, source,
    principal, originating_human, originating_human_source,
    first_seen_at, last_seen_at, event_count, parent_session_id, parent_link_source
)
VALUES ($1, $2, $3, 'vendor_credential', $4, $5, $6, $7, $8, $9, $9, 0, $10, $8)
ON CONFLICT (id) DO UPDATE SET
    parent_session_id = COALESCE(sessions.parent_session_id, EXCLUDED.parent_session_id),
    parent_link_source = COALESCE(sessions.parent_link_source, EXCLUDED.parent_link_source),
    originating_human = COALESCE(sessions.originating_human, EXCLUDED.originating_human),
    originating_human_source =
        CASE WHEN sessions.originating_human IS NULL
             THEN EXCLUDED.originating_human_source
             ELSE sessions.originating_human_source END,
    principal = COALESCE(sessions.principal, EXCLUDED.principal),
    updated_at = now()
"""

#: Close derived sessions that have gone quiet. Vendor sessions are left
#: alone: the vendor says when those end, and guessing on their behalf would
#: report a session as over while it is still being used.
#:
#: Scoped to one tenant per call rather than sweeping the table. The first
#: version had no tenant predicate and relied on the RLS policy's
#: `current_tenant_id() IS NULL` arm, which a worker satisfies by setting
#: nothing -- so one statement reached every tenant's rows and
#: `check_tenant_query_predicates.py` failed the build for it. That gate is
#: right: RLS is defence in depth here, not the control, and a maintenance
#: sweep that can touch every tenant at once is the shape this repository
#: has been bitten by before. It also bounds the work, so one noisy tenant
#: cannot stall the sweep for the rest.
_CLOSE_IDLE_SQL = """
UPDATE sessions
   SET ended_at = last_seen_at,
       ended_reason = 'idle',
       updated_at = now()
 WHERE tenant_id = $1
   AND ended_at IS NULL
   AND key_kind = 'derived'
   AND last_seen_at < now() - make_interval(secs => $2)
"""

#: The tenants with at least one open derived session. Drives the sweep so
#: it visits only tenants that can have work, rather than every tenant row.
_IDLE_TENANTS_SQL = """
SELECT DISTINCT tenant_id
  FROM sessions
 WHERE ended_at IS NULL
   AND key_kind = 'derived'
   AND last_seen_at < now() - make_interval(secs => $1)
"""


class SessionStore:
    """Upserts one session row per event and resolves the chain.

    Takes an asyncpg pool rather than opening its own, because it runs on the
    hot path beside the lake writer and a second pool against the same
    database is two connection budgets to size instead of one.
    """

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def record_event(self, tenant_id: str, payload: dict[str, Any]) -> SessionRef | None:
        """Record one event against its session. Returns None when it has none.

        None is a real answer and not a failure: a source that names no
        session, for an event with no principal, address and client to derive
        one from, genuinely has no session, and saying so is the point.
        """
        block = _session_block(payload)
        if block is None:
            return None

        key = str(block.get("key") or "").strip()
        kind = str(block.get("key_kind") or "").strip()
        if not key or kind not in KEY_KINDS:
            # A block with a kind outside the closed set means the producer
            # and this consumer have drifted. Refuse the row rather than
            # writing one the CHECK constraint will reject anyway, and say so
            # loudly: it is a deploy-skew bug, not a data quirk.
            if kind:
                logger.warning("fusion.session.unknown_key_kind", extra={"key_kind": kind})
            return None

        source = _source_of(payload)
        sid = session_id(tenant_id, source, key)
        seen_at = _event_time(payload)
        ref = SessionRef(
            id=sid,
            key=key,
            key_kind=kind,
            source=source,
            principal=_clean(block.get("principal")),
            originating_human=_clean(block.get("originating_human")),
            originating_human_source=_clean(block.get("originating_human_source")),
        )

        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    _UPSERT_SQL,
                    sid,
                    uuid.UUID(tenant_id),
                    key,
                    kind,
                    _clean(block.get("key_source")) or "",
                    source,
                    ref.principal,
                    ref.originating_human,
                    ref.originating_human_source,
                    seen_at,
                    _json_list(_actor_kind(payload)),
                    _json_list(_source_ip(payload)),
                )
                issued = block.get("issued")
                if isinstance(issued, dict):
                    await self._link_issued(conn, tenant_id, source, sid, issued, seen_at)
        except Exception as exc:  # noqa: BLE001 — sessions are context, never the alert path
            # Deliberately soft. An alert that reaches an analyst without
            # session context is degraded; an alert that never reaches them
            # because the session store was unreachable is an outage. Logged
            # at error with the reason so it is visible rather than absorbed.
            logger.error("fusion.session.upsert_failed", extra={"error": str(exc)}, exc_info=True)
            return None
        return ref

    async def _link_issued(
        self,
        conn: Any,
        tenant_id: str,
        source: str,
        parent_id: uuid.UUID,
        issued: dict[str, Any],
        seen_at: datetime,
    ) -> None:
        """Record the session an STS call created, and the edge back to it.

        This edge exists on the issuing call and nowhere else. The child
        session's own events name only the role it assumed, so without this
        the person behind a chained session is unrecoverable — which is the
        whole reason 2.4 reaches into the AssumeRole response at all.
        """
        key = _clean(issued.get("key"))
        if not key:
            return
        child_id = session_id(tenant_id, source, key)
        if child_id == parent_id:
            # A call that issued the credential it was made with is not a
            # chain, and writing the edge would make the row its own parent.
            return
        await conn.execute(
            _LINK_ISSUED_SQL,
            child_id,
            uuid.UUID(tenant_id),
            key,
            _clean(issued.get("key_source")) or "",
            source,
            _clean(issued.get("principal")),
            _clean(issued.get("originating_human")),
            _clean(issued.get("originating_human_source")),
            seen_at,
            parent_id,
        )

    async def close_idle(
        self,
        idle_seconds: int = DERIVED_IDLE_SECONDS,
        *,
        tenant_id: str | None = None,
    ) -> int:
        """Close derived sessions that have gone quiet. Returns rows closed.

        With ``tenant_id`` the sweep touches that tenant only. Without it the
        tenants that *have* idle sessions are read first and swept one at a
        time, so the UPDATE always carries a tenant predicate and one
        tenant's backlog cannot stall the others.
        """
        try:
            async with self._pool.acquire() as conn:
                if tenant_id is not None:
                    result = await conn.execute(_CLOSE_IDLE_SQL, tenant_id, float(idle_seconds))
                    return _rows_affected(result)

                rows = await conn.fetch(_IDLE_TENANTS_SQL, float(idle_seconds))
                closed = 0
                for row in rows:
                    result = await conn.execute(_CLOSE_IDLE_SQL, row["tenant_id"], float(idle_seconds))
                    closed += _rows_affected(result)
                return closed
        except Exception as exc:  # noqa: BLE001 — same reasoning as record_event
            logger.error("fusion.session.close_idle_failed", extra={"error": str(exc)}, exc_info=True)
            return 0


def _session_block(payload: dict[str, Any]) -> dict[str, Any] | None:
    """The `activity.session` block, or None when the event predates 2.4.

    An event from a replayed topic or from before the projection shipped has
    no block at all and must flow through untouched rather than erroring.
    """
    activity = payload.get("activity")
    if not isinstance(activity, dict):
        return None
    block = activity.get("session")
    return block if isinstance(block, dict) and block else None


def _source_of(payload: dict[str, Any]) -> str:
    for path in (("metadata", "product", "name"), ("connector_type",), ("source",)):
        node: Any = payload
        for part in path:
            node = node.get(part) if isinstance(node, dict) else None
        if isinstance(node, str) and node.strip():
            return node.strip()
    return "unknown"


def _event_time(payload: dict[str, Any]) -> datetime:
    raw = payload.get("time") or payload.get("event_time")
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    if isinstance(raw, int | float):
        # OCSF `time` is milliseconds since epoch. A value small enough to be
        # seconds is treated as seconds rather than landing the session in
        # 1970, which is the shape this mistake takes when it ships.
        seconds = raw / 1000 if raw > 10_000_000_000 else raw
        try:
            return datetime.fromtimestamp(seconds, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return datetime.now(UTC)
    if isinstance(raw, str) and raw:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def _actor_kind(payload: dict[str, Any]) -> str | None:
    activity = payload.get("activity")
    if not isinstance(activity, dict):
        return None
    actor = activity.get("actor")
    if not isinstance(actor, dict):
        return None
    return _clean(actor.get("kind"))


def _source_ip(payload: dict[str, Any]) -> str | None:
    activity = payload.get("activity")
    if isinstance(activity, dict):
        location = activity.get("location")
        if isinstance(location, dict):
            if ip := _clean(location.get("ip")):
                return ip
    endpoint = payload.get("src_endpoint")
    if isinstance(endpoint, dict):
        return _clean(endpoint.get("ip"))
    return None


def _clean(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    return trimmed or None


def _json_list(value: str | None) -> str:
    return json.dumps([value] if value else [])


def _rows_affected(result: Any) -> int:
    """asyncpg returns the command tag, e.g. 'UPDATE 7'."""
    if isinstance(result, str):
        parts = result.rsplit(" ", 1)
        if len(parts) == 2 and parts[1].isdigit():
            return int(parts[1])
    return 0
