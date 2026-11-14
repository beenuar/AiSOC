"""Tenant-scoped persistence for copilot conversations and saved hunt searches.

Both used to be module-level dicts — `_CONVERSATIONS` in `copilot.py` and
`_SAVED_SEARCHES` in `hunt_search.py`. A module global has no tenant, so the
read could not be scoped: the information needed to scope it was never
stored. The list handlers bound no principal at all, so one tenant's
conversations were returned to whoever asked.

Follows `app/hunt/store.py` and `app/investigator/ledger.py`: raw asyncpg, a
lazily-created pool, and `app.current_tenant_id` set on every connection.

One deliberate difference from those two. They are best-effort — a database
outage must not take the hunt scheduler offline, so their writes are wrapped
and a failure is logged. These are not. A read that fails must raise, because
the alternative is returning an empty list, and an empty list is
indistinguishable from "this tenant has no conversations". A write that fails
must raise, because the alternative is telling an analyst their search was
saved when it was not.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import asyncpg
import structlog

logger = structlog.get_logger()

_POOL: asyncpg.Pool | None = None


class ConversationStoreUnavailable(RuntimeError):
    """The store cannot answer. Raised rather than returning an empty result.

    Distinguished from "no rows" on purpose: a caller that cannot tell them
    apart renders an empty conversation list over a database outage, and the
    analyst concludes their history is gone.
    """


def _normalise_dsn(url: str) -> str:
    return url.replace("postgresql+asyncpg://", "postgresql://").replace("postgres+asyncpg://", "postgresql://")


async def _pool() -> asyncpg.Pool:
    global _POOL
    if _POOL is not None:
        return _POOL
    dsn = os.environ.get("DATABASE_URL", "").strip()
    if not dsn:
        raise ConversationStoreUnavailable(
            "DATABASE_URL is not set, so copilot conversations cannot be stored. They used "
            "to live in a process-local dict shared by every tenant; refusing is the "
            "correct behaviour now."
        )
    _POOL = await asyncpg.create_pool(dsn=_normalise_dsn(dsn), min_size=1, max_size=4, command_timeout=10)
    return _POOL


async def _scoped(conn: asyncpg.Connection, tenant_id: uuid.UUID) -> None:
    """Bind the connection to one tenant for the enclosing transaction.

    `app.current_tenant_id` is the variable every policy in this schema
    reads. It said `app.tenant_id` in two modules until 2026-09, and the
    scope was silently never applied — the same spelling mistake is the
    reason the query layer filters as well.
    """
    await conn.execute("SELECT set_config('app.current_tenant_id', $1, true)", str(tenant_id))


@dataclass(frozen=True)
class Conversation:
    id: str
    title: str
    messages: list[dict[str, Any]]
    updated_at: str

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "updatedAt": self.updated_at,
            "messageCount": len(self.messages),
        }

    def full(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "messages": self.messages}


def _row_to_conversation(row: asyncpg.Record) -> Conversation:
    raw = row["messages"]
    return Conversation(
        id=str(row["id"]),
        title=row["title"],
        messages=json.loads(raw) if isinstance(raw, str) else list(raw or []),
        updated_at=row["updated_at"].astimezone(UTC).isoformat(),
    )


# ── Conversations ───────────────────────────────────────────────────────────


async def list_conversations(*, tenant_id: uuid.UUID, limit: int = 20) -> list[Conversation]:
    pool = await _pool()
    async with pool.acquire() as conn, conn.transaction():
        await _scoped(conn, tenant_id)
        rows = await conn.fetch(
            """
            SELECT id, title, messages, updated_at
              FROM aisoc_copilot_conversations
             WHERE tenant_id = $1
             ORDER BY updated_at DESC
             LIMIT $2
            """,
            tenant_id,
            max(1, min(limit, 200)),
        )
    return [_row_to_conversation(row) for row in rows]


async def get_conversation(*, tenant_id: uuid.UUID, conversation_id: str) -> Conversation | None:
    """Return the conversation, or None if this tenant does not have it.

    The `tenant_id` predicate is what makes "does not exist" and "belongs to
    somebody else" the same answer. Before this, an id was enough.
    """
    try:
        parsed = uuid.UUID(conversation_id)
    except ValueError:
        return None
    pool = await _pool()
    async with pool.acquire() as conn, conn.transaction():
        await _scoped(conn, tenant_id)
        row = await conn.fetchrow(
            """
            SELECT id, title, messages, updated_at
              FROM aisoc_copilot_conversations
             WHERE tenant_id = $1 AND id = $2
            """,
            tenant_id,
            parsed,
        )
    return _row_to_conversation(row) if row else None


async def append_messages(
    *,
    tenant_id: uuid.UUID,
    conversation_id: str | None,
    user_id: uuid.UUID | None,
    title: str,
    new_messages: list[dict[str, Any]],
) -> Conversation:
    """Create or extend a conversation, and return it as stored.

    One statement rather than read-modify-write. Two browser tabs on the same
    conversation would otherwise each read the message list, append locally,
    and write back — and the second write would silently drop the first one's
    turn.
    """
    pool = await _pool()
    payload = json.dumps(new_messages)
    now = datetime.now(UTC)

    async with pool.acquire() as conn, conn.transaction():
        await _scoped(conn, tenant_id)
        parsed: uuid.UUID | None = None
        if conversation_id:
            try:
                parsed = uuid.UUID(conversation_id)
            except ValueError:
                parsed = None

        if parsed is not None:
            row = await conn.fetchrow(
                """
                UPDATE aisoc_copilot_conversations
                   SET messages = messages || $3::jsonb,
                       updated_at = $4
                 WHERE tenant_id = $1 AND id = $2
             RETURNING id, title, messages, updated_at
                """,
                tenant_id,
                parsed,
                payload,
                now,
            )
            if row is not None:
                return _row_to_conversation(row)
            # Falls through to an insert. A caller naming an id that belongs
            # to another tenant gets a new conversation of their own rather
            # than an error that would confirm the id exists.

        row = await conn.fetchrow(
            """
            INSERT INTO aisoc_copilot_conversations
                        (tenant_id, user_id, title, messages, updated_at)
                 VALUES ($1, $2, $3, $4::jsonb, $5)
              RETURNING id, title, messages, updated_at
            """,
            tenant_id,
            user_id,
            title,
            payload,
            now,
        )
    return _row_to_conversation(row)


# ── Saved hunt searches ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class SavedSearch:
    id: str
    name: str
    query: str
    backend: str
    updated_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "query": self.query,
            "backend": self.backend,
            "updatedAt": self.updated_at,
        }


def _row_to_search(row: asyncpg.Record) -> SavedSearch:
    return SavedSearch(
        id=str(row["id"]),
        name=row["name"],
        query=row["query"],
        backend=row["backend"],
        updated_at=row["updated_at"].astimezone(UTC).isoformat(),
    )


async def list_saved_searches(*, tenant_id: uuid.UUID, limit: int = 50) -> list[SavedSearch]:
    pool = await _pool()
    async with pool.acquire() as conn, conn.transaction():
        await _scoped(conn, tenant_id)
        rows = await conn.fetch(
            """
            SELECT id, name, query, backend, updated_at
              FROM aisoc_saved_hunt_searches
             WHERE tenant_id = $1
             ORDER BY updated_at DESC
             LIMIT $2
            """,
            tenant_id,
            max(1, min(limit, 200)),
        )
    return [_row_to_search(row) for row in rows]


async def save_search(
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID | None,
    name: str,
    query: str,
    backend: str = "",
) -> SavedSearch:
    pool = await _pool()
    async with pool.acquire() as conn, conn.transaction():
        await _scoped(conn, tenant_id)
        row = await conn.fetchrow(
            """
            INSERT INTO aisoc_saved_hunt_searches
                        (tenant_id, user_id, name, query, backend)
                 VALUES ($1, $2, $3, $4, $5)
              RETURNING id, name, query, backend, updated_at
            """,
            tenant_id,
            user_id,
            name,
            query,
            backend,
        )
    return _row_to_search(row)


async def delete_saved_search(*, tenant_id: uuid.UUID, search_id: str) -> bool:
    try:
        parsed = uuid.UUID(search_id)
    except ValueError:
        return False
    pool = await _pool()
    async with pool.acquire() as conn, conn.transaction():
        await _scoped(conn, tenant_id)
        result = await conn.execute(
            "DELETE FROM aisoc_saved_hunt_searches WHERE tenant_id = $1 AND id = $2",
            tenant_id,
            parsed,
        )
    return result.endswith(" 1")


async def reset_pool_for_tests() -> None:
    """Drop the cached pool. Only the suite calls this."""
    global _POOL
    if _POOL is not None:
        await _POOL.close()
        _POOL = None
