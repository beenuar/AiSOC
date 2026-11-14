"""Realtime co-investigation workspace (Theme 2l).

Every case gets a shared *workspace* — a collaborative notes document
that humans **and** agents write into simultaneously. Analysts can
``@mention`` an agent (e.g. ``@investigator look at host bravo-12``)
and the mention parser dispatches an agent run that streams its
findings straight back into the same workspace.

Design choices (and what we *deliberately* did not build):

1. We do **not** ship a full CRDT (Yjs / Automerge). For a SOC notes
   surface the conflict surface is tiny (a handful of analysts and
   agents, low typing concurrency, server has authoritative ordering)
   and a real CRDT would drag in WASM payloads and binary update
   formats that the existing JSON websocket can't ferry without a
   second protocol. Instead we use **server-ordered ops**: every op is
   appended to ``WorkspaceOp`` in monotonic ``seq`` order, the server
   is the single source of truth for ordering, and clients reconcile
   by replaying ops from a known ``seq``. This is the same pattern
   Notion, Linear, and Figma's comments use.

2. Ops are **append-only**. We never UPDATE a ``WorkspaceOp`` row.
   That lets us treat the op log as an audit trail (who said what,
   when, on which case) and it survives unchanged through cold
   storage for compliance replay (Theme 4 / Theme 6).

3. Tenant scoping is denormalized onto every op (not just the parent
   workspace). The WS broadcast path queries ops by ``seq > since``
   and we want the filter to be a single composite index ``(tenant_id,
   case_id, seq)`` rather than a join — workspace fan-out happens on
   the hot path of every keystroke.

Op kinds we actually need today:

* ``note.append`` – append a chunk of markdown to the running document.
  This is the 90% case (analyst types a paragraph, agent dumps a
  finding). The payload carries the markdown plus the author identity.
* ``note.replace`` – replace a previously-appended block by its op id.
  This is how we let an agent revise a draft ("Investigator is still
  working" → "Investigator concluded: …") without producing a noisy
  diff.
* ``mention`` – an analyst typed ``@<agent>``. The op carries the
  parsed mention; the dispatcher reads these and queues agent runs.
* ``agent.started`` / ``agent.finished`` – heartbeat ops that the
  dispatcher and agents emit so every connected client gets a live
  "Investigator is looking at this…" indicator without polling.

Future op kinds (``note.edit_range``, ``cursor.move``, etc.) can be
added without a migration because the payload is ``JSON``. We just
*don't* invent them speculatively.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from sqlmodel import JSON, Column, Field, SQLModel


class WorkspaceOpKind(str, Enum):
    """Allowed values for ``WorkspaceOp.kind``.

    Kept as a closed enum (rather than a free-form string) so the
    websocket consumers can switch on it without defensive ``in {…}``
    checks. New kinds require a code change, which is intentional —
    every kind has semantics the dispatcher / renderer relies on.
    """

    NOTE_APPEND = "note.append"
    NOTE_REPLACE = "note.replace"
    MENTION = "mention"
    AGENT_STARTED = "agent.started"
    AGENT_FINISHED = "agent.finished"


class WorkspaceAuthorKind(str, Enum):
    """Who emitted the op.

    Splitting human vs agent vs system matters for audit replay and
    for the UI (humans render with an avatar, agents with the agent
    icon, system events render inline as muted timeline entries).
    """

    HUMAN = "human"
    AGENT = "agent"
    SYSTEM = "system"


class CaseWorkspace(SQLModel, table=True):
    """One collaborative workspace per case.

    The workspace itself is a thin parent row. The interesting state
    lives in the ``WorkspaceOp`` log — we keep the parent row so we
    can attach workspace-level metadata (cursor presence, current
    op sequence head) without storing it on the ``Case`` table.
    """

    id: Optional[int] = Field(default=None, primary_key=True)

    # Tenant scoping. The workspace inherits its case's tenant; we
    # denormalize so every query that touches workspace rows can be
    # tenant-filtered without a join on ``case``.
    tenant_id: str = Field(index=True)

    # 1:1 with Case. ``unique=True`` plus the index lets us upsert a
    # workspace on first access without a race.
    case_id: int = Field(foreign_key="case.id", unique=True, index=True)

    # The current head of the op log. Clients fetch state by reading
    # ops where ``seq > <their-last-seen>``; this column lets the GET
    # ``/workspace`` endpoint return the head cheaply.
    head_seq: int = Field(default=0)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WorkspaceOp(SQLModel, table=True):
    """An append-only operation in a workspace's log.

    Ordering is **server-assigned**: ``seq`` is allocated inside the
    transaction that inserts the row, monotonically per-workspace.
    Clients never invent ``seq`` values; if they need optimistic UI
    they generate a client-side ``client_op_id`` (UUID) which we
    echo back so the local optimistic row can be reconciled.
    """

    id: Optional[int] = Field(default=None, primary_key=True)

    # Denormalized tenant for fast filtering on the hot fan-out path.
    # Missing tenant on an op is a programming error; we enforce
    # non-null at the DB layer (sqlmodel default for required str).
    tenant_id: str = Field(index=True)

    # Parent workspace + case (case_id duplicated for the WS broadcast
    # path which keys on case_id, not workspace_id).
    workspace_id: int = Field(foreign_key="caseworkspace.id", index=True)
    case_id: int = Field(foreign_key="case.id", index=True)

    # Monotonic per-workspace sequence number. Together with
    # ``workspace_id`` this is the canonical ordering key. We do *not*
    # rely on ``created_at`` for ordering — clocks drift, two ops can
    # share a millisecond, and the WS subscribe cursor needs a strict
    # total order.
    seq: int = Field(index=True)

    # Op semantics. ``kind`` is a string-valued enum (see
    # ``WorkspaceOpKind``); the validator on apply() enforces the enum.
    kind: str = Field(index=True)

    # Free-form JSON payload. Shape varies by ``kind``:
    #   note.append   → {"text": str, "block_id": str}
    #   note.replace  → {"target_op_id": int, "text": str}
    #   mention       → {"agent": str, "raw": str, "block_id": str}
    #   agent.started → {"agent": str, "mention_op_id": int}
    #   agent.finished→ {"agent": str, "mention_op_id": int, "summary": str}
    payload: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))

    # Authorship. ``author_kind`` distinguishes human / agent / system;
    # ``author_id`` is the JWT subject for humans, the agent name for
    # agents, and the literal string "system" for system events.
    author_kind: str = Field(default=WorkspaceAuthorKind.HUMAN.value, index=True)
    author_id: str = Field(default="unknown")

    # Optional client-supplied UUID so a client that posted an op can
    # match its optimistic UI row to the server-confirmed broadcast.
    # We don't enforce uniqueness — duplicate retries are fine.
    client_op_id: Optional[str] = Field(default=None, index=True)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
