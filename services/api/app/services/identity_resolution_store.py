"""One read interface over the CORE table and the `full` graph.

Depth plan wave 2, Phase 3.1. Backs migration 128.

ADR-0010 put entity context in Postgres for CORE and kept Neo4j for `full`.
Identity resolution is entity context, so it lands both ways — and the
reason this module exists rather than two writers is that two stores written
by two code paths disagree, and the disagreement is invisible: both answer,
and nobody compares them.

So :func:`save_links` writes Postgres first and mirrors to the graph
best-effort, and :func:`links_for` reads **Postgres only**. The graph copy
is for traversal in `full`, never a second source of truth; a read that
preferred the graph would answer differently on the two profiles for reasons
no operator could see.

The merge rule, restated here because this is where it is enforced
------------------------------------------------------------------
:func:`cluster_for` walks merge-strength links only. Weak links are returned
by :func:`links_for` and excluded from the walk, so a chain of three weak
links cannot merge two identities no single rule would join — which is how a
transitive merge quietly becomes the broadest possible one.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.identity_resolution import MERGE_THRESHOLD, IdentityLink, ResolutionResult

logger = structlog.get_logger(__name__)

__all__ = ["cluster_for", "decide_link", "links_for", "save_links"]

# Written out per statement rather than interpolated. `text()` with an
# f-string is a taint sink for `avoid-sqlalchemy-text`, and the rule is
# right that it cannot tell a constant column list from a caller-supplied
# one. `check_raw_sql_columns.py` compares each copy against migration 128,
# so a drifting copy is caught.


def _row(row: Any) -> dict[str, Any]:
    evidence = row.evidence if isinstance(row.evidence, list) else json.loads(row.evidence or "[]")
    confidence = float(row.confidence)
    decided = row.decided
    return {
        "id": str(row.id),
        "left": row.left_key,
        "right": row.right_key,
        "confidence": round(confidence, 4),
        "rule": row.rule,
        "evidence": evidence,
        # A human decision overrides the rule in both directions, and the
        # two facts stay separate so a reader can see which it was.
        "merged": decided == "confirmed" or (decided != "rejected" and confidence >= MERGE_THRESHOLD),
        "decided": decided,
        "decided_by": str(row.decided_by) if row.decided_by else None,
        "decided_at": row.decided_at.isoformat() if row.decided_at else None,
        "first_seen": row.first_seen.isoformat() if row.first_seen else None,
        "last_seen": row.last_seen.isoformat() if row.last_seen else None,
    }


def _ordered(left: str, right: str) -> tuple[str, str]:
    """A pair stored once however it was discovered.

    The migration's CHECK enforces `left_key < right_key`, so a writer that
    skipped this would get an IntegrityError rather than a silent duplicate
    under the other ordering — which is the point of having the constraint
    as well as this function.
    """
    return (left, right) if left < right else (right, left)


async def save_links(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    result: ResolutionResult,
    mirror_to_graph: bool = True,
) -> int:
    """Persist every link, strong and weak. Returns the number written.

    Weak links are written too. Dropping them at write time would make "we
    considered this and rejected it" unrecoverable, and that sentence is
    most of the value when somebody asks why two accounts were not joined.
    """
    written = 0
    for link in result.links:
        left, right = _ordered(link.left, link.right)
        await db.execute(
            text(
                """
                INSERT INTO identity_links (
                    tenant_id, left_key, right_key, confidence, rule, evidence
                ) VALUES (
                    :tenant_id, :left_key, :right_key, :confidence, :rule,
                    CAST(:evidence AS jsonb)
                )
                ON CONFLICT (tenant_id, left_key, right_key) DO UPDATE
                   SET confidence = EXCLUDED.confidence,
                       rule       = EXCLUDED.rule,
                       evidence   = EXCLUDED.evidence,
                       last_seen  = NOW()
                """
            ),
            {
                "tenant_id": str(tenant_id),
                "left_key": left,
                "right_key": right,
                "confidence": float(link.confidence),
                "rule": link.rule,
                "evidence": json.dumps(list(link.evidence)),
            },
        )
        written += 1

    if mirror_to_graph:
        await _mirror_to_graph(tenant_id=tenant_id, links=result.links)
    return written


async def _mirror_to_graph(*, tenant_id: uuid.UUID, links: list[IdentityLink]) -> int:
    """Write `SAME_PERSON` edges when the graph is enabled.

    Best-effort and never raised into the caller: the graph is a `full`
    component and CORE has none, so an unreachable Neo4j is the expected
    state on the most common profile rather than a failure.

    Only merge-strength links are mirrored. A weak link in the graph would
    be walked by every traversal that does not know to filter it, and the
    traversals are written by people who will not remember to.
    """
    strong = [link for link in links if link.merged]
    if not strong:
        return 0
    try:
        from app.db.neo4j import get_session  # noqa: PLC0415 — optional component
    except Exception as exc:  # noqa: BLE001
        logger.debug("identity_links.graph_module_unavailable", error=str(exc))
        return 0

    cypher = """
    MERGE (a:Identity {id: $left, tenant_id: $tenant_id})
    MERGE (b:Identity {id: $right, tenant_id: $tenant_id})
    MERGE (a)-[r:SAME_PERSON]->(b)
    SET r.confidence = $confidence,
        r.rule = $rule,
        r.tenant_id = $tenant_id,
        r.last_seen = datetime()
    """
    written = 0
    try:
        async with get_session() as session:
            for link in strong:
                left, right = _ordered(link.left, link.right)
                await session.run(
                    cypher,
                    left=left,
                    right=right,
                    tenant_id=str(tenant_id),
                    confidence=float(link.confidence),
                    rule=link.rule,
                )
                written += 1
    except Exception as exc:  # noqa: BLE001 — CORE has no graph; this is expected there
        logger.debug("identity_links.graph_write_skipped", error=str(exc))
        return 0
    return written


async def links_for(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    key: str,
    include_weak: bool = True,
) -> list[dict[str, Any]]:
    """Every link touching ``key``, from either end.

    Reads Postgres only. The graph copy exists for traversal in `full` and
    is never a second source of truth: a read that preferred it would answer
    differently on the two profiles for reasons no operator could see.
    """
    # The optional strength filter is a parameter, not an appended clause:
    # one statement, one plan, and no f-string reaching `text()`.
    result = await db.execute(
        text(
            """
            SELECT id, left_key, right_key, confidence, rule, evidence,
                   decided, decided_by, decided_at, first_seen, last_seen
              FROM identity_links
             WHERE tenant_id = :tenant_id
               AND (left_key = :key OR right_key = :key)
               AND (
                     CAST(:include_weak AS boolean)
                     OR confidence >= :floor
                     OR decided = 'confirmed'
                   )
             ORDER BY confidence DESC, last_seen DESC
            """
        ),
        {
            "tenant_id": str(tenant_id),
            "key": key,
            "include_weak": bool(include_weak),
            "floor": MERGE_THRESHOLD,
        },
    )
    return [_row(row) for row in result.fetchall()]


async def cluster_for(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    key: str,
    max_depth: int = 3,
) -> list[str]:
    """Every identity that is the same person as ``key``.

    Breadth-first over **merge-strength links only**, bounded. A weak link
    is never traversed, so three weak hops cannot join two identities that
    no single rule was willing to join.

    ``max_depth`` bounds the walk because an estate with one bad strong link
    would otherwise return the whole tenant, and a bounded wrong answer is
    recoverable in a way an unbounded one is not.
    """
    seen = {key}
    frontier = [key]
    for _ in range(max(1, max_depth)):
        if not frontier:
            break
        rows = await db.execute(
            text(
                """
                SELECT left_key, right_key
                  FROM identity_links
                 WHERE tenant_id = :tenant_id
                   AND (left_key = ANY(:keys) OR right_key = ANY(:keys))
                   AND (confidence >= :floor OR decided = 'confirmed')
                   AND (decided IS DISTINCT FROM 'rejected')
                """
            ),
            {"tenant_id": str(tenant_id), "keys": frontier, "floor": MERGE_THRESHOLD},
        )
        discovered: list[str] = []
        for row in rows.fetchall():
            for candidate in (row.left_key, row.right_key):
                if candidate not in seen:
                    seen.add(candidate)
                    discovered.append(candidate)
        frontier = discovered
    return sorted(seen - {key})


async def decide_link(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    link_id: uuid.UUID,
    decision: str,
    user_id: uuid.UUID | str,
) -> dict[str, Any] | None:
    """Record a person confirming or rejecting a link. ``None`` if not theirs.

    A confirmation promotes a weak link to merge strength and a rejection
    demotes a strong one, without touching ``confidence`` — the rule did not
    become more or less certain, a human disagreed with it, and the two
    facts stay separable.
    """
    if decision not in {"confirmed", "rejected"}:
        raise ValueError(f"decision must be 'confirmed' or 'rejected', got {decision!r}")

    result = await db.execute(
        text(
            """
            UPDATE identity_links
               SET decided = :decision,
                   decided_by = :user_id,
                   decided_at = NOW()
             WHERE tenant_id = :tenant_id
               AND id = :link_id
            RETURNING id, left_key, right_key, confidence, rule, evidence,
                   decided, decided_by, decided_at, first_seen, last_seen
            """
        ),
        {
            "tenant_id": str(tenant_id),
            "link_id": str(link_id),
            "decision": decision,
            "user_id": str(user_id),
        },
    )
    row = result.fetchone()
    return _row(row) if row else None
