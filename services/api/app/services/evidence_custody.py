"""Append tamper-evident custody entries to a case's evidence chain.

Wave 0 of the gap-closure plan.

`aisoc_cases.evidence_chain` has existed since migration 012. Three
places read it — the case detail, `GET /cases/{id}/evidence`, and the
case summary — and **nothing has ever written to it**, so the evidence
report an auditor exports has always been an empty list under a heading
that says "Evidence Chain".

That is worse than having no report. An empty chain under that heading
reads as "no evidence was handled", not as "this product does not record
custody".

What a custody entry records
------------------------------
Four things, which is what a chain of custody is for: **what** item,
**what happened** to it, **when**, and **who** did it. The actor is the
authenticated principal rather than a free-text name, because the column
an auditor reads must not be caller-supplied.

Why it is hash-chained
----------------------
Each entry carries the hash of the one before it, computed over a
canonical serialisation, exactly as `audit_hash` does for the audit log.
That makes a *silent* edit detectable: changing an entry breaks every
hash after it, and removing one breaks the link across the gap. It does
not make editing impossible — anyone with database access can rewrite
the whole chain — so this is tamper **evidence**, not tamper
**proofing**, and :func:`verify_chain` says which entry first disagrees
rather than returning a bare boolean.

The chain lives in the case's own JSONB column rather than a side table
so that it moves with the case: an export, a backup restore or a tenant
migration that carried the case but not its custody record would be a
chain with a hole in it and no way to tell.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

__all__ = [
    "CUSTODY_ACTIONS",
    "build_entry",
    "compute_entry_hash",
    "verify_chain",
]

#: The vocabulary. A closed set rather than free text, because a custody
#: log whose verbs vary by call site cannot be filtered or audited.
CUSTODY_ACTIONS = (
    "case_opened",
    "alert_linked",
    "alert_unlinked",
    "observable_added",
    "status_changed",
    "investigation_launched",
    "artifact_attached",
    "case_closed",
)


def _canonical(payload: dict[str, Any]) -> bytes:
    """One byte representation, so a hash is reproducible by a reader."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def compute_entry_hash(entry: dict[str, Any], prev_hash: str | None) -> str:
    """SHA-256 over this entry's content mixed with its predecessor.

    `entry_hash` is excluded from its own input for the obvious reason.
    The previous hash goes in first so that the genesis entry (with no
    predecessor) is still distinguishable from one whose predecessor
    hashed to the empty string.
    """
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    digest = hashlib.sha256()
    digest.update((prev_hash or "").encode("utf-8"))
    digest.update(b"\x00")
    digest.update(_canonical(body))
    return digest.hexdigest()


def build_entry(
    *,
    action: str,
    actor_id: Any,
    actor_email: str | None = None,
    item: str | None = None,
    detail: dict[str, Any] | None = None,
    prev_hash: str | None = None,
    at: datetime | None = None,
) -> dict[str, Any]:
    """One custody entry, hashed against the chain it will join.

    `action` outside :data:`CUSTODY_ACTIONS` raises. A typo'd verb would
    be stored happily and then never match a filter, which is the quiet
    failure this module exists to stop repeating.
    """
    if action not in CUSTODY_ACTIONS:
        raise ValueError(f"unknown custody action {action!r}; expected one of {list(CUSTODY_ACTIONS)}")

    entry: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "action": action,
        "at": (at or datetime.now(UTC)).isoformat(),
        "actor_id": str(actor_id) if actor_id is not None else None,
        "actor_email": actor_email,
        "item": item,
        "detail": detail or {},
        "prev_hash": prev_hash,
    }
    entry["entry_hash"] = compute_entry_hash(entry, prev_hash)
    return entry


def append_entry(chain: list[dict[str, Any]] | None, **kwargs: Any) -> list[dict[str, Any]]:
    """Return the chain with one entry appended, linked to the current tail."""
    existing = list(chain or [])
    prev = existing[-1].get("entry_hash") if existing else None
    existing.append(build_entry(prev_hash=prev, **kwargs))
    return existing


def verify_chain(chain: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Recompute every link and name the first that disagrees.

    Returns a report rather than a boolean: "the chain is broken" sends an
    auditor to read all of it, while "entry 4 of 9 does not match" sends
    them to the row that changed.
    """
    entries = list(chain or [])
    if not entries:
        return {"intact": True, "entries": 0, "broken_at": None, "reason": None}

    prev_hash: str | None = None
    for index, entry in enumerate(entries):
        if entry.get("prev_hash") != prev_hash:
            return {
                "intact": False,
                "entries": len(entries),
                "broken_at": index,
                "reason": (
                    f"entry {index} links to {entry.get('prev_hash')!r} but the entry before it "
                    f"hashes to {prev_hash!r} — an entry was removed, reordered or inserted"
                ),
            }
        expected = compute_entry_hash(entry, prev_hash)
        if entry.get("entry_hash") != expected:
            return {
                "intact": False,
                "entries": len(entries),
                "broken_at": index,
                "reason": (
                    f"entry {index} carries hash {entry.get('entry_hash')!r} but its contents "
                    f"hash to {expected!r} — the entry was edited after it was written"
                ),
            }
        prev_hash = entry["entry_hash"]

    return {"intact": True, "entries": len(entries), "broken_at": None, "reason": None}
