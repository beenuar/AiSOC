"""Tamper-evident hash chain for audit log entries.

The ``audit_log`` table is already write-only (trigger-enforced) and
tenant-isolated (RLS). What that combination does *not* defend against
is a privileged operator with SQL access doing
``TRUNCATE audit_log`` / ``DROP TABLE`` / ``DELETE WHERE …`` (via
``ALTER TABLE … DISABLE TRIGGER ALL``) and replacing the history with a
forgery. The trigger only fires on UPDATE/DELETE through the normal
SQL path; a sufficiently privileged actor can bypass it.

A hash chain closes that gap **without** trusting Postgres. Every audit
row stores:

* ``prev_hash``  — the ``entry_hash`` of the previous audit row for
  the same tenant, or ``None`` for the first row.
* ``entry_hash`` — sha256 over a canonical serialization of this row's
  business fields, mixed with ``prev_hash``.

Anyone — including an external auditor — can replay the chain
deterministically and prove that no row was deleted, reordered, or
silently rewritten. The verification logic is intentionally pure (no
DB access) so it can run on a CSV export as easily as a live row.

The algorithm:

1. Build a stable, sorted-key JSON payload of the fields that define
   the audit event (``tenant_id``, ``actor_id``, ``actor_email``,
   ``actor_ip``, ``action``, ``resource``, ``resource_id``,
   ``changes`` already-redacted, ``metadata``, ``created_at`` in
   ISO-8601, and the row ``id`` itself).
2. Prepend the ``prev_hash`` (or an empty string for the genesis row).
3. ``entry_hash = sha256(payload).hexdigest()``.

The set of hashed fields is deliberately conservative — adding a field
is a chain-breaking change and requires a schema migration. We
explicitly include the row ``id`` because the table assigns one by
default and including it makes the chain agnostic to insertion order
within the same wall-clock microsecond.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any


def _canonicalise(value: Any) -> Any:
    """Map non-JSON-native types into something ``json.dumps`` can encode deterministically."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        # ISO 8601 with explicit offset; required for chain stability
        # across DB drivers that may otherwise stringify with subtle
        # whitespace differences.
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _canonicalise(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_canonicalise(v) for v in value]
    # Fallback: stringify. Audit metadata occasionally contains exotic
    # values (e.g. enum instances); we never want the hash to crash.
    return str(value)


def compute_entry_hash(
    *,
    prev_hash: str | None,
    row_id: uuid.UUID,
    tenant_id: uuid.UUID,
    actor_id: uuid.UUID | None,
    actor_email: str | None,
    actor_ip: str | None,
    action: str,
    resource: str | None,
    resource_id: str | None,
    changes: dict[str, Any] | None,
    metadata: dict[str, Any] | None,
    created_at: datetime,
) -> str:
    """Compute the SHA-256 hash of the canonical row contents + prev hash.

    The ``changes`` payload MUST already have been passed through
    :func:`app.services.audit_redaction.redact_changes` — the chain is
    over the *persisted* form, not the original caller-supplied dict.
    """
    body = {
        "id": _canonicalise(row_id),
        "tenant_id": _canonicalise(tenant_id),
        "actor_id": _canonicalise(actor_id),
        "actor_email": actor_email,
        "actor_ip": actor_ip,
        "action": action,
        "resource": resource,
        "resource_id": resource_id,
        "changes": _canonicalise(changes),
        "metadata": _canonicalise(metadata),
        "created_at": _canonicalise(created_at),
    }
    serialised = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    h = hashlib.sha256()
    h.update((prev_hash or "").encode("utf-8"))
    # Domain separator stops accidental collisions if anyone reuses the
    # encoded body in another hash context.
    h.update(b"\x1faudit-log-v1\x1f")
    h.update(serialised.encode("utf-8"))
    return h.hexdigest()


def verify_chain(rows: list[dict[str, Any]]) -> tuple[bool, int | None, str | None]:
    """Replay ``rows`` (oldest → newest, same tenant) and verify the chain.

    Each row must expose the same field names as
    :func:`compute_entry_hash` plus ``prev_hash`` and ``entry_hash``.

    Returns ``(True, None, None)`` on success, or
    ``(False, index, reason)`` pointing at the first violating row.
    A row missing ``entry_hash`` is treated as legacy / unchained and
    skipped — the chain "starts" from the first row that carries one.
    This keeps existing deployments verifiable without a backfill.
    """
    prev_hash: str | None = None
    started = False
    for idx, row in enumerate(rows):
        stored = row.get("entry_hash")
        if stored is None:
            if started:
                # Once a tenant has chained rows, every subsequent row
                # must also be chained. A gap = tampering.
                return False, idx, "chain interrupted: entry_hash missing"
            continue
        started = True

        # prev_hash on the row must match the chain we have so far.
        recorded_prev = row.get("prev_hash")
        if recorded_prev != prev_hash:
            return False, idx, "prev_hash mismatch"

        computed = compute_entry_hash(
            prev_hash=prev_hash,
            row_id=row["id"],
            tenant_id=row["tenant_id"],
            actor_id=row.get("actor_id"),
            actor_email=row.get("actor_email"),
            actor_ip=row.get("actor_ip"),
            action=row["action"],
            resource=row.get("resource"),
            resource_id=row.get("resource_id"),
            changes=row.get("changes"),
            metadata=row.get("metadata"),
            created_at=row["created_at"],
        )
        if computed != stored:
            return False, idx, "entry_hash mismatch"
        prev_hash = computed
    return True, None, None


__all__ = [
    "compute_entry_hash",
    "verify_chain",
]
