"""Tests for audit-log tamper-evident hash chain.

The hash chain is the only mechanism that defends ``audit_log`` against
a privileged operator (or stolen DB credentials) that bypasses the
immutability trigger via ``ALTER TABLE … DISABLE TRIGGER ALL`` /
``TRUNCATE`` and forges a replacement history. Anyone — auditor or
incident responder — can replay the chain on a CSV export to prove the
history is intact.

This suite locks down the contract that compliance teams rely on:

1. ``compute_entry_hash`` is **deterministic** for a given set of inputs
   (same row + same prev_hash → same digest).
2. Mutating ANY business-relevant field changes the digest.
3. ``prev_hash`` is mixed in so the chain is order-dependent
   (reordering rows breaks verification).
4. ``verify_chain`` accepts a valid chain.
5. ``verify_chain`` rejects: a deleted row, a rewritten row, a reordered
   row, and a row whose ``prev_hash`` doesn't link.
6. Legacy rows (no ``entry_hash``) are tolerated at the head of a
   tenant's history — but a gap *after* the chain has started is a
   forgery signal.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from app.services.audit_hash import compute_entry_hash, verify_chain


def _ts(seconds: int) -> datetime:
    return datetime(2026, 5, 9, 12, 0, seconds, tzinfo=UTC)


def _row(
    *,
    prev_hash: str | None,
    row_id: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None,
    actor_id: uuid.UUID | None = None,
    actor_email: str | None = "analyst@example.com",
    actor_ip: str | None = "10.0.0.1",
    action: str = "cases:update",
    resource: str | None = "case",
    resource_id: str | None = "case-42",
    changes: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a row dict + its computed ``entry_hash`` for chain replay."""
    rid = row_id or uuid.UUID("11111111-1111-1111-1111-111111111111")
    tid = tenant_id or uuid.UUID("22222222-2222-2222-2222-222222222222")
    aid = actor_id if actor_id is not None else uuid.UUID("33333333-3333-3333-3333-333333333333")
    ts = created_at or _ts(0)
    digest = compute_entry_hash(
        prev_hash=prev_hash,
        row_id=rid,
        tenant_id=tid,
        actor_id=aid,
        actor_email=actor_email,
        actor_ip=actor_ip,
        action=action,
        resource=resource,
        resource_id=resource_id,
        changes=changes,
        metadata=metadata,
        created_at=ts,
    )
    return {
        "id": rid,
        "tenant_id": tid,
        "actor_id": aid,
        "actor_email": actor_email,
        "actor_ip": actor_ip,
        "action": action,
        "resource": resource,
        "resource_id": resource_id,
        "changes": changes,
        "metadata": metadata,
        "created_at": ts,
        "prev_hash": prev_hash,
        "entry_hash": digest,
    }


# ---------------------------------------------------------------------------
# compute_entry_hash
# ---------------------------------------------------------------------------


class TestComputeEntryHash:
    def test_deterministic(self):
        """Same inputs → same digest. The whole chain rests on this."""
        kwargs = {
            "prev_hash": None,
            "row_id": uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            "tenant_id": uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            "actor_id": uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            "actor_email": "a@b.com",
            "actor_ip": "1.2.3.4",
            "action": "cases:update",
            "resource": "case",
            "resource_id": "case-1",
            "changes": {"status": ["open", "closed"]},
            "metadata": {"request_id": "rid-1"},
            "created_at": _ts(0),
        }
        a = compute_entry_hash(**kwargs)
        b = compute_entry_hash(**kwargs)
        assert a == b
        assert len(a) == 64, "sha256 hex digest must be 64 chars"

    def test_prev_hash_changes_digest(self):
        """Same row, different prev_hash → different digest. Order-bound."""
        base_kwargs = {
            "row_id": uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            "tenant_id": uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            "actor_id": None,
            "actor_email": None,
            "actor_ip": None,
            "action": "x",
            "resource": "y",
            "resource_id": "z",
            "changes": None,
            "metadata": None,
            "created_at": _ts(0),
        }
        h1 = compute_entry_hash(prev_hash=None, **base_kwargs)
        h2 = compute_entry_hash(prev_hash="deadbeef", **base_kwargs)
        h3 = compute_entry_hash(prev_hash="cafe", **base_kwargs)
        assert h1 != h2 != h3
        assert h1 != h3

    @pytest.mark.parametrize(
        "field,new_value",
        [
            ("actor_email", "different@example.com"),
            ("actor_ip", "9.9.9.9"),
            ("action", "cases:delete"),
            ("resource", "alert"),
            ("resource_id", "case-999"),
            ("changes", {"status": ["open", "investigating"]}),
            ("metadata", {"request_id": "rid-2"}),
        ],
    )
    def test_mutating_any_business_field_changes_digest(self, field, new_value):
        """A forgery that changes a single business-relevant field must be detectable."""
        base = {
            "prev_hash": "abc",
            "row_id": uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            "tenant_id": uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            "actor_id": uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            "actor_email": "a@b.com",
            "actor_ip": "1.2.3.4",
            "action": "cases:update",
            "resource": "case",
            "resource_id": "case-1",
            "changes": {"status": ["open", "closed"]},
            "metadata": {"request_id": "rid-1"},
            "created_at": _ts(0),
        }
        h_before = compute_entry_hash(**base)
        mutated = dict(base)
        mutated[field] = new_value
        h_after = compute_entry_hash(**mutated)
        assert h_before != h_after, f"changing {field} must change the chain digest; otherwise a forgery would pass verification"

    def test_changing_created_at_changes_digest(self):
        base = {
            "prev_hash": None,
            "row_id": uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            "tenant_id": uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            "actor_id": None,
            "actor_email": None,
            "actor_ip": None,
            "action": "x",
            "resource": "y",
            "resource_id": "z",
            "changes": None,
            "metadata": None,
        }
        h1 = compute_entry_hash(**base, created_at=_ts(0))
        h2 = compute_entry_hash(**base, created_at=_ts(1))
        assert h1 != h2

    def test_exotic_changes_values_do_not_crash(self):
        """Audit metadata occasionally contains non-JSON-native types."""

        class WeirdEnum:
            def __str__(self) -> str:
                return "weird"

        # Should not raise — the helper must fall back to stringification.
        h = compute_entry_hash(
            prev_hash=None,
            row_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            tenant_id=uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            actor_id=None,
            actor_email=None,
            actor_ip=None,
            action="x",
            resource=None,
            resource_id=None,
            changes={"thing": WeirdEnum()},
            metadata=None,
            created_at=_ts(0),
        )
        assert len(h) == 64


# ---------------------------------------------------------------------------
# verify_chain
# ---------------------------------------------------------------------------


class TestVerifyChain:
    def _build_chain(self, n: int) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        prev: str | None = None
        for i in range(n):
            row = _row(
                prev_hash=prev,
                row_id=uuid.UUID(f"{i:08x}-0000-4000-8000-000000000000"),
                action=f"cases:update#{i}",
                created_at=_ts(i),
            )
            rows.append(row)
            prev = row["entry_hash"]
        return rows

    def test_empty_chain_passes(self):
        ok, idx, reason = verify_chain([])
        assert ok is True
        assert idx is None
        assert reason is None

    def test_valid_chain_passes(self):
        rows = self._build_chain(5)
        ok, idx, reason = verify_chain(rows)
        assert ok, f"verification failed at {idx}: {reason}"

    def test_rewritten_row_is_detected(self):
        rows = self._build_chain(5)
        # An operator tries to whitewash row 2 by editing the action.
        rows[2]["action"] = "cases:read"
        ok, idx, reason = verify_chain(rows)
        assert ok is False
        # Either row 2 fails directly (entry_hash mismatch) or row 3 fails
        # because its prev_hash no longer matches the recomputed chain.
        assert idx in (2, 3)
        assert reason is not None

    def test_deleted_row_is_detected(self):
        rows = self._build_chain(5)
        # Drop row 2 — the chain now skips a link.
        del rows[2]
        ok, idx, reason = verify_chain(rows)
        assert ok is False
        # The break shows up at the row that used to follow the deleted one.
        assert idx == 2
        assert reason is not None

    def test_reordered_rows_are_detected(self):
        rows = self._build_chain(5)
        rows[1], rows[2] = rows[2], rows[1]
        ok, idx, reason = verify_chain(rows)
        assert ok is False
        assert idx is not None
        assert reason is not None

    def test_prev_hash_tampering_is_detected(self):
        rows = self._build_chain(3)
        rows[1]["prev_hash"] = "deadbeef" * 8  # bogus 64-char hex
        ok, idx, reason = verify_chain(rows)
        assert ok is False
        assert idx == 1
        assert "prev_hash" in (reason or "")

    def test_entry_hash_tampering_is_detected(self):
        rows = self._build_chain(3)
        rows[1]["entry_hash"] = "0" * 64
        ok, idx, reason = verify_chain(rows)
        assert ok is False
        assert idx == 1
        assert "entry_hash" in (reason or "")

    def test_legacy_rows_without_chain_are_skipped(self):
        """Existing deployments without backfilled hashes must still verify."""
        rows = self._build_chain(2)
        # Two legacy rows at the head (no entry_hash). Then the chained pair.
        legacy_a = dict(rows[0])
        legacy_a["entry_hash"] = None
        legacy_a["prev_hash"] = None
        legacy_b = dict(rows[1])
        legacy_b["entry_hash"] = None
        legacy_b["prev_hash"] = None
        # Re-chain the tail from genesis since we treat it as the start.
        fresh_a = _row(prev_hash=None, created_at=_ts(10))
        fresh_b = _row(prev_hash=fresh_a["entry_hash"], created_at=_ts(11))
        ok, idx, reason = verify_chain([legacy_a, legacy_b, fresh_a, fresh_b])
        assert ok, f"verification failed at {idx}: {reason}"

    def test_gap_after_chain_start_is_detected(self):
        """Once we have chained rows, every subsequent row MUST be chained."""
        a = _row(prev_hash=None, created_at=_ts(0))
        # The "forgery" — a row inserted without joining the chain.
        forgery = dict(a)
        forgery["id"] = uuid.UUID("ffffffff-ffff-4fff-8fff-ffffffffffff")
        forgery["created_at"] = _ts(1)
        forgery["prev_hash"] = None
        forgery["entry_hash"] = None
        ok, idx, reason = verify_chain([a, forgery])
        assert ok is False
        assert idx == 1
        assert "missing" in (reason or "").lower() or "chain" in (reason or "").lower()
