"""Batched alert writes keep the single path's contract.

Gap-closure wave 7. `persist` acquires a pooled connection and makes a
round trip per alert, so a deployment taking 200 alerts/s makes 200
acquisitions and 200 round trips a second and spends most of its time
waiting rather than working.

A faster path that changes semantics is a different feature, so what
is pinned here is the contract rather than the speed.
"""

from __future__ import annotations

import re

import pytest
from app.services.alert_sink import PersistOutcome


class _Conn:
    def __init__(self, behaviour) -> None:  # noqa: ANN001
        self.behaviour = behaviour
        self.calls = 0

    async def fetchrow(self, _sql, *args):  # noqa: ANN001, ANN002, ANN202
        self.calls += 1
        return self.behaviour(self.calls, args)

    async def execute(self, *_a, **_k):  # noqa: ANN002, ANN003, ANN202
        return None


class _Acquire:
    def __init__(self, conn) -> None:  # noqa: ANN001
        self.conn = conn

    async def __aenter__(self):  # noqa: ANN204
        return self.conn

    async def __aexit__(self, *_exc) -> bool:  # noqa: ANN002
        return False


class _Pool:
    def __init__(self, conn) -> None:  # noqa: ANN001
        self.conn = conn
        self.acquisitions = 0

    def acquire(self):  # noqa: ANN201
        self.acquisitions += 1
        return _Acquire(self.conn)


class TestTheArgumentTupleHasOneDefinition:
    def test_it_matches_the_column_count_in_the_insert(self) -> None:
        """The two paths were two copies of a 25-element tuple, which is
        the pair that drifts by one column and writes a confidence score
        into a narrative without anything failing."""
        from app.services.alert_sink import _INSERT_SQL

        # Matched with a regex rather than by splitting on whitespace: almost
        # every placeholder in this statement carries a cast or a trailing
        # comma (`$9::jsonb,`), so the whitespace form only ever saw the two
        # bare ones and the width assertion below was nearly vacuous.
        placeholders = {int(n) for n in re.findall(r"\$(\d+)", _INSERT_SQL)}
        assert placeholders, "no positional placeholders found; this test is checking nothing"
        assert max(placeholders) >= 20, "the insert shrank unexpectedly — re-check _insert_args"
        # No gaps: asyncpg binds positionally, so a skipped number means every
        # argument after it lands in the wrong column.
        assert placeholders == set(range(1, max(placeholders) + 1)), (
            f"placeholder numbering has holes: {sorted(set(range(1, max(placeholders) + 1)) - placeholders)}"
        )


@pytest.mark.asyncio
class TestBatchContract:
    async def test_one_result_per_input_in_order(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Callers branch on `PersistOutcome`; a summary would make a
        duplicate indistinguishable from an insert."""
        from app.services.alert_sink import AlertSink

        sink = AlertSink.__new__(AlertSink)
        conn = _Conn(lambda n, args: {"id": args[0]})
        pool = _Pool(conn)
        monkeypatch.setattr(sink, "_ensure_pool", lambda: _coro(pool), raising=False)
        monkeypatch.setattr(sink, "_link_source_finding", lambda *a, **k: _coro(None), raising=False)
        monkeypatch.setattr(sink, "_connect_failed_logged", False, raising=False)

        batch = [_fused(i) for i in range(4)]
        results = await sink.persist_many(batch)

        assert len(results) == 4
        assert all(r.outcome is PersistOutcome.INSERTED for r in results)

    async def test_one_connection_for_the_whole_batch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The point of the change. Four alerts used to mean four
        acquisitions."""
        from app.services.alert_sink import AlertSink

        sink = AlertSink.__new__(AlertSink)
        conn = _Conn(lambda n, args: {"id": args[0]})
        pool = _Pool(conn)
        monkeypatch.setattr(sink, "_ensure_pool", lambda: _coro(pool), raising=False)
        monkeypatch.setattr(sink, "_link_source_finding", lambda *a, **k: _coro(None), raising=False)
        monkeypatch.setattr(sink, "_connect_failed_logged", False, raising=False)

        await sink.persist_many([_fused(i) for i in range(4)])
        assert pool.acquisitions == 1, f"{pool.acquisitions} acquisitions for one batch"
        assert conn.calls == 4

    async def test_one_bad_row_does_not_take_the_batch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Same contract as the single path, where a malformed alert
        must not wedge the consumer."""
        from app.services.alert_sink import AlertSink

        def behaviour(n, args):  # noqa: ANN001, ANN202
            if n == 2:
                raise RuntimeError("malformed row")
            return {"id": args[0]}

        sink = AlertSink.__new__(AlertSink)
        pool = _Pool(_Conn(behaviour))
        monkeypatch.setattr(sink, "_ensure_pool", lambda: _coro(pool), raising=False)
        monkeypatch.setattr(sink, "_link_source_finding", lambda *a, **k: _coro(None), raising=False)
        monkeypatch.setattr(sink, "_connect_failed_logged", False, raising=False)

        results = await sink.persist_many([_fused(i) for i in range(3)])
        outcomes = [r.outcome for r in results]
        assert outcomes[1] is PersistOutcome.FAILED
        assert outcomes[0] is PersistOutcome.INSERTED
        assert outcomes[2] is PersistOutcome.INSERTED, "a later row was lost to an earlier failure"

    async def test_an_empty_batch_is_not_an_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.services.alert_sink import AlertSink

        sink = AlertSink.__new__(AlertSink)
        assert await sink.persist_many([]) == []


def _coro(value):  # noqa: ANN001, ANN202
    async def _inner():  # noqa: ANN202
        return value

    return _inner()


def _fused(index: int):  # noqa: ANN202
    """A fused alert with only what the sink reads."""
    pytest.importorskip("app.models")
    from types import SimpleNamespace
    from uuid import uuid4

    from app.services.alert_sink import FusionDecision

    alert = SimpleNamespace(
        tenant_id=uuid4(),
        title=f"alert {index}",
        description=None,
        severity=SimpleNamespace(value="high"),
        mitre_tactics=[],
        mitre_techniques=[],
        raw_event={},
        fingerprint=lambda: f"fp-{index}",
        event_time=None,
        connector_id=None,
        connector_type=None,
        source_event_ids=[],
        ocsf_class_uid=None,
        rule_id=None,
        rule_name=None,
        external_id=None,
        # The IOC and entity helpers read these. A namespace missing
        # them raised inside the sink's own except clause and every row
        # came back FAILED — a double more *limited* than the real
        # model, which is the mirror of the usual problem here.
        src_ip=None,
        dst_ip=None,
        file_hash=None,
        domain=None,
        url=None,
        hostname=None,
        username=None,
        process_name=None,
    )
    return SimpleNamespace(
        id=uuid4(),
        alert=alert,
        fusion_decision=FusionDecision.NEW_ALERT,
        confidence_score=0.5,
        confidence_label=SimpleNamespace(value="medium"),
        confidence_rationale=[],
        narrative="",
        anomaly_score=0.0,
        correlated_events=[],
    )
