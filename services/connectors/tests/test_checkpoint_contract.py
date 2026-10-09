"""Ingest checkpoints are a declared contract, not a duck type (10b).

The durable half shipped already: `record_checkpoint` persists a cursor, and
the scheduler advances it only after ingest accepted the batch. What was
missing was adoption — `splunk` was the only one of 84 connectors
implementing it, and the scheduler reached it through
`getattr(connector, "set_checkpoint", None)`, which on the other 83 was
simply absent.

That is the shape worth testing against. A duck-typed optional protocol has
no failing state, only a quiet one: the seed no-opped at `logger.debug` and
nothing could report which connectors resumed and which re-read their
overlap window. So these tests hold two things — the machinery is correct,
and the *count* of adopters is visible rather than assumed.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import BaseConnector, ConnectorSchema


class _Cursored(BaseConnector):
    connector_id = "test_cursored"
    connector_name = "Cursored"
    connector_category = "siem"
    checkpoint_time_field: tuple[str, ...] = ("ts",)
    checkpoint_id_field: tuple[str, ...] = ("uid",)

    @classmethod
    def schema(cls) -> ConnectorSchema:  # pragma: no cover - not exercised
        raise NotImplementedError

    async def test_connection(self) -> dict[str, Any]:  # pragma: no cover
        raise NotImplementedError

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:  # pragma: no cover
        raise NotImplementedError


class _Uncursored(_Cursored):
    connector_id = "test_uncursored"
    checkpoint_time_field: tuple[str, ...] = ()
    checkpoint_id_field: tuple[str, ...] = ()


def _row(ts: str, uid: str) -> dict[str, Any]:
    return {"ts": ts, "uid": uid}


class TestTheContractIsAskable:
    def test_a_connector_that_declares_both_fields_checkpoints(self) -> None:
        assert _Cursored.checkpoints() is True

    def test_the_default_is_not_checkpointing_and_says_so(self) -> None:
        """The honest default. A connector whose cursor fields nobody has
        identified must not pretend to have one — but it is now *declared*
        not-checkpointing, which is the difference from an absent method."""
        assert _Uncursored.checkpoints() is False

    def test_a_time_field_without_a_tie_breaker_does_not_count(self) -> None:
        """Two events in the same second are ordinary. A cursor on time alone
        either loses the second one or replays the first forever."""

        class _HalfDeclared(_Cursored):
            connector_id = "test_half"
            checkpoint_id_field: tuple[str, ...] = ()

        assert _HalfDeclared.checkpoints() is False

    def test_every_connector_answers_the_question(self) -> None:
        """The property the getattr could not provide: ask any of the 84."""
        for connector_id, cls in CONNECTOR_REGISTRY.items():
            assert isinstance(cls.checkpoints(), bool), connector_id
            assert callable(cls.set_checkpoint)
            assert callable(cls.get_checkpoint)


class TestTheMachineryIsCorrect:
    def test_rows_are_ordered_by_time_then_id(self) -> None:
        c = _Cursored()
        rows = [_row("t3", "c"), _row("t1", "b"), _row("t1", "a")]

        assert [r["uid"] for r in c.apply_checkpoint(rows)] == ["a", "b", "c"]

    def test_anything_at_or_before_the_cursor_is_dropped(self) -> None:
        """This is what suppresses the duplicates an overlapping poll
        window produces — the reason the overlap is safe to keep."""
        c = _Cursored()
        c.set_checkpoint({"time": "t2", "id": "b"})
        rows = [_row("t1", "a"), _row("t2", "b"), _row("t2", "c"), _row("t3", "d")]

        assert [r["uid"] for r in c.apply_checkpoint(rows)] == ["c", "d"]

    def test_the_cursor_advances_to_the_last_fresh_row(self) -> None:
        c = _Cursored()
        c.apply_checkpoint([_row("t1", "a"), _row("t2", "b")])

        assert c.get_checkpoint() == {"time": "t2", "id": "b"}

    def test_nothing_new_leaves_the_cursor_unmoved(self) -> None:
        """`None` rather than the old value: the scheduler writes only what
        moved, so a poll that found nothing must not rewrite the row."""
        c = _Cursored()
        c.set_checkpoint({"time": "t9", "id": "z"})

        assert c.apply_checkpoint([_row("t1", "a")]) == []
        assert c.get_checkpoint() is None

    def test_two_rows_sharing_a_timestamp_both_survive(self) -> None:
        c = _Cursored()
        kept = c.apply_checkpoint([_row("t1", "a"), _row("t1", "b")])

        assert {r["uid"] for r in kept} == {"a", "b"}

    def test_a_connector_that_does_not_checkpoint_passes_rows_through(self) -> None:
        """Safe to call unconditionally from any `fetch_alerts`."""
        c = _Uncursored()
        rows = [_row("t3", "c"), _row("t1", "a")]

        assert c.apply_checkpoint(rows) == rows
        assert c.get_checkpoint() is None

    def test_a_malformed_seed_is_treated_as_no_cursor(self) -> None:
        c = _Cursored()
        for junk in (None, {}, {"time": "", "id": ""}, "not-a-dict"):
            c.set_checkpoint(junk)  # type: ignore[arg-type]
            assert c.apply_checkpoint([_row("t1", "a")]) == [_row("t1", "a")]


class TestAdoptionIsCountedNotAssumed:
    #: Every connector that resumes from a persisted cursor, with the fields
    #: it resumes on. Shrink-only in the sense that matters: a connector
    #: dropping out of this list fails the test rather than going quiet,
    #: which is exactly what the `getattr` could not do.
    EXPECTED = {
        "splunk": (("_time", "event_time"), ("event_id", "_cd")),
        "okta": (("published",), ("uuid",)),
        "m365_audit": (("CreationTime",), ("Id",)),
        "aws_cloudtrail": (("EventTime",), ("EventId",)),
        "azure_activity": (("eventTimestamp",), ("eventDataId", "id")),
        # Depth plan 4.1. These three read a queue or an object store rather
        # than a time-windowed API, so the cursor is doing a different job:
        # the queue already guarantees nothing is lost, and the cursor exists
        # to drop the duplicate that at-least-once delivery guarantees will
        # eventually arrive. All three therefore carry a synthetic
        # `record_id` built from the object or message identity, which is
        # what makes it stable across a re-read.
        "aws_cloudtrail_s3": (("event_time",), ("record_id",)),
        "gcp_pubsub": (("event_time",), ("record_id",)),
        "azure_event_hubs": (("event_time",), ("record_id",)),
    }

    def test_the_adopters_are_exactly_the_ones_recorded(self) -> None:
        actual = {cid for cid, cls in CONNECTOR_REGISTRY.items() if cls.checkpoints()}

        assert actual == set(self.EXPECTED), (
            "the set of checkpointing connectors changed. Adding one is good — record it here. "
            "Losing one silently is the defect this replaces."
        )

    @pytest.mark.parametrize("connector_id", sorted(EXPECTED))
    def test_each_adopter_declares_the_fields_recorded_for_it(self, connector_id: str) -> None:
        cls = CONNECTOR_REGISTRY[connector_id]
        time_fields, id_fields = self.EXPECTED[connector_id]

        assert cls.checkpoint_time_field == time_fields
        assert cls.checkpoint_id_field == id_fields

    def test_the_rest_are_honestly_not_checkpointing(self) -> None:
        """Not a failure. A connector without a declared cursor re-reads its
        overlap window after a restart, which is safe and loses events older
        than that window. The number is here so the gap is legible."""
        without = sorted(cid for cid, cls in CONNECTOR_REGISTRY.items() if not cls.checkpoints())

        assert len(without) == len(CONNECTOR_REGISTRY) - len(self.EXPECTED)
        assert len(CONNECTOR_REGISTRY) >= 84


class TestTheSchedulerNoLongerDuckTypes:
    def test_it_calls_the_contract_directly(self) -> None:
        """The getattr is what made 83 silent no-ops invisible."""
        from pathlib import Path

        source = (Path(__file__).resolve().parents[1] / "app" / "scheduler.py").read_text(encoding="utf-8")
        # Comments stripped first: the scheduler's own comment quotes the
        # pattern it replaced, and a gate that cannot tell code from prose
        # about the code fires on its own explanation.
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))

        assert 'getattr(connector, "set_checkpoint"' not in code
        assert 'getattr(connector, "get_checkpoint"' not in code
        assert "connector.set_checkpoint(" in code
        assert "connector.get_checkpoint()" in code

    def test_the_advance_still_happens_only_after_ingest_accepts(self) -> None:
        """The whole safety property of the persisted cursor: a batch ingest
        rejected must be re-read, not skipped."""
        from pathlib import Path

        source = (Path(__file__).resolve().parents[1] / "app" / "scheduler.py").read_text(encoding="utf-8")
        accept_index = source.index('accepted = int(result.get("accepted", 0) or 0)')
        advance_index = source.index("new_checkpoint = connector.get_checkpoint()")

        assert accept_index < advance_index
