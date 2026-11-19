"""The ingest cursor orders rows by instant, not by the text the vendor sent.

``BaseConnector.apply_checkpoint`` sorts and compares the vendor's raw
timestamp strings. Text order is not time order once the same instant can be
written more than one way: ``...10:00:00Z`` sorts after ``...10:00:00.500Z``
even though it is half a second earlier, and ``...11:00:00+05:00`` (06:00Z)
sorts after ``...10:00:00Z`` (10:00Z). A row newer than the cursor is then
dropped as already read, and the staged cursor can name the wrong row.

These tests drive the real ESET connector and the real checkpoint machinery.
They fail on the current code and are expected to pass once the cursor
compares parsed instants.
"""

from __future__ import annotations

from datetime import UTC, datetime

from tests.connectors.test_eset_protect import Vendor, _detection

_CURSOR_UUID = "22222222-2222-2222-2222-222222222222"


def _row(uuid: str, occur_time: str) -> dict:
    return {**_detection(uuid, occurred=None), "occurTime": occur_time}


def _instant(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


def test_a_row_a_fraction_of_a_second_newer_than_the_cursor_is_kept() -> None:
    """10:00:00.500Z is later than the cursor 10:00:00Z, so it is new and must be raised."""
    connector = Vendor().connector()
    connector.set_checkpoint({"time": "2026-11-14T10:00:00Z", "id": _CURSOR_UUID})

    fresh = connector.apply_checkpoint([_row("33333333-3333-3333-3333-333333333333", "2026-11-14T10:00:00.500Z")])

    assert [row["uuid"] for row in fresh] == ["33333333-3333-3333-3333-333333333333"], (
        "a detection half a second after the cursor was dropped as already read"
    )


def test_a_row_later_than_a_cursor_written_with_an_offset_is_kept() -> None:
    """The cursor 11:00+05:00 is 06:00Z; a row at 10:00Z is later and must be kept."""
    connector = Vendor().connector()
    connector.set_checkpoint({"time": "2026-11-14T11:00:00+05:00", "id": _CURSOR_UUID})

    fresh = connector.apply_checkpoint([_row("33333333-3333-3333-3333-333333333333", "2026-11-14T10:00:00Z")])

    assert [row["uuid"] for row in fresh] == ["33333333-3333-3333-3333-333333333333"], (
        "a detection at 10:00Z was dropped against a cursor that is 06:00Z"
    )


def test_the_staged_cursor_is_the_newest_instant_in_a_mixed_batch() -> None:
    """Row b (11:00+05:00) is 06:00Z and row a (10:00Z) is later, so the staged cursor must name a."""
    connector = Vendor().connector()
    connector.set_checkpoint(None)

    connector.apply_checkpoint(
        [
            _row("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "2026-11-14T10:00:00Z"),
            _row("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "2026-11-14T11:00:00+05:00"),
        ]
    )

    staged = connector.get_checkpoint()
    assert staged is not None and staged["id"] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", (
        f"the staged cursor is {staged}; the newest detection is aaaa… at 10:00Z"
    )


def test_the_staged_cursor_is_the_fractional_second_row_not_its_whole_second_twin() -> None:
    """10:00:00.500Z is later than 10:00:00Z, so the staged cursor must be the .500 row."""
    connector = Vendor().connector()
    connector.set_checkpoint(None)

    connector.apply_checkpoint(
        [
            _row("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "2026-11-14T10:00:00.500Z"),
            _row("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "2026-11-14T10:00:00Z"),
        ]
    )

    staged = connector.get_checkpoint()
    assert staged is not None and staged["id"] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", (
        f"the staged cursor is {staged}; the newest detection is the .500Z row"
    )
