"""The ingest cursor orders rows by instant, not by the text the vendor sent (#1970).

``BaseConnector.apply_checkpoint`` used to sort and compare the vendor's raw
timestamp strings. Text order is not time order once the same instant can be
written more than one way: ``...10:00:00.500Z`` sorts before ``...10:00:00Z``
even though it is half a second later, and ``...11:00:00+05:00`` (06:00Z)
sorts after ``...10:00:00Z``. A row newer than the cursor was then dropped as
already read, and the staged cursor could name the wrong row.

These tests drive the real ESET connector and the real checkpoint machinery.
They fail on the current code and pass once the cursor compares parsed
instants, with the id breaking ties within one instant.
"""

from __future__ import annotations

from tests.connectors.test_eset_protect import Vendor, _detection

_CURSOR_UUID = "22222222-2222-2222-2222-222222222222"


def _row(uuid: str, occur_time: str) -> dict:
    return {**_detection(uuid, occurred=None), "occurTime": occur_time}


def test_a_row_half_a_second_newer_than_the_cursor_is_kept() -> None:
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


def test_the_staged_cursor_names_the_newest_instant_in_a_mixed_batch() -> None:
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
        f"the staged cursor is {staged}; the newest detection is aaaa at 10:00Z"
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


def test_a_row_at_the_cursor_is_dropped_and_its_same_instant_successor_is_kept() -> None:
    """The tie-break is the id: the row the cursor names is already read, the
    row sharing its instant with a greater id is not."""
    connector = Vendor().connector()
    connector.set_checkpoint({"time": "2026-11-14T10:00:00Z", "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"})

    fresh = connector.apply_checkpoint(
        [
            _row("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "2026-11-14T10:00:00.500Z"),
            _row("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "2026-11-14T10:00:00Z"),
            _row("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "2026-11-14T10:00:00Z"),
        ]
    )

    assert [row["uuid"] for row in fresh] == [
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    ], "the cursor row was re-raised, or its same-instant successor was dropped"


def test_a_naive_timestamp_is_read_as_utc() -> None:
    """A cursor with no offset names a UTC instant, so a row half a second
    later is new and a row a second earlier is already read."""
    connector = Vendor().connector()
    connector.set_checkpoint({"time": "2026-11-14T10:00:00", "id": _CURSOR_UUID})

    fresh = connector.apply_checkpoint(
        [
            _row("33333333-3333-3333-3333-333333333333", "2026-11-14T10:00:00.500Z"),
            _row("44444444-4444-4444-4444-444444444444", "2026-11-14T09:59:59Z"),
        ]
    )

    assert [row["uuid"] for row in fresh] == ["33333333-3333-3333-3333-333333333333"]


def test_a_row_whose_time_does_not_parse_is_kept_not_dropped() -> None:
    """A time this side cannot parse is not a reason to drop a row: it cannot
    be proven older than the cursor, so it is raised."""
    connector = Vendor().connector()
    connector.set_checkpoint({"time": "2026-11-14T10:00:00Z", "id": _CURSOR_UUID})

    fresh = connector.apply_checkpoint([_row("33333333-3333-3333-3333-333333333333", "yesterday")])

    assert [row["uuid"] for row in fresh] == ["33333333-3333-3333-3333-333333333333"]


def test_unparseable_times_keep_the_old_text_comparison() -> None:
    """The fallback for times no parser can place is the previous behaviour:
    rows at or before the cursor as text are dropped, the rest are kept."""
    connector = Vendor().connector()
    connector.set_checkpoint({"time": "t2", "id": "b"})

    fresh = connector.apply_checkpoint([_row("a", "t1"), _row("b", "t2"), _row("c", "t2"), _row("d", "t3")])

    assert [row["uuid"] for row in fresh] == ["c", "d"]
