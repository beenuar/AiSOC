"""The Avro container reader, graded against committed bytes.

The fixture is binary and is never produced by the code under test, so these
expectations are a statement about the file rather than a round trip. The
negative cases matter more than the happy path: a decoder that returns a
short list on a truncated file turns a gap in an audit trail into a result
nobody questions, so every unreadable shape has to raise.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.connectors.avro_ocf import AvroError, AvroUnsupported, read_container

FIXTURE = Path(__file__).parent / "fixtures" / "azure_event_hubs" / "capture_block.avro"


def _blob() -> bytes:
    return FIXTURE.read_bytes()


class TestReadingACaptureFile:
    def test_both_capture_events_are_returned(self) -> None:
        assert len(read_container(_blob())) == 2

    def test_the_declared_fields_decode_to_their_recorded_values(self) -> None:
        first, second = read_container(_blob())
        assert first["SequenceNumber"] == 1001
        assert first["Offset"] == "400"
        assert first["EnqueuedTimeUtc"] == "2026-10-08T11:21:00.0000000Z"
        assert second["SequenceNumber"] == 1002

    def test_a_map_of_unions_decodes_including_its_null_branch(self) -> None:
        """Capture's `Properties` map is a union with a null branch, and a
        decoder that skipped the branch index would read the next field's
        bytes as this one's value — silently, and plausibly."""
        first = read_container(_blob())[0]
        assert first["SystemProperties"] == {"x-opt-partition-key": "entra"}
        assert first["Properties"] == {"aisoc-fixture": "true", "empty": None}

    def test_the_body_is_the_azure_monitor_batch(self) -> None:
        first = read_container(_blob())[0]
        payload = json.loads(first["Body"].decode())
        assert [r["category"] for r in payload["records"]] == ["SignInLogs", "AuditLogs"]


class TestItRefusesRatherThanGuesses:
    def test_a_file_that_is_not_avro_is_refused(self) -> None:
        with pytest.raises(AvroError, match="bad magic"):
            read_container(b"not avro at all")

    def test_a_truncated_file_raises_rather_than_returning_what_it_got(self) -> None:
        """A partial decode of an audit log is worse than no decode, because
        the gap is invisible to whoever reads the result."""
        with pytest.raises(AvroError):
            read_container(_blob()[:-40])

    def test_a_corrupted_block_boundary_is_caught_by_the_sync_marker(self) -> None:
        blob = bytearray(_blob())
        blob[-1] ^= 0xFF
        with pytest.raises(AvroError, match="sync marker"):
            read_container(bytes(blob))

    def test_an_undecodable_codec_names_itself(self) -> None:
        """ "Returned nothing" and "cannot read snappy" are different facts and
        only one of them is the operator's to fix."""
        blob = _blob().replace(b"\x0edeflate", b"\x0cs" + b"nappy", 1)
        with pytest.raises(AvroUnsupported, match="snappy"):
            read_container(blob)

    def test_a_block_claiming_an_absurd_object_count_is_refused(self) -> None:
        """The count comes off the wire, so a reader that trusts it allocates
        whatever a corrupt or hostile file asks for.

        Hand-built rather than taken from the fixture: this needs a *header*
        the fixture does not contain, and the bytes below only have to be a
        container the reader gets far enough into to read a block count.
        """
        with pytest.raises(AvroError, match="refusing a"):
            read_container(_container(_zigzag(1 << 40) + _zigzag(4) + b"aaaa" + _SYNC))

    def test_a_string_claiming_more_bytes_than_the_file_holds_is_refused(self) -> None:
        with pytest.raises(AvroError, match="truncated|refusing"):
            read_container(_container(_zigzag(1) + _zigzag(3) + _zigzag(1 << 30) + _SYNC))


_SYNC = bytes(range(16))
_MINIMAL_SCHEMA = {"type": "record", "name": "R", "fields": [{"name": "a", "type": "string"}]}


def _zigzag(value: int) -> bytes:
    encoded = (value << 1) ^ (value >> 63)
    out = bytearray()
    while True:
        byte = encoded & 0x7F
        encoded >>= 7
        if encoded:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _container(blocks: bytes) -> bytes:
    """A null-codec container whose header is well-formed and whose body is not."""
    schema = json.dumps(_MINIMAL_SCHEMA, separators=(",", ":")).encode()
    metadata = (
        _zigzag(2)
        + _zigzag(len(b"avro.schema"))
        + b"avro.schema"
        + _zigzag(len(schema))
        + schema
        + _zigzag(len(b"avro.codec"))
        + b"avro.codec"
        + _zigzag(len(b"null"))
        + b"null"
        + _zigzag(0)
    )
    return b"Obj\x01" + metadata + _SYNC + blocks
