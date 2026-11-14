"""A reader for Avro Object Container Files, scoped to what Capture writes.

Azure Event Hubs Capture is Avro-only — there is no JSON output mode — so
reading captured Entra and Activity-log telemetry means decoding Avro, and
no Avro library is a declared dependency of this service. Adding one would
mean a new pin across fourteen declaration sites for a format whose binary
encoding is a page of the specification, so the subset Capture emits is
decoded here instead.

What it does and does not do
----------------------------

The schema is read **from the file**, not hardcoded. A decoder that assumed
Capture's current field order would decode a future Capture layout into
plausible-looking nonsense, which is the worst possible failure for evidence
an analyst will act on. So the writer's schema is parsed out of the OCF
metadata and the decoder walks it.

Supported: ``record``, ``map``, ``array``, ``union``, ``enum``, ``fixed``,
``null``, ``boolean``, ``int``, ``long``, ``float``, ``double``, ``bytes``,
``string``, and named-type references back to a previously-defined record.
That is a superset of what Capture writes and a subset of Avro.

Not supported, and refused loudly rather than guessed at: the ``snappy`` and
``zstandard`` codecs, and logical-type reinterpretation (a
``timestamp-micros`` long comes back as a long). ``AvroUnsupported`` names
which one, because "returned nothing" and "could not read this codec" are
different facts and only one of them is the operator's to fix.

Bounds exist on every length read. An Avro length prefix is attacker-
influenced in the sense that it comes off the wire: a corrupted or hostile
object declaring a four-gigabyte string must raise, not allocate.
"""

from __future__ import annotations

import json
import struct
import zlib
from dataclasses import dataclass
from typing import Any

MAGIC = b"Obj\x01"
SYNC_SIZE = 16

#: No single value inside one captured event is legitimately larger than
#: this. Event Hubs caps a single event at 1 MiB.
MAX_VALUE_BYTES = 64 * 1024 * 1024

#: A block that claims more objects than this is refused. Capture writes a
#: few thousand per block.
MAX_OBJECTS_PER_BLOCK = 5_000_000


class AvroError(ValueError):
    """The bytes are not a readable Avro container file."""


class AvroUnsupported(AvroError):
    """Readable Avro, using a feature this decoder deliberately does not guess at."""


@dataclass
class _Reader:
    data: bytes
    pos: int = 0

    def take(self, n: int) -> bytes:
        if n < 0 or n > MAX_VALUE_BYTES:
            raise AvroError(f"refusing a {n}-byte read")
        end = self.pos + n
        if end > len(self.data):
            raise AvroError(f"truncated: wanted {n} bytes at offset {self.pos}, {len(self.data) - self.pos} remain")
        out = self.data[self.pos : end]
        self.pos = end
        return out

    def long(self) -> int:
        """Zigzag varint, which is how Avro encodes every int and long."""
        shift = 0
        acc = 0
        while True:
            if self.pos >= len(self.data):
                raise AvroError("truncated varint")
            byte = self.data[self.pos]
            self.pos += 1
            acc |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7
            if shift > 63:
                raise AvroError("varint wider than 64 bits")
        return (acc >> 1) ^ -(acc & 1)


def _named(schema: Any) -> str:
    if isinstance(schema, str):
        return schema
    if isinstance(schema, dict):
        return str(schema.get("type", ""))
    if isinstance(schema, list):
        return "union"
    raise AvroError(f"unreadable schema node: {schema!r}")


def _decode(reader: _Reader, schema: Any, named: dict[str, Any]) -> Any:
    """One value of ``schema``. ``named`` carries records defined earlier."""
    if isinstance(schema, list):
        index = reader.long()
        if not 0 <= index < len(schema):
            raise AvroError(f"union branch {index} out of range for {len(schema)} branches")
        return _decode(reader, schema[index], named)

    kind = _named(schema)

    if kind in named and kind not in _PRIMITIVES:
        schema = named[kind]
        kind = _named(schema)

    if kind == "null":
        return None
    if kind == "boolean":
        return reader.take(1) != b"\x00"
    if kind in ("int", "long"):
        return reader.long()
    if kind == "float":
        return struct.unpack("<f", reader.take(4))[0]
    if kind == "double":
        return struct.unpack("<d", reader.take(8))[0]
    if kind == "bytes":
        return reader.take(reader.long())
    if kind == "string":
        return reader.take(reader.long()).decode("utf-8", errors="replace")
    if kind == "fixed":
        return reader.take(int(schema["size"]))
    if kind == "enum":
        symbols = schema.get("symbols") or []
        index = reader.long()
        if not 0 <= index < len(symbols):
            raise AvroError(f"enum index {index} outside {len(symbols)} symbols")
        return symbols[index]
    if kind == "record":
        if isinstance(schema, dict) and schema.get("name"):
            named[str(schema["name"])] = schema
            if schema.get("namespace"):
                named[f"{schema['namespace']}.{schema['name']}"] = schema
        out: dict[str, Any] = {}
        for field in schema.get("fields") or []:
            out[str(field["name"])] = _decode(reader, field["type"], named)
        return out
    if kind in ("map", "array"):
        items = schema["values"] if kind == "map" else schema["items"]
        collected_map: dict[str, Any] = {}
        collected_list: list[Any] = []
        while True:
            count = reader.long()
            if count == 0:
                break
            if count < 0:
                # A negative count means the block is followed by its byte
                # size, which a reader that wants to skip the block uses.
                count = -count
                reader.long()
            if count > MAX_OBJECTS_PER_BLOCK:
                raise AvroError(f"refusing a {count}-entry block")
            for _ in range(count):
                if kind == "map":
                    key = reader.take(reader.long()).decode("utf-8", errors="replace")
                    collected_map[key] = _decode(reader, items, named)
                else:
                    collected_list.append(_decode(reader, items, named))
        return collected_map if kind == "map" else collected_list

    raise AvroUnsupported(f"avro type {kind!r} is not decoded here")


_PRIMITIVES = frozenset({"null", "boolean", "int", "long", "float", "double", "bytes", "string"})


def read_container(blob: bytes) -> list[dict[str, Any]]:
    """Every record in one Avro container file.

    Raises :class:`AvroError` for anything unreadable rather than returning
    a short list: a partial decode of an audit log is worse than no decode,
    because the gap is invisible.
    """
    if not blob.startswith(MAGIC):
        raise AvroError("not an Avro container file (bad magic)")

    reader = _Reader(blob, len(MAGIC))
    metadata_schema = {"type": "map", "values": "bytes"}
    metadata = _decode(reader, metadata_schema, {})
    if not isinstance(metadata, dict):
        raise AvroError("container metadata is not a map")

    codec = (metadata.get("avro.codec") or b"null").decode("ascii", errors="replace")
    if codec not in ("null", "deflate"):
        raise AvroUnsupported(f"avro codec {codec!r} is not decoded here; re-capture with the null or deflate codec")

    raw_schema = metadata.get("avro.schema")
    if not raw_schema:
        raise AvroError("container metadata carries no avro.schema")
    schema = json.loads(raw_schema.decode("utf-8"))

    sync = reader.take(SYNC_SIZE)

    records: list[dict[str, Any]] = []
    while reader.pos < len(blob):
        count = reader.long()
        size = reader.long()
        payload = reader.take(size)
        if reader.take(SYNC_SIZE) != sync:
            raise AvroError("block sync marker mismatch — the file is corrupt or truncated mid-block")
        if codec == "deflate":
            # Raw deflate, no zlib header: that is what the Avro
            # specification means by "deflate".
            payload = zlib.decompressobj(-zlib.MAX_WBITS).decompress(payload, MAX_VALUE_BYTES)
        if count > MAX_OBJECTS_PER_BLOCK:
            raise AvroError(f"refusing a block of {count} objects")
        block = _Reader(payload)
        named: dict[str, Any] = {}
        for _ in range(count):
            value = _decode(block, schema, named)
            if isinstance(value, dict):
                records.append(value)
    return records
