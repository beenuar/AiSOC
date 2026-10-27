"""On-disk spool for lake rows that ClickHouse has not accepted yet.

Why this exists
---------------
``LakeWriter`` buffered rows in a Python list and returned ``True`` from
``write_event`` to mean "accepted for archival". The fusion consumer then
committed the input Kafka offset. So the offset -- the only record of what
has been archived -- advanced on the strength of process memory: a hard kill
lost the buffer whole, and the capacity guard discarded the *oldest* rows,
whose offsets had been committed minutes earlier. Nothing could replay them,
because nothing knew they were missing.

The spool gives archival a recovery boundary that does not depend on the
alert pipeline's offsets. A row is on disk before ``write_event`` returns,
and a restart replays whatever ClickHouse never took.

Durability, stated exactly
--------------------------
Segments are appended with ``write()`` and are **not** ``fsync``ed per row by
default. That is a deliberate boundary, not an oversight:

* A process crash, SIGKILL, container stop or `docker kill` loses nothing:
  the bytes are in the kernel page cache and the OS writes them out whether
  or not this process is alive. That is the failure this module is for.
* A machine power loss or a kernel panic can lose the tail. Set
  ``AISOC_LAKE_SPOOL_FSYNC=1`` to flush every append if that matters; it
  costs a disk round trip per batch.
* The spool is only as durable as its filesystem. On Kubernetes with an
  ``emptyDir``, a rescheduled pod starts with an empty spool, and rows whose
  offsets were already committed are gone. Mount a volume. This is documented
  rather than papered over, because the alternative -- claiming durability
  the deployment does not have -- is the thing being fixed.

Capacity is back-pressure, never discard
----------------------------------------
At ``max_bytes`` the spool refuses the append and says so. The caller turns
that into a retryable failure, the consumer holds the Kafka offset, and
Kafka's retention becomes the buffer -- which is the durable log the platform
already runs, orders of magnitude larger than any in-process cap. Raising a
memory limit was never a durability fix, and neither is raising this one.

Format
------
Line-delimited JSON, one row per line, in rotating segments. A truncated
final line (the power-loss case above) is skipped on read with a counter, so
one torn write cannot make the rest of a segment unreadable.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

_SEGMENT_SUFFIX = ".jsonl"
_QUARANTINE_DIR = "quarantine"


def _encode(row: dict[str, Any]) -> str:
    """One row as a JSON line.

    ``event_time`` is a ``datetime`` by the time it reaches here (the driver
    binds DateTime64 from an object, not a string), so it round-trips through
    an explicit ISO conversion rather than ``default=str``: reading it back
    has to produce the same value the first attempt would have inserted, or a
    recovered row is a different row.
    """
    out = dict(row)
    when = out.get("event_time")
    if isinstance(when, datetime):
        out["event_time"] = when.replace(tzinfo=UTC).isoformat() if when.tzinfo is None else when.isoformat()
    return json.dumps(out, default=str, separators=(",", ":"))


def _decode(line: str) -> dict[str, Any] | None:
    try:
        row = json.loads(line)
    except ValueError:
        return None
    if not isinstance(row, dict):
        return None
    when = row.get("event_time")
    if isinstance(when, str):
        try:
            parsed = datetime.fromisoformat(when)
            row["event_time"] = parsed.astimezone(UTC).replace(tzinfo=None) if parsed.tzinfo else parsed
        except ValueError:
            row["event_time"] = datetime.now(UTC).replace(tzinfo=None)
    return row


class LakeSpool:
    """Append-only disk spool with rotating segments and a byte cap."""

    def __init__(
        self,
        directory: str | Path,
        *,
        max_bytes: int = 512 * 1024 * 1024,
        segment_bytes: int = 32 * 1024 * 1024,
        fsync: bool = False,
    ) -> None:
        self._dir = Path(directory)
        self._quarantine = self._dir / _QUARANTINE_DIR
        self._max_bytes = max(1, int(max_bytes))
        self._segment_bytes = max(1, int(segment_bytes))
        self._fsync = fsync
        self._handle: Any = None
        #: Lazily scanned, then maintained by append and invalidated by
        #: anything that rewrites a segment. None means "rescan".
        self._rows_cache: int | None = None
        self._bytes_cache: int | None = None
        self._segment: Path | None = None
        self._segment_bytes_written = 0
        self.rows_spooled = 0
        self.rows_recovered = 0
        self.rows_quarantined = 0
        self.capacity_refusals = 0
        self.unreadable_lines = 0
        self.write_failures = 0
        #: False once the directory proves unusable, so a deployment with a
        #: read-only or missing volume refuses events loudly instead of
        #: pretending to spool them.
        self._usable = True

    @property
    def usable(self) -> bool:
        return self._usable

    @property
    def directory(self) -> Path:
        return self._dir

    def open(self) -> bool:
        """Create the spool directory. False means archival has no disk home."""
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            self._quarantine.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._usable = False
            logger.error(
                "lake_spool.unusable",
                directory=str(self._dir),
                error=str(exc),
                detail="lake rows cannot be made durable; archival will apply back-pressure rather than accept them",
            )
            return False
        # Seeded from the directory, not carried over: the count that
        # matters is the one a restarted process reads, and whatever the
        # previous process had in memory is gone with it.
        self._invalidate()
        return True

    def bytes_on_disk(self) -> int:
        if self._bytes_cache is None:
            self._bytes_cache = self._scan_bytes()
        return self._bytes_cache

    def rows_on_disk(self) -> int:
        """Pending rows.

        Cached, and the cache is seeded by a real scan of the directory at
        :meth:`open` — which is the case that matters, because the number is
        read right after the restart this module exists for, when a running
        total from the previous process would be meaningless. From then on
        it is maintained by the two operations that can change it (append
        and commit), because counting lines in every segment on every
        accepted event is an O(backlog) cost on the hot path: with the
        scan in place the fusion suite went from 18 s to 30 s.
        """
        if self._rows_cache is None:
            self._rows_cache = self._scan_rows()
        return self._rows_cache

    def _scan_bytes(self) -> int:
        total = 0
        for segment in self._segments():
            try:
                total += segment.stat().st_size
            except OSError:  # pragma: no cover — a segment removed mid-scan
                continue
        return total

    def _scan_rows(self) -> int:
        pending = 0
        for segment in self._segments():
            try:
                with segment.open("r", encoding="utf-8") as handle:
                    pending += sum(1 for line in handle if line.strip())
            except OSError:  # pragma: no cover
                continue
        return pending

    def _invalidate(self) -> None:
        """Drop the cached counts so the next read rescans.

        Used after a commit or a quarantine, where the change is a rewrite
        rather than a known delta and guessing at one is how a counter
        drifts away from the directory it claims to describe.
        """
        self._rows_cache = None
        self._bytes_cache = None

    def _segments(self) -> list[Path]:
        if not self._dir.exists():
            return []
        return sorted(p for p in self._dir.glob(f"*{_SEGMENT_SUFFIX}") if p.is_file())

    def append(self, rows: list[dict[str, Any]]) -> bool:
        """Spool rows. False means the cap was hit or the disk refused them.

        A False answer must reach the Kafka offset: it is the whole point of
        the back-pressure contract.
        """
        if not rows:
            return True
        if not self._usable:
            return False
        payload = "".join(_encode(row) + "\n" for row in rows)
        encoded = payload.encode("utf-8")
        if self.bytes_on_disk() + len(encoded) > self._max_bytes:
            self.capacity_refusals += 1
            logger.error(
                "lake_spool.at_capacity",
                cap_bytes=self._max_bytes,
                on_disk_bytes=self.bytes_on_disk(),
                detail=("the archive spool is full; the consumer will hold its Kafka offset rather than discard events"),
            )
            return False
        try:
            handle = self._ensure_segment()
            handle.write(payload)
            handle.flush()
            if self._fsync:
                os.fsync(handle.fileno())
        except OSError as exc:
            self.write_failures += 1
            self._close_segment()
            self._invalidate()
            logger.error("lake_spool.append_failed", error=str(exc), rows=len(rows))
            return False
        self._segment_bytes_written += len(encoded)
        self.rows_spooled += len(rows)
        if self._rows_cache is not None:
            self._rows_cache += len(rows)
        if self._bytes_cache is not None:
            self._bytes_cache += len(encoded)
        if self._segment_bytes_written >= self._segment_bytes:
            self._close_segment()
        return True

    def _ensure_segment(self) -> Any:
        if self._handle is not None:
            return self._handle
        self._dir.mkdir(parents=True, exist_ok=True)
        # Monotonic-ish name so `sorted()` replays oldest first, with a short
        # random tail because two replicas may share a volume.
        name = f"{time.time_ns():020d}-{uuid.uuid4().hex[:8]}{_SEGMENT_SUFFIX}"
        self._segment = self._dir / name
        self._handle = self._segment.open("a", encoding="utf-8")
        self._segment_bytes_written = 0
        return self._handle

    def _close_segment(self) -> None:
        if self._handle is not None:
            try:
                self._handle.close()
            except OSError:  # pragma: no cover
                pass
        self._handle = None
        self._segment = None
        self._segment_bytes_written = 0

    def read_batches(self, batch_size: int) -> Iterator[tuple[list[dict[str, Any]], Path, int]]:
        """Yield ``(rows, segment, lines consumed)`` oldest segment first.

        The caller drives this: it inserts a batch and then calls
        :meth:`commit_segment` once ClickHouse has taken it. A batch that is
        never committed stays on disk, which is the recovery property --
        reading must not be destructive.
        """
        self._close_segment()  # so the current segment is complete on disk
        for segment in self._segments():
            rows: list[dict[str, Any]] = []
            consumed = 0
            try:
                with segment.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        if not line.strip():
                            consumed += 1
                            continue
                        row = _decode(line)
                        consumed += 1
                        if row is None:
                            # A torn final line from a power loss, or a line
                            # another process was mid-write on. Skipped with
                            # a counter rather than failing the segment.
                            self.unreadable_lines += 1
                            continue
                        rows.append(row)
                        if len(rows) >= batch_size:
                            yield rows, segment, consumed
                            rows, consumed = [], 0
            except OSError as exc:  # pragma: no cover — a segment removed mid-read
                logger.warning("lake_spool.segment_unreadable", segment=segment.name, error=str(exc))
                continue
            if rows:
                yield rows, segment, consumed

    def commit_segment(self, segment: Path, consumed: int) -> None:
        """Drop ``consumed`` leading lines from ``segment``, deleting it when empty.

        Rewrites the remainder rather than tracking an offset in a sidecar,
        because a sidecar is a second thing that can be lost independently of
        the data it describes. Segments are bounded by ``segment_bytes``, so
        the rewrite is bounded too.
        """
        try:
            if not segment.exists():
                return
            with segment.open("r", encoding="utf-8") as handle:
                remaining = handle.readlines()[consumed:]
            if not any(line.strip() for line in remaining):
                segment.unlink(missing_ok=True)
                return
            tmp = segment.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as handle:
                handle.writelines(remaining)
            tmp.replace(segment)
        except OSError as exc:  # pragma: no cover
            logger.warning("lake_spool.commit_failed", segment=segment.name, error=str(exc))
        finally:
            self._invalidate()

    def quarantine(self, rows: list[dict[str, Any]], *, reason: str) -> None:
        """Move rows ClickHouse keeps refusing somewhere replayable.

        A repeatedly-rejected batch is a schema disagreement, not a transport
        fault, so retrying it forever blocks everything behind it. Deleting
        it makes the gap permanent even after someone fixes the schema. It
        goes to a file an operator can replay and the count is exposed.
        """
        if not rows:
            return
        try:
            self._quarantine.mkdir(parents=True, exist_ok=True)
            target = self._quarantine / f"{time.time_ns():020d}-{uuid.uuid4().hex[:8]}{_SEGMENT_SUFFIX}"
            with target.open("w", encoding="utf-8") as handle:
                handle.write("".join(_encode(row) + "\n" for row in rows))
        except OSError as exc:
            logger.error("lake_spool.quarantine_failed", error=str(exc), rows=len(rows))
            return
        self.rows_quarantined += len(rows)
        self._invalidate()
        logger.error(
            "lake_spool.quarantined",
            rows=len(rows),
            reason=reason,
            path=str(self._quarantine),
            detail="ClickHouse refused these rows repeatedly; they are retained for replay and are NOT in the lake",
        )

    def quarantined_rows_on_disk(self) -> int:
        if not self._quarantine.exists():
            return 0
        total = 0
        for path in self._quarantine.glob(f"*{_SEGMENT_SUFFIX}"):
            try:
                with path.open("r", encoding="utf-8") as handle:
                    total += sum(1 for line in handle if line.strip())
            except OSError:  # pragma: no cover
                continue
        return total

    def close(self) -> None:
        self._close_segment()
