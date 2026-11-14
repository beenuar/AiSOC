"""Tiered archive: hot/warm/cold roll-off (t6-cold-storage).

The archive is a *write-side* helper. It accepts events through
:meth:`TieredArchive.archive` and decides which tier each event
lands in based on age, then persists it accordingly:

* **Hot** events stay in the operational store. The archive does
  *not* duplicate them — they are owned by the live database. The
  archive only tracks them for stats.
* **Warm** events are written to a per-day batch file. Batches
  are append-only Parquet-style records (in our dev mode the file
  is JSON Lines for simplicity; production swaps in a real
  Parquet writer).
* **Cold** events land in a per-day cold-tier file. Same shape;
  the difference is retention horizon and the fact that
  :func:`query_cold_archive` is the only way to read them back.

The thresholds are configurable per archive instance so MSSP
deployments with different residency budgets can run side by side.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


class StorageTier:
    """Constants for tier names used across the cold-storage package."""

    HOT = "hot"
    WARM = "warm"
    COLD = "cold"


@dataclass
class ArchiveStats:
    hot_writes: int = 0
    warm_writes: int = 0
    cold_writes: int = 0
    bytes_written: int = 0


@dataclass
class ArchiveBatch:
    """A descriptor for a per-(tier, day) batch on disk."""

    tier: str
    tenant_id: str
    day: str  # YYYY-MM-DD
    path: Path
    rows: int = 0
    bytes_on_disk: int = 0


class TieredArchive:
    """Roll-off router for time-series events.

    Construct one per process. The on-disk layout is::

        <root>/<tier>/<tenant_id>/<YYYY-MM-DD>.jsonl

    Production deployments swap in S3 / GCS / Athena via a
    different :class:`QueryEngine` and :class:`Writer`; the on-
    disk layout here is enough for tests and the dev runner to
    exercise the full archive → query path end-to-end.
    """

    def __init__(
        self,
        *,
        root: Path,
        warm_threshold_days: int = 7,
        cold_threshold_days: int = 30,
    ) -> None:
        if cold_threshold_days < warm_threshold_days:
            raise ValueError(
                "cold_threshold_days must be >= warm_threshold_days"
            )
        self._root = root
        self._warm_days = warm_threshold_days
        self._cold_days = cold_threshold_days
        self._lock = threading.Lock()
        self.stats = ArchiveStats()
        for tier in (StorageTier.HOT, StorageTier.WARM, StorageTier.COLD):
            (self._root / tier).mkdir(parents=True, exist_ok=True)

    @property
    def root(self) -> Path:
        return self._root

    def _classify(self, event_time: datetime) -> str:
        now = datetime.now(timezone.utc)
        age_days = max(0.0, (now - event_time).total_seconds() / 86400.0)
        if age_days >= self._cold_days:
            return StorageTier.COLD
        if age_days >= self._warm_days:
            return StorageTier.WARM
        return StorageTier.HOT

    def _path_for(
        self, *, tier: str, tenant_id: str, day: str
    ) -> Path:
        directory = self._root / tier / tenant_id
        directory.mkdir(parents=True, exist_ok=True)
        return directory / f"{day}.jsonl"

    def archive(self, event: dict[str, Any]) -> Optional[str]:
        """Route ``event`` into the appropriate tier.

        Returns the tier name on success, or ``None`` if the event
        was rejected for missing required fields. The archive is
        deliberately permissive about field shapes — the only
        requirement is ``tenant_id`` + ``event_time`` (ISO-8601
        string or epoch seconds).
        """

        tenant_id = str(event.get("tenant_id", "")).strip()
        if not tenant_id:
            return None
        ts = event.get("event_time")
        if isinstance(ts, str):
            try:
                event_time = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                return None
        elif isinstance(ts, (int, float)) and ts > 0:
            event_time = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        else:
            return None
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)

        tier = self._classify(event_time)
        if tier == StorageTier.HOT:
            with self._lock:
                self.stats.hot_writes += 1
            return tier

        day = event_time.strftime("%Y-%m-%d")
        path = self._path_for(tier=tier, tenant_id=tenant_id, day=day)
        normalised = dict(event)
        normalised["__tier"] = tier
        normalised["__archived_at"] = datetime.now(timezone.utc).isoformat()

        line = json.dumps(normalised, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with self._lock:
            with path.open("ab") as fh:
                fh.write(line)
                fh.write(b"\n")
            self.stats.bytes_written += len(line) + 1
            if tier == StorageTier.WARM:
                self.stats.warm_writes += 1
            else:
                self.stats.cold_writes += 1
        return tier

    def list_batches(self, tenant_id: str, *, tier: str) -> list[ArchiveBatch]:
        directory = self._root / tier / tenant_id
        if not directory.exists():
            return []
        out: list[ArchiveBatch] = []
        for path in sorted(directory.glob("*.jsonl")):
            try:
                stat = path.stat()
            except OSError:
                continue
            day = path.stem
            with path.open("rb") as fh:
                rows = sum(1 for _ in fh)
            out.append(
                ArchiveBatch(
                    tier=tier,
                    tenant_id=tenant_id,
                    day=day,
                    path=path,
                    rows=rows,
                    bytes_on_disk=stat.st_size,
                )
            )
        return out

    def clear_tenant(self, tenant_id: str) -> int:
        """Test helper — drop a tenant's data from every tier."""

        n = 0
        for tier in (StorageTier.WARM, StorageTier.COLD):
            directory = self._root / tier / tenant_id
            if not directory.exists():
                continue
            for path in directory.glob("*.jsonl"):
                try:
                    path.unlink()
                    n += 1
                except OSError:
                    pass
        return n

    def iter_rows(
        self,
        *,
        tenant_id: str,
        tier: str,
        day: Optional[str] = None,
    ) -> Iterable[dict[str, Any]]:
        directory = self._root / tier / tenant_id
        if not directory.exists():
            return
        files = (
            [directory / f"{day}.jsonl"]
            if day
            else sorted(directory.glob("*.jsonl"))
        )
        for path in files:
            if not path.exists():
                continue
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        # Skip a single corrupt line rather than
                        # poisoning the whole batch.
                        continue


# ---------------------------------------------------------------------------
# Process-wide singleton + helpers
# ---------------------------------------------------------------------------


_default_root = Path(
    os.environ.get(
        "AISOC_COLD_STORAGE_ROOT",
        str(Path(__file__).resolve().parent.parent.parent / "data" / "cold_storage"),
    )
)


cold_archive = TieredArchive(root=_default_root)


def archive_event(event: dict[str, Any]) -> Optional[str]:
    return cold_archive.archive(event)


def write_demo_archive(*, tenant_id: str = "demo") -> int:
    """Seed a small synthetic archive for tests / dev runs.

    Writes one warm and one cold batch per tenant with three
    events each. Returns the total number of events written.
    """

    written = 0
    now = datetime.now(timezone.utc)
    # Warm: 10 days old.
    warm_day = (now.replace(hour=0, minute=0, second=0, microsecond=0) - _td(10)).strftime("%Y-%m-%d")
    cold_day = (now.replace(hour=0, minute=0, second=0, microsecond=0) - _td(60)).strftime("%Y-%m-%d")
    warm_path = cold_archive._path_for(tier=StorageTier.WARM, tenant_id=tenant_id, day=warm_day)
    cold_path = cold_archive._path_for(tier=StorageTier.COLD, tenant_id=tenant_id, day=cold_day)

    rows_warm = [
        {
            "tenant_id": tenant_id,
            "event_class": "auth",
            "event_time": (now - _td(10)).isoformat(),
            "outcome": "failure",
            "src_user": "alice",
            "__tier": "warm",
        }
        for _ in range(3)
    ]
    rows_cold = [
        {
            "tenant_id": tenant_id,
            "event_class": "process_spawn",
            "event_time": (now - _td(60)).isoformat(),
            "rare_process": True,
            "src_host": "host-1",
            "__tier": "cold",
        }
        for _ in range(3)
    ]

    for path, rows in ((warm_path, rows_warm), (cold_path, rows_cold)):
        with path.open("ab") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True).encode("utf-8"))
                fh.write(b"\n")
                written += 1
    return written


def _td(days: float):
    from datetime import timedelta

    return timedelta(days=days)
