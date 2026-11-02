# VENDORED COPY. Canonical source: scripts/ip_class_dataset.py
# Regenerate with: python3 scripts/sync_vendored_ip_class.py
# Held byte-identical by scripts/sync_vendored_ip_class.py --check.
#!/usr/bin/env python3
"""Loader half of the anonymizer and hosting classification dataset.

Pairs with `scripts/fetch_ip_class_dataset.py` (the downloader) and is
compared against it by `scripts/check_ip_class_dataset.py`.

Who reads this, and who does not
--------------------------------
The classifier that runs in production is the Go one in
`services/ingest/internal/activity/ipclass`. It embeds the same committed
dataset and stamps every event at ingest. **This module is not a second
production classifier**, and adding one would be the drift this repository
has been bitten by before: two implementations of one security predicate
that agree until they quietly do not.

This module exists for fixture replay. A committed detection fixture carries
a `src_ip` and no activity projection, because fixtures are authored against
the rule rather than captured from a live pipeline. Without it, a rule Lane C
writes against `ip_class` would pass its fixtures and never fire live, or
fire live and fail its fixtures. `scripts/check_ip_class_dataset.py` asserts
the Go answer and the Python answer agree over a sample of the dataset, so
the two cannot diverge silently.

The dataset lives under the Go package because `go:embed` cannot reach above
its own package and the ingest image's build context is `services/ingest`.
One copy plus a gate beats two copies plus a sync, which is the arrangement
the event catalogue beside it already uses for the same reason.
"""

from __future__ import annotations

import bisect
import ipaddress
import json
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

#: Relative to the repository root, found by walking up from this file.
#:
#: An upward walk and not a fixed number of `.parent` hops, because this
#: module is vendored into `services/fusion/app/services/ip_class.py` and the
#: two copies must be byte-identical for the sync gate to hold them together.
#: A hop count would differ between them and would be the one line nobody
#: notices drifting.
#:
#: The walk failing is a supported outcome: the fusion runtime image ships
#: `app/` only, so the dataset is not on disk there. Every event in that
#: image already carries the class stamped by ingest, so nothing is lost; see
#: `load()`.
_DATASET_RELATIVE = Path("services") / "ingest" / "internal" / "activity" / "ipclass" / "data"


def _find_dataset_dir() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / _DATASET_RELATIVE
        if (candidate / "ip_classes.tsv").is_file():
            return candidate
    return None


#: The closed set, in the order the plan names them. Mirrored by
#: `fetch_ip_class_dataset.ALL_CLASSES` and by the Go package; the gate
#: compares all three.
ALL_CLASSES = ("vpn", "tor_exit", "public_proxy", "residential_proxy", "hosting_provider")


class Classification(NamedTuple):
    """One answer. There is no "not an anonymizer" value on purpose."""

    ip_class: str
    source: str
    version: str


class _Table(NamedTuple):
    starts_v4: list[int]
    entries_v4: list[tuple[int, int, str, str]]
    starts_v6: list[int]
    entries_v6: list[tuple[int, int, str, str]]
    version: str
    record_count: int


def _empty() -> _Table:
    return _Table([], [], [], [], "", 0)


@lru_cache(maxsize=1)
def load(directory: str | None = None) -> _Table:
    """Parse the committed dataset once per process.

    A missing dataset returns an empty table rather than raising. The fusion
    runtime image ships `app/` only, so this file can be imported where the
    dataset is not on disk; there, every event already carries the class
    stamped by ingest and nothing is lost. A gate asserts the dataset is
    present everywhere it is actually needed, so "empty" never passes
    silently in CI.
    """
    base = Path(directory) if directory else _find_dataset_dir()
    if base is None:
        return _empty()
    records = base / "ip_classes.tsv"
    if not records.is_file():
        return _empty()

    version = ""
    manifest = base / "manifest.json"
    if manifest.is_file():
        try:
            version = str(json.loads(manifest.read_text(encoding="utf-8")).get("version") or "")
        except (ValueError, OSError):
            version = ""

    rows_v4: list[tuple[int, int, str, str]] = []
    rows_v6: list[tuple[int, int, str, str]] = []
    count = 0
    for line in records.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            network = ipaddress.ip_network(parts[0], strict=False)
        except ValueError:
            continue
        row = (
            int(network.network_address),
            int(network.broadcast_address),
            parts[1],
            parts[2],
        )
        (rows_v4 if network.version == 4 else rows_v6).append(row)
        count += 1

    # Sorted by start address, then by prefix length descending, so a nested
    # /32 inside a /16 is found before its container. The walk below relies
    # on that ordering rather than on the file's.
    rows_v4.sort(key=lambda r: (r[0], -(r[1] - r[0])))
    rows_v6.sort(key=lambda r: (r[0], -(r[1] - r[0])))
    return _Table(
        [r[0] for r in rows_v4],
        rows_v4,
        [r[0] for r in rows_v6],
        rows_v6,
        version,
        count,
    )


def classify(value: str, *, directory: str | None = None) -> Classification | None:
    """Classify one address, or None when the dataset has no entry.

    None and not a default: three of the five classes ship with zero
    records, so "no entry" is the normal case and must not read as "this
    address is ordinary".
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if not is_public(address):
        return None

    table = load(directory)
    starts, entries = (table.starts_v4, table.entries_v4) if address.version == 4 else (table.starts_v6, table.entries_v6)
    if not entries:
        return None

    numeric = int(address)
    index = bisect.bisect_right(starts, numeric)
    # Walk back over candidates whose start is at or below the query. Bounded
    # for the same reason as the Go side: a /8 with many siblings would make
    # an unbounded walk linear in the sibling count.
    for i in range(index - 1, max(-1, index - 1 - _MAX_NESTING_PROBE), -1):
        start, end, cls, provider = entries[i]
        if start <= numeric <= end:
            return Classification(cls, provider, table.version)
    return None


_MAX_NESTING_PROBE = 64

#: Mirrors `activity.IsPublicIP` in the Go tree. Listed explicitly rather
#: than using `ipaddress.is_global`, whose membership has moved between
#: Python minors: a security predicate must not answer differently under two
#: interpreter builds of the same commit.
_NON_PUBLIC = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "198.18.0.0/15",
        "224.0.0.0/4",
        "0.0.0.0/8",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
        "::/128",
        "ff00::/8",
        "2001:db8::/32",
    )
)


def is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not any(address in network for network in _NON_PUBLIC)


def dataset_version(*, directory: str | None = None) -> str:
    return load(directory).version


def record_count(*, directory: str | None = None) -> int:
    return load(directory).record_count


def sample_address(ip_class: str, *, directory: str | None = None) -> str | None:
    """One address the dataset classifies as `ip_class`, for tests."""
    table = load(directory)
    for entries in (table.entries_v4, table.entries_v6):
        for start, _end, cls, _provider in entries:
            if cls == ip_class:
                family = ipaddress.IPv4Address if entries is table.entries_v4 else ipaddress.IPv6Address
                return str(family(start))
    return None
