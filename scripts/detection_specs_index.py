"""
AiSOC Detection Pack v1 - Combined Specification Index
======================================================

Imports the rule tables from `detection_specs.py`, `detection_specs_part2.py`,
and the `detection_specs_part3_*.py` expansion modules, then exposes a single
`CATEGORIES` mapping plus an `all_specs()` iterator.

The category names map directly onto subdirectories under `detections/`.

Tier mapping:
* `detection_specs.py` + `detection_specs_part2.py` — original 200 hand-curated
  native specs.
* `detection_specs_part3_*.py` — 600 additional native specs generated through
  the compact `S()` builder (see `detection_specs_part3_helpers.py`). These
  follow the same fixture + MITRE quality gate as the originals.
"""

from __future__ import annotations

from collections.abc import Iterable

# Local imports must be relative to scripts/ (that is the cwd when invoked).
from detection_specs import CLOUD, IDENTITY  # type: ignore[import-not-found]
from detection_specs_part2 import (  # type: ignore[import-not-found]
    APPLICATION,
    DATA_EXFIL,
    ENDPOINT,
    NETWORK,
)
from detection_specs_part3_application import APPLICATION_EXTRA  # type: ignore[import-not-found]
from detection_specs_part3_cloud import CLOUD_EXTRA  # type: ignore[import-not-found]
from detection_specs_part3_endpoint import ENDPOINT_EXTRA  # type: ignore[import-not-found]
from detection_specs_part3_identity import IDENTITY_EXTRA  # type: ignore[import-not-found]
from detection_specs_part3_network import NETWORK_EXTRA  # type: ignore[import-not-found]

CATEGORIES: dict[str, list[dict]] = {
    "cloud": [*CLOUD, *CLOUD_EXTRA],
    "identity": [*IDENTITY, *IDENTITY_EXTRA],
    "endpoint": [*ENDPOINT, *ENDPOINT_EXTRA],
    "network": [*NETWORK, *NETWORK_EXTRA],
    "application": [*APPLICATION, *APPLICATION_EXTRA],
    "data-exfil": DATA_EXFIL,
}


def all_specs() -> Iterable[tuple[str, dict]]:
    """Yield (category, spec) tuples in deterministic order."""
    for category in sorted(CATEGORIES.keys()):
        for spec in CATEGORIES[category]:
            yield category, spec


def total_counts() -> dict[str, int]:
    return {category: len(rules) for category, rules in CATEGORIES.items()}


if __name__ == "__main__":
    counts = total_counts()
    total = sum(counts.values())
    print("AiSOC Detection Pack v1 spec counts:")
    for category, count in sorted(counts.items()):
        print(f"  {category:14s} {count:4d}")
    print(f"  {'TOTAL':14s} {total:4d}")
