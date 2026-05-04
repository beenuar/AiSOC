"""
AiSOC Detection Pack v1 - Combined Specification Index
======================================================

Imports the rule tables from `detection_specs.py` and `detection_specs_part2.py`
and exposes a single `ALL_SPECS` list grouped by category.

The category names map directly onto subdirectories under `detections/`.
"""

from __future__ import annotations

from typing import Iterable

# Local imports must be relative to scripts/ (that is the cwd when invoked).
from detection_specs import CLOUD, IDENTITY  # type: ignore[import-not-found]
from detection_specs_part2 import (  # type: ignore[import-not-found]
    APPLICATION,
    DATA_EXFIL,
    ENDPOINT,
    NETWORK,
)


CATEGORIES: dict[str, list[dict]] = {
    "cloud": CLOUD,
    "identity": IDENTITY,
    "endpoint": ENDPOINT,
    "network": NETWORK,
    "application": APPLICATION,
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
