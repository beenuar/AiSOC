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
* `detection_specs_part4_threat_anomaly.py` — depth plan 3.5. Threat
  conditions paired with depth plan 3.4 baseline scores. Fixtures are
  hand-authored rather than synthesised, because the content of these
  rules is a relationship and a fixture copied from the clause cannot
  test it.
* `detection_specs_part5_families.py` — depth 2 wave 2 item 2.1. Named
  scenario families over SaaS and cloud sources. Each spec declares the
  family it belongs to and the category it generates into, and every one
  is replayed through its real connector and the real engine by
  `scripts/check_scenario_family_alignment.py`.
* `detection_specs_part6_coverage.py` — the same item's second pass, which
  closed the 800-condition target. Each spec carries the vendor envelope
  that proves it, so a rule edited without its proof fails immediately.
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
from detection_specs_part4_threat_anomaly import THREAT_ANOMALY  # type: ignore[import-not-found]
from detection_specs_part5_families import (  # type: ignore[import-not-found]
    FAMILIES_APPLICATION,
    FAMILIES_CLOUD,
    FAMILIES_DATA_EXFIL,
    FAMILIES_IDENTITY,
)
from detection_specs_part6_coverage import (  # type: ignore[import-not-found]
    COVERAGE_APPLICATION,
    COVERAGE_CLOUD,
    COVERAGE_DATA_EXFIL,
    COVERAGE_IDENTITY,
)

CATEGORIES: dict[str, list[dict]] = {
    "cloud": [*CLOUD, *CLOUD_EXTRA, *FAMILIES_CLOUD, *COVERAGE_CLOUD],
    "identity": [*IDENTITY, *IDENTITY_EXTRA, *FAMILIES_IDENTITY, *COVERAGE_IDENTITY],
    "endpoint": [*ENDPOINT, *ENDPOINT_EXTRA],
    "network": [*NETWORK, *NETWORK_EXTRA],
    "application": [*APPLICATION, *APPLICATION_EXTRA, *FAMILIES_APPLICATION, *COVERAGE_APPLICATION],
    "data-exfil": [*DATA_EXFIL, *FAMILIES_DATA_EXFIL, *COVERAGE_DATA_EXFIL],
    # Depth plan 3.5. Its own category because the claim is different:
    # these pair a threat condition with a depth plan 3.4 baseline score,
    # so a fresh install has the rule before it has the signal. Counted
    # separately in scripts/project_stats.py for the same reason.
    "threat-anomaly": THREAT_ANOMALY,
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
