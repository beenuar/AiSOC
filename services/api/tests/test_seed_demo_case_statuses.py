"""Every case status the demo seeder can write is one the schema admits.

The defect this pins (reported by a community contributor on #353): the two
random case makers in ``app.scripts.seed_demo`` drew from the
pre-consolidation ``cases`` vocabulary — ``open`` / ``in_progress`` /
``pending`` — while migration 083 repointed the ORM ``Case`` model at
``aisoc_cases``, whose CHECK constraint (migration 012) admits only the
console's states. Three of the five picks (75% of the weighted draw)
violated the constraint, so ``make demo`` failed on the first such case and
the seeded catalogue — including the ``INC-RT-001`` showcase, which seeds in
the same transaction — never landed.

No database here on purpose: the unit-level property is that the seeder's
vocabulary *is* the schema's vocabulary, pinned in both directions — the
makers against ``app.services.case_status``, and ``case_status`` against the
CHECK constraint text in the migration itself, so neither side can drift
without this file noticing.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

from app.scripts import seed_demo
from app.services.case_status import ALL_STATUSES

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"


def _check_constraint_statuses() -> set[str]:
    """The status vocabulary the ``aisoc_cases`` CHECK actually enforces."""
    sql = (MIGRATIONS / "012_case_management.sql").read_text(encoding="utf-8")
    match = re.search(r"aisoc_cases[\s\S]*?CHECK \(status IN \(([^)]+)\)", sql)
    assert match, "could not find the aisoc_cases status CHECK in migration 012"
    return {token.strip().strip("'") for token in match.group(1).split(",")}


def test_case_status_constants_match_the_check_constraint() -> None:
    """``app.services.case_status`` and migration 012 agree, member for member.

    If either side moves without the other, every assertion below is argued
    against the wrong vocabulary — so this one goes first.
    """
    assert set(ALL_STATUSES) == _check_constraint_statuses()


def test_random_case_makers_only_produce_schema_valid_statuses() -> None:
    """The weighted draws in both makers stay inside the CHECK's vocabulary.

    100 draws per maker: every status in the choice lists carries at least
    10% weight, so a stray invalid member is seen with near certainty — and
    the draw is the exact call ``make demo`` executes, not a re-statement of
    the list.
    """
    tenant = uuid.uuid4()
    when = datetime.now(UTC)
    for idx in range(100):
        case = seed_demo._make_case(tenant, idx, when, [uuid.uuid4()])
        assert case.status in ALL_STATUSES, f"_make_case produced {case.status!r}"
        synthetic = seed_demo._make_synthetic_case(tenant, idx, when, [uuid.uuid4()])
        assert synthetic.status in ALL_STATUSES, f"_make_synthetic_case produced {synthetic.status!r}"


def test_incident_spec_statuses_are_schema_valid() -> None:
    """The hand-written incident specs carry only schema-valid statuses."""
    for incident in seed_demo._REALISTIC_INCIDENTS:
        assert incident["status"] in ALL_STATUSES, f"{incident.get('key', incident.get('title'))}: {incident['status']!r}"
    for incident in seed_demo._DEMO_QUICK_INCIDENTS:
        assert incident["status"] in ALL_STATUSES, f"{incident['key']}: {incident['status']!r}"


def test_alert_status_map_covers_the_live_case_vocabulary() -> None:
    """``_alert_status_for_case`` answers for every state a case can hold.

    Pinned pair by pair rather than "returns something valid": it used to key
    on the pre-consolidation words, so every live status fell through to the
    default — which *is* a valid alert status, meaning a membership check
    passes against the broken map too.
    """
    expected = {
        "new": "new",
        "triaged": "triaged",
        "investigating": "investigating",
        "contained": "investigating",
        "resolved": "resolved",
        "closed": "resolved",
    }
    assert set(expected) == set(ALL_STATUSES)
    for status, alert_status in expected.items():
        assert seed_demo._alert_status_for_case(status) == alert_status, status
