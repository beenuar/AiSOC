"""Tests for the T6.4 quick-seed (``pnpm aisoc:demo --quick``) path.

The quick-seed mode in ``app.scripts.seed_demo`` is the path the 90-second
product screencast records against: it populates exactly four deterministic
``DEMO-*`` cases (phishing / cloud takeover / insider exfil / ransomware)
with byte-stable UUIDs and timestamps so the screencast looks the same on
every re-record.

These tests lock in the *contract* of the quick seeder so future refactors
can't silently change:

- the four canonical case keys (``DEMO-001`` … ``DEMO-004``),
- which connector source each case advertises to the buyer (so the Source
  column in the demo doesn't drift),
- the determinism of the seed (same clock + same code = same UUID).

The fast tests run as plain unit tests — they only introspect the
module-level ``_DEMO_QUICK_INCIDENTS`` constant and the deterministic
``_demo_quick_uuid`` helper, no DB and no event loop required. The
heavier end-to-end assertion (that running the seeder actually persists
four ``Case`` rows with the expected keys) is parked behind a
``pytest.mark.integration`` marker because it needs a running Postgres
and an alembic-migrated schema.

Why a marker rather than a separate file?
  Keeping the contract assertions and the wire-format assertions in the
  same file means a developer who breaks the constant catches both
  failures in one ``pytest -k demo_seed`` run, which is the natural
  reflex when fiddling with the seeder.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from typing import Any

import pytest
from app.scripts.seed_demo import (
    _DEMO_QUICK_DEFAULT_CLOCK_ISO,
    _DEMO_QUICK_INCIDENTS,
    _demo_quick_uuid,
    _parse_clock,
)

# Canonical contract. If you're updating these you're either renaming a
# case (in which case docs/marketplace/CHANGELOG all need to follow) or
# you've made a mistake — the quick seed exists to power the public
# screencast and the four case names are referenced from README.md,
# apps/web/public/.demo-mp4-placeholder, and the CHANGELOG.
EXPECTED_DEMO_KEYS: list[str] = [
    "DEMO-001",
    "DEMO-002",
    "DEMO-003",
    "DEMO-004",
]

EXPECTED_CONNECTOR_SOURCES: dict[str, set[str]] = {
    # DEMO-001 phishing: M365 audit (o365) + the email-inbox connector
    # that flagged the spear-phish lure before the sign-in landed.
    "DEMO-001": {"o365", "email-inbox"},
    # DEMO-002 cloud takeover: CloudTrail is the system of record, but
    # GuardDuty is the detection that fires the impossible-travel alert,
    # so both are honestly attributed.
    "DEMO-002": {"aws-cloudtrail", "aws-guardduty"},
    # DEMO-003 insider exfil: Confluence audit (the bulk-download
    # signal) plus Google Workspace (the personal-drive upload). Two
    # sources is the whole point of the case — neither alone is enough.
    "DEMO-003": {"confluence-audit", "google-workspace"},
    # DEMO-004 ransomware: both EDRs cover the same host so the demo
    # shows the platform fusing duplicate telemetry rather than
    # double-counting it.
    "DEMO-004": {"crowdstrike", "sentinelone"},
}


# ─── Fast, DB-less contract tests ─────────────────────────────────────────────


def test_demo_quick_has_exactly_four_canonical_cases() -> None:
    """T6.4 demands exactly four cases — no more, no less.

    Adding a fifth would push the screencast over its 90-second budget;
    removing one would make the platform pitch (four pillars: phishing,
    cloud, insider, ransomware) feel incomplete.
    """
    keys = [incident["key"] for incident in _DEMO_QUICK_INCIDENTS]
    assert keys == EXPECTED_DEMO_KEYS, (
        "Quick-seed case keys drifted. The four DEMO-* keys are referenced "
        "from README.md and the screencast brief; update those too if you "
        "intend to change the canonical set."
    )


def test_demo_quick_connector_sources_match_contract() -> None:
    """Each case advertises the connector(s) that produced its evidence.

    The Source column in the UI is what a buyer reads first; if the
    seeded data attributes a phishing case to ``crowdstrike`` they'll
    rightly think the demo is broken.
    """
    for incident in _DEMO_QUICK_INCIDENTS:
        key = incident["key"]
        actual = set(incident["connector_sources"])
        expected = EXPECTED_CONNECTOR_SOURCES[key]
        assert actual == expected, f"{key}: connector_sources drifted. " f"expected {sorted(expected)}, got {sorted(actual)}"


def test_demo_quick_alerts_reference_declared_connectors() -> None:
    """Every alert under a case must come from one of the case's connectors.

    Otherwise the Source filter in the UI surfaces a phantom connector
    nobody declared, and the buyer's first click reveals an unexplained
    sourcetype.
    """
    for incident in _DEMO_QUICK_INCIDENTS:
        declared = set(incident["connector_sources"])
        for alert in incident["alerts"]:
            connector_type = alert.get("connector_type")
            assert connector_type in declared, (
                f"{incident['key']}: alert {alert.get('title')!r} comes from "
                f"connector_type={connector_type!r}, which is not in the "
                f"case's connector_sources={sorted(declared)}"
            )


def test_demo_quick_uuid_is_stable_per_input() -> None:
    """The whole point of ``_demo_quick_uuid`` is byte-stable IDs.

    If this regresses, the screencast re-records will look subtly
    different from the original — different deeplink, different ledger
    row IDs — and we'll burn a recording session chasing diffs.
    """
    a1 = _demo_quick_uuid("DEMO-001", "case")
    a2 = _demo_quick_uuid("DEMO-001", "case")
    assert a1 == a2, "_demo_quick_uuid must be deterministic for identical input"

    b = _demo_quick_uuid("DEMO-002", "case")
    assert a1 != b, "Different inputs must yield different UUIDs"

    # Lock the actual byte value of DEMO-001's case UUID — if this
    # changes, the marketplace + docs that hardcode the deeplink need
    # to follow. uuid5 is stable across Python versions/platforms, so
    # this number should never drift.
    assert str(a1) == str(uuid.uuid5(uuid.UUID("a15a1c00-0000-4d04-8000-000000000064"), "DEMO-001/case"))


def test_demo_quick_clock_parses_default_iso() -> None:
    """``--clock`` defaults to the canonical T6.4 anchor.

    A user who runs ``pnpm aisoc:demo --quick`` without ``--clock`` must
    land on the same wall-clock the screencast was recorded at, or the
    alert "happened-at" labels will drift between runs.
    """
    parsed = _parse_clock(None)
    expected = _parse_clock(_DEMO_QUICK_DEFAULT_CLOCK_ISO)
    assert parsed == expected
    # ISO surface — UTC anchored. tz must be present; a naive datetime
    # here would mean ``utcnow()`` snuck back in.
    assert parsed.utcoffset() is not None


# ─── Heavy integration test ───────────────────────────────────────────────────
#
# Gated behind `pytest.mark.integration` because it needs a real Postgres
# (an alembic-migrated schema). The CI demo-seed workflow runs this; the
# default local `pytest` invocation skips it. Run explicitly with:
#
#     AISOC_RUN_INTEGRATION=1 pytest -m integration services/api/tests/test_demo_seed.py
#
# Without the env var we skip rather than fail so developer machines
# don't have to run a Postgres container to get the unit tests green.


@pytest.mark.integration
def test_demo_quick_seed_persists_four_cases() -> None:
    """End-to-end: run the quick seeder, count DEMO-* cases.

    Skipped unless ``AISOC_RUN_INTEGRATION=1`` and a Postgres reachable
    via ``DATABASE_URL`` is up. The seeder is expected to land exactly
    four ``Case`` rows keyed ``DEMO-001`` … ``DEMO-004`` with the
    connector_sources lists from the contract above.
    """
    if not os.getenv("AISOC_RUN_INTEGRATION"):
        pytest.skip("set AISOC_RUN_INTEGRATION=1 to run the seed against Postgres")

    # Local import so the heavy SQLAlchemy + asyncpg dependency chain
    # doesn't load when the integration test is skipped (which is the
    # common case on a developer laptop).
    from app.db.database import AsyncSessionLocal
    from app.models.case import Case
    from app.scripts.seed_demo import _parse_clock, _run_quick_seed
    from sqlalchemy import select

    async def _run_and_count() -> list[Case]:
        await _run_quick_seed(clock=_parse_clock(None))
        async with AsyncSessionLocal() as session:
            stmt = select(Case).where(Case.key.in_(EXPECTED_DEMO_KEYS))
            result = await session.execute(stmt)
            return list(result.scalars().all())

    cases = asyncio.run(_run_and_count())
    by_key: dict[str, Case] = {c.key: c for c in cases}
    assert set(by_key.keys()) == set(EXPECTED_DEMO_KEYS), (
        f"Quick seed did not produce exactly the four DEMO-* cases. " f"Got keys: {sorted(by_key.keys())}"
    )

    # Walk the persisted metadata to confirm connector_sources made it
    # through. The seeder stuffs `connector_sources` into the case
    # `metadata` JSON column; if the schema moves, this assertion is
    # what surfaces the regression.
    for key, case in by_key.items():
        meta: dict[str, Any] = case.case_metadata or {}
        sources = set(meta.get("connector_sources") or [])
        assert sources == EXPECTED_CONNECTOR_SOURCES[key], (
            f"{key}: persisted connector_sources={sorted(sources)} " f"does not match contract={sorted(EXPECTED_CONNECTOR_SOURCES[key])}"
        )
