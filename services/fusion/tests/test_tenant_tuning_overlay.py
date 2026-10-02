"""A tenant's tuning reaches the streaming engine, and only that tenant's.

Parity plan 5.4: "Fusion loads static JSON and never reads tenant tuning.
Load per-tenant suppressions, thresholds, disables, custom rules and MSSP
rule packs into fusion as versioned overlays with hot reload. A tuning
change applies to that tenant only and is recorded with its author and
reason."

What was wrong
--------------
`DetectionEngine` evaluated the shared corpus and nothing else. The
console writes a tenant's disables, thresholds and suppressions to
`detection_rules` in Postgres, where the streaming engine never looked. A
tenant who turned a noisy rule off kept receiving its alerts, and the
console showed the rule as disabled: the worst shape, because it tells the
operator the problem is solved.

The two properties worth testing hardest
-----------------------------------------
**One tenant's tuning must not touch another's.** This is the plan's own
"done when", and the obvious implementation (a module-level dict keyed on
rule id) gets it wrong silently.

**A failed reload must keep the previous overlay**, not fall back to "no
tuning". Losing a tenant's suppressions because the database blinked would
turn their queue back on, which is the opposite of what the tuning was for
and would look like a flood rather than a fault.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import pytest
from app.services.tenant_overlay import (
    EMPTY,
    OverlayCache,
    TenantOverlay,
    build_overlay,
)


def _row(rule_id: str, **kw):  # noqa: ANN001, ANN201
    base = {
        "rule_id": rule_id,
        "status": "active",
        "suppression_config": None,
        "threshold_config": None,
        # `detection_rules` has an `author` column and no `updated_by`.
        # The first version of this fake carried `updated_by`, which is
        # how a query selecting a column that does not exist passed every
        # test: the fake answered whatever it was asked.
        "author": None,
    }
    base.update(kw)
    return base


class TestBuildingAnOverlay:
    def test_a_disabled_rule_is_an_override(self) -> None:
        overlay = build_overlay("t-1", [_row("det-1", status="disabled")])
        assert overlay.overrides["det-1"].enabled is False

    def test_an_untuned_rule_produces_no_override(self) -> None:
        """The overlay is a delta. A tenant who has tuned nothing must cost
        nothing, not carry 833 no-op entries."""
        overlay = build_overlay("t-1", [])
        assert overlay.overrides == {}

    def test_the_version_is_derived_from_the_rows(self) -> None:
        """Content-derived rather than a timestamp, so a consumer can tell
        a real change from a periodic refetch."""
        rows = [_row("det-1", status="disabled")]
        assert build_overlay("t-1", rows).version == build_overlay("t-1", rows).version

    def test_a_changed_row_changes_the_version(self) -> None:
        a = build_overlay("t-1", [_row("det-1", status="active")])
        b = build_overlay("t-1", [_row("det-1", status="disabled")])
        assert a.version != b.version

    def test_a_json_string_config_is_parsed(self) -> None:
        """The driver may hand back jsonb as a string."""
        overlay = build_overlay("t-1", [_row("det-1", suppression_config='{"suppress_when": {"host": ["JENKINS-01"]}}')])
        assert overlay.overrides["det-1"].suppress_when == {"host": ["JENKINS-01"]}

    def test_a_malformed_config_does_not_raise(self) -> None:
        overlay = build_overlay("t-1", [_row("det-1", suppression_config="not json")])
        assert overlay.overrides["det-1"].suppress_when == {}


class TestSuppression:
    def test_a_disabled_rule_is_suppressed_with_a_reason(self) -> None:
        overlay = build_overlay(
            "t-1",
            [
                _row(
                    "det-1",
                    status="disabled",
                    author="alice@example.com",
                    suppression_config={"reason": "known noisy on build agents"},
                )
            ],
        )
        why = overlay.suppresses("det-1", {})
        assert why is not None
        assert "disabled" in why
        assert "alice@example.com" in why, "the author must travel with the suppression"
        assert "build agents" in why, "the reason must travel with the suppression"

    def test_a_field_match_suppresses(self) -> None:
        overlay = build_overlay(
            "t-1",
            [_row("det-1", suppression_config={"suppress_when": {"host": ["JENKINS-01"]}})],
        )
        assert overlay.suppresses("det-1", {"host": "JENKINS-01"}) is not None
        assert overlay.suppresses("det-1", {"host": "WIN-FIN-02"}) is None

    def test_an_absent_field_does_not_suppress(self) -> None:
        """Suppressing on a field the event does not carry would silence
        every event rather than the ones the tenant meant."""
        overlay = build_overlay("t-1", [_row("det-1", suppression_config={"suppress_when": {"host": ["X"]}})])
        assert overlay.suppresses("det-1", {"user": "j.doe"}) is None

    def test_an_untuned_rule_is_never_suppressed(self) -> None:
        assert build_overlay("t-1", []).suppresses("det-1", {"host": "anything"}) is None


class TestTheSeverityFloor:
    def test_a_match_below_the_floor_is_held(self) -> None:
        overlay = build_overlay("t-1", [_row("det-1", threshold_config={"min_severity": "high"})])
        assert overlay.raises_severity_floor("det-1", "medium") is not None
        assert overlay.raises_severity_floor("det-1", "high") is None
        assert overlay.raises_severity_floor("det-1", "critical") is None

    def test_an_unknown_severity_does_not_silently_hold(self) -> None:
        """A severity the ladder does not know must not be treated as the
        lowest, which would suppress it."""
        overlay = build_overlay("t-1", [_row("det-1", threshold_config={"min_severity": "high"})])
        assert overlay.raises_severity_floor("det-1", "unknown-tier") is None


class _Conn:
    def __init__(self, rows, fail=False) -> None:  # noqa: ANN001
        self.rows = rows
        self.fail = fail
        self.fetches = 0

    async def fetch(self, sql, *args):  # noqa: ANN001, ARG002
        self.fetches += 1
        if self.fail:
            raise RuntimeError("database down")
        return [r for r in self.rows if str(r.get("_tenant", args[0])) == str(args[0])]


class _Pool:
    def __init__(self, conn: _Conn) -> None:
        self._conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self._conn


@pytest.mark.asyncio
class TestTenantIsolation:
    async def test_one_tenants_tuning_does_not_reach_another(self) -> None:
        """The plan's own done-when, and the thing a dict keyed on rule id
        alone gets wrong silently."""
        rows = [
            {**_row("det-1", status="disabled"), "_tenant": "t-1"},
            {**_row("det-2", status="disabled"), "_tenant": "t-2"},
        ]
        cache = OverlayCache(_Pool(_Conn(rows)), reload_seconds=0)

        a = await cache.get("t-1")
        b = await cache.get("t-2")

        assert "det-1" in a.overrides and "det-2" not in a.overrides
        assert "det-2" in b.overrides and "det-1" not in b.overrides
        assert a.suppresses("det-2", {}) is None, "tenant A inherited tenant B's suppression"


@pytest.mark.asyncio
class TestHotReload:
    async def test_it_refetches_after_the_interval(self) -> None:
        conn = _Conn([_row("det-1", status="disabled")])
        cache = OverlayCache(_Pool(conn), reload_seconds=10)
        await cache.get("t-1", now=0.0)
        await cache.get("t-1", now=1.0)
        assert conn.fetches == 1, "it refetched inside the interval"
        await cache.get("t-1", now=100.0)
        assert conn.fetches == 2, "it did not refetch after the interval"

    async def test_an_explicit_invalidate_forces_a_refetch(self) -> None:
        conn = _Conn([_row("det-1", status="disabled")])
        cache = OverlayCache(_Pool(conn), reload_seconds=10_000)
        await cache.get("t-1", now=0.0)
        cache.invalidate("t-1")
        await cache.get("t-1", now=1.0)
        assert conn.fetches == 2


@pytest.mark.asyncio
class TestAFailedReload:
    async def test_it_keeps_the_previous_overlay(self) -> None:
        """Falling back to no-tuning would turn the tenant's queue back on,
        which reads as a flood rather than as a fault."""
        conn = _Conn([_row("det-1", status="disabled")])
        cache = OverlayCache(_Pool(conn), reload_seconds=0)
        first = await cache.get("t-1")
        assert "det-1" in first.overrides

        conn.fail = True
        second = await cache.get("t-1")
        assert second.suppresses("det-1", {}) is not None, "the suppression was lost on a transient database failure"

    async def test_a_first_load_that_fails_returns_empty_rather_than_raising(self) -> None:
        """Nothing is cached yet, so there is nothing to keep. Detection
        must continue rather than stop."""
        cache = OverlayCache(_Pool(_Conn([], fail=True)), reload_seconds=0)
        assert await cache.get("t-1") is EMPTY

    async def test_no_pool_is_empty_not_an_error(self) -> None:
        assert await OverlayCache(None).get("t-1") is EMPTY


class TestTheEngineAppliesIt:
    def test_evaluate_accepts_an_overlay(self) -> None:
        import inspect

        from app.services.detection_engine import DetectionEngine

        signature = inspect.signature(DetectionEngine.evaluate)
        assert "overlay" in signature.parameters, "the streaming engine cannot see tenant tuning, which is the defect 5.4 exists to fix"

    def test_a_suppressed_hit_is_dropped(self) -> None:
        from app.services.detection_engine import DetectionEngine

        rules = [
            {
                "id": "det-1",
                "name": "Noisy",
                "severity": "high",
                "category": "endpoint",
                "match_when": {"host": "JENKINS-01"},
            }
        ]
        engine = DetectionEngine(rules=rules)
        message = {"ocsf_event": {"raw_data": '{"host": "JENKINS-01"}'}}

        assert engine.evaluate(message), "the rule did not fire without an overlay"

        overlay = build_overlay("t-1", [_row("det-1", suppression_config={"suppress_when": {"host": ["JENKINS-01"]}})])
        assert engine.evaluate(message, overlay) == [], "the tenant's suppression was ignored"

    def test_an_empty_overlay_changes_nothing(self) -> None:
        """A tenant who has tuned nothing must see exactly what they saw
        before this existed."""
        from app.services.detection_engine import DetectionEngine

        rules = [
            {
                "id": "det-1",
                "name": "Noisy",
                "severity": "high",
                "category": "endpoint",
                "match_when": {"host": "JENKINS-01"},
            }
        ]
        engine = DetectionEngine(rules=rules)
        message = {"ocsf_event": {"raw_data": '{"host": "JENKINS-01"}'}}
        assert engine.evaluate(message, EMPTY) == engine.evaluate(message)

    def test_the_overlay_is_optional(self) -> None:
        """Additive: every existing caller passes nothing and is
        unaffected."""
        import inspect

        from app.services.detection_engine import DetectionEngine

        assert inspect.signature(DetectionEngine.evaluate).parameters["overlay"].default is None


class TestTheOverlayType:
    def test_empty_is_shared_and_carries_no_overrides(self) -> None:
        assert isinstance(EMPTY, TenantOverlay)
        assert EMPTY.overrides == {}


class TestPerTenantAllowlists:
    """Parity 5.5. The cheapest of the five unreachable families.

    15 rules read an `<x>_in_allowlist` boolean that nothing computed, so
    they could never fire on any connector. An allowlist is the same
    decision a tenant already expresses as a suppression, so the overlay
    was the natural place for it: 133 unreachable rules became 119.

    Per tenant rather than in the shared derived-field pass, because a
    global allowlist would make one tenant's exceptions apply to
    everybody.
    """

    def test_a_member_is_in_the_allowlist(self) -> None:
        from app.services.tenant_overlay import allowlist_fields

        out = allowlist_fields({"src_country": ["GB", "US"]}, {"src_country": "GB"})
        assert out["src_country_in_allowlist"] is True
        assert out["src_country_not_in_allowlist"] is False

    def test_a_stranger_is_not(self) -> None:
        from app.services.tenant_overlay import allowlist_fields

        out = allowlist_fields({"src_country": ["GB"]}, {"src_country": "RU"})
        assert out["src_country_in_allowlist"] is False
        assert out["src_country_not_in_allowlist"] is True

    def test_an_unconfigured_allowlist_contributes_no_key(self) -> None:
        """The property that matters most.

        A `not_in_allowlist` clause against a missing key is true for
        every event, so the rule would fire on all of them. That is the
        negation-flips-on-absence failure already recorded for the Sigma
        import, and `False` would be just as wrong in the other
        direction.
        """
        from app.services.tenant_overlay import allowlist_fields

        assert allowlist_fields({}, {"src_country": "RU"}) == {}

    def test_an_absent_event_field_contributes_no_key(self) -> None:
        from app.services.tenant_overlay import allowlist_fields

        assert allowlist_fields({"src_country": ["GB"]}, {"user": "j.doe"}) == {}

    def test_every_allowlist_boolean_the_corpus_reads_is_mapped(self) -> None:
        """Otherwise a rule stays unreachable while the ratchet says it is
        not."""
        import json
        import pathlib as _p
        import re

        from app.services.tenant_overlay import ALLOWLIST_FIELDS

        corpus = _p.Path(__file__).resolve().parents[1] / "app/data/detection_ruleset.json"
        rules = json.loads(corpus.read_text())
        rules = rules if isinstance(rules, list) else rules.get("rules", [])
        wanted = set()
        for rule in rules:
            wanted.update(re.findall(r'"([a-z_]+_(?:not_)?in_allowlist)"', json.dumps(rule.get("match_when") or {})))
        missing = wanted - set(ALLOWLIST_FIELDS)
        assert not missing, f"the corpus reads allowlist booleans nothing derives: {sorted(missing)}"

    def test_a_rule_that_could_never_fire_now_can(self) -> None:
        """End to end through the real engine."""
        from app.services.detection_engine import DetectionEngine
        from app.services.tenant_overlay import build_overlay

        rules = [
            {
                "id": "r1",
                "name": "Login from an unexpected country",
                "severity": "high",
                "category": "identity",
                "match_when": {"src_country_not_in_allowlist": True},
            }
        ]
        engine = DetectionEngine(rules=rules)
        event = {"ocsf_event": {"raw_data": '{"src_country": "RU"}'}}

        assert engine.evaluate(event) == [], "the rule fired with no allowlist configured"

        overlay = build_overlay(
            "t-1",
            [_row("other", suppression_config={"allowlists": {"src_country": ["GB"]}})],
        )
        assert len(engine.evaluate(event, overlay)) == 1, "the rule still cannot fire"

        allowed = {"ocsf_event": {"raw_data": '{"src_country": "GB"}'}}
        assert engine.evaluate(allowed, overlay) == [], "an allowlisted country still alerted"


class TestTheQueryMatchesTheRealSchema:
    """The gap that let a non-existent column ship.

    `_fetch` selected `rule_id` and `updated_by` from `detection_rules`,
    which has neither. Every test above passed, because a fake answers
    whatever it is asked — so the overlay would have loaded nothing on
    every deployment while the suite stayed green. Live QA found it.

    This reads the migration rather than a second hand-written list,
    because a list maintained beside the query drifts in the same
    direction the query already drifted.
    """

    def test_every_selected_column_exists_in_the_migration(self) -> None:
        import pathlib as _p
        import re

        root = _p.Path(__file__).resolve().parents[3]
        init = (root / "services/api/migrations/001_init.sql").read_text()

        body = re.search(
            r"CREATE TABLE (?:IF NOT EXISTS )?detection_rules\s*\((.*?)\n\);",
            init,
            re.S | re.I,
        )
        assert body, "detection_rules is not created in 001_init.sql; this test is looking in the wrong place"

        declared = {m.group(1).lower() for line in body.group(1).splitlines() if (m := re.match(r"\s*([a-z_][a-z0-9_]*)\s+[A-Za-z]", line))}
        # Later migrations add columns; pick those up too rather than
        # failing on a column that exists but arrived after 001.
        for path in sorted((root / "services/api/migrations").glob("*.sql")):
            for m in re.finditer(
                r"ALTER TABLE\s+(?:IF EXISTS\s+)?detection_rules\s+ADD COLUMN\s+(?:IF NOT EXISTS\s+)?([a-z_][a-z0-9_]*)",
                path.read_text(),
                re.I,
            ):
                declared.add(m.group(1).lower())

        source = (_p.Path(__file__).resolve().parents[1] / "app/services/tenant_overlay.py").read_text()
        projection = re.search(r"SELECT (.*?)\s+FROM detection_rules", source, re.S)
        assert projection, "the overlay no longer selects from detection_rules"

        referenced = {token.lower() for token in re.findall(r"\b([a-z_][a-z0-9_]*)\b", projection.group(1))} - {
            "coalesce",
            "as",
            "rule_id",
            "source_id",
            "null",
        }

        missing = referenced - declared
        assert not missing, (
            f"the overlay selects column(s) no migration creates: {sorted(missing)}. "
            "Every execution of this query raises UndefinedColumnError, the handler turns "
            "it into a warning, and the overlay silently loads nothing."
        )
