"""The insider watchlist is a control, not a checkbox.

What was wrong
--------------
``user_risk_profiles.is_watchlisted`` existed since migration 014 and the
console PATCH wrote it — and nothing consumed it. No alert was elevated, no
row ever expired, and nothing reviewed the identity's recent activity. The
docstring family: a feature whose whole implementation was its storage.

What this asserts
-----------------
* **Elevation goes through the existing business-context path.** The managed
  document `managed_rules_yaml` generates parses with the same loader the
  console uses, and evaluated by the real engine it tags the identity's
  alerts and raises `info`/`low` to `medium` — and **never touches** `high`
  or `critical`, because `set_severity` is a fixed assignment and a blanket
  rule would downgrade exactly the alerts that matter.
* Adversarial reasons (quotes, newlines, YAML syntax) stay data.
* Watchlisting requires a reason and a future expiry — never indefinite.
* The lookback reports an unreachable lake as *could not check*, never as
  zero, and opens the review case either way.
* The HR door is idempotent and never overwrites an existing row.
* The generated document is pinned to a golden fixture that the agents-side
  test parses with *its* independent loader, so the two implementations of
  the grammar cannot drift apart silently.

The Postgres truths (expiry exclusion inside the SQL, RLS, the upsert that
preserves the analyst's yaml_text) live in
``tests/isolation/test_insider_watchlist_live.py``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.services import insider_watchlist as svc
from app.services.business_context.engine import BusinessContextEngine
from app.services.business_context.models import load_rules_from_yaml

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
GOLDEN = Path(__file__).parent / "fixtures" / "managed_rules_golden.yaml"

_FUTURE = datetime(2030, 1, 15, tzinfo=UTC)


def _entries() -> list[svc.WatchEntry]:
    return [
        svc.WatchEntry(ref="mallory@example.com", reason="resignation accepted", expires_at=_FUTURE),
        svc.WatchEntry(ref="o'brien@example.com", reason="HR: status 'terminated'\nlast day 2030-01-01", expires_at=_FUTURE),
    ]


def _evaluate(yaml_doc: str, alert: dict[str, Any]) -> Any:
    engine = BusinessContextEngine()
    engine.replace(TENANT, load_rules_from_yaml(yaml_doc))
    return engine.evaluate(TENANT, alert)


class TestManagedRuleGeneration:
    def test_parses_with_the_consoles_own_loader(self) -> None:
        rules = load_rules_from_yaml(svc.managed_rules_yaml(_entries()))
        assert len(rules) == 4  # tag + floor per identity
        assert all(r.id.startswith("managed-insider-watchlist-") for r in rules)

    def test_tags_and_floors_a_low_severity_alert(self) -> None:
        doc = svc.managed_rules_yaml(_entries())
        result = _evaluate(doc, {"username": "mallory@example.com", "severity": "low"})
        assert result.after.get("severity") == "medium"
        assert "insider-watchlist" in (result.after.get("tags") or [])

    @pytest.mark.parametrize("severity", ["high", "critical", "medium"])
    def test_never_downgrades(self, severity: str) -> None:
        """`set_severity` is a fixed assignment; the guard is the `in` clause."""
        doc = svc.managed_rules_yaml(_entries())
        result = _evaluate(doc, {"username": "mallory@example.com", "severity": severity})
        assert result.after.get("severity") == severity

    def test_other_identities_are_untouched(self) -> None:
        doc = svc.managed_rules_yaml(_entries())
        result = _evaluate(doc, {"username": "alice@example.com", "severity": "low"})
        assert result.after.get("severity") == "low"
        assert not result.matched_rule_ids

    def test_adversarial_reason_stays_data(self) -> None:
        """A reason containing YAML syntax must not become structure."""
        hostile = svc.WatchEntry(
            ref="eve@example.com",
            reason="x'\nrules:\n  - id: injected\n    then: {suppress: true}",
            expires_at=_FUTURE,
        )
        rules = load_rules_from_yaml(svc.managed_rules_yaml([hostile]))
        assert len(rules) == 2
        assert not any(r.id == "injected" for r in rules)

    def test_no_entries_means_an_empty_document(self) -> None:
        assert svc.managed_rules_yaml([]) == ""

    def test_matches_the_golden_fixture_the_agents_side_parses(self) -> None:
        """The agents service re-implements the grammar (separate image, no
        shared import). The golden fixture is the bridge: this test pins the
        generator to it, and the agents suite parses the same bytes with its
        own loader. Regenerate deliberately when generation changes:

            python -c "import sys; sys.path.insert(0, 'services/api');
            from app.services.insider_watchlist import *;
            print(managed_rules_yaml([...]), end='')" > .../managed_rules_golden.yaml
        """
        assert GOLDEN.read_text() == svc.managed_rules_yaml(_entries())


class TestValidation:
    def test_reason_is_required(self) -> None:
        with pytest.raises(svc.WatchlistValidationError, match="reason"):
            svc.validate_watchlist_request(reason="  ", expires_at=_FUTURE)

    def test_expiry_is_required(self) -> None:
        with pytest.raises(svc.WatchlistValidationError, match="never indefinite"):
            svc.validate_watchlist_request(reason="leaving", expires_at=None)

    def test_expiry_must_be_future(self) -> None:
        past = datetime.now(UTC) - timedelta(days=1)
        with pytest.raises(svc.WatchlistValidationError, match="future"):
            svc.validate_watchlist_request(reason="leaving", expires_at=past)

    def test_expiry_must_be_aware(self) -> None:
        with pytest.raises(svc.WatchlistValidationError, match="timezone-aware"):
            svc.validate_watchlist_request(
                reason="leaving",
                expires_at=datetime(2030, 1, 1),  # noqa: DTZ001 — the point
            )


def _profile(ref: str | None = "mallory@example.com", watchlisted: bool = False) -> MagicMock:
    profile = MagicMock()
    profile.id = uuid.uuid4()
    profile.tenant_id = TENANT
    profile.external_user_ref = ref
    profile.is_watchlisted = watchlisted
    return profile


def _session_for_lookback(alert_count: int | None = 3) -> MagicMock:
    """A session whose execute() answers the alerts count and records adds."""
    db = MagicMock()
    db.added = []
    db.add = lambda obj: db.added.append(obj)
    db.flush = AsyncMock()

    async def _execute(stmt: Any, params: dict | None = None) -> MagicMock:
        result = MagicMock()
        text = str(getattr(stmt, "text", stmt))
        if "count(*) FROM alerts" in text:
            if alert_count is None:
                raise RuntimeError("alerts table unavailable")
            result.scalar_one.return_value = alert_count
        else:  # the watchlist select / managed-yaml upsert
            result.fetchall.return_value = []
        return result

    db.execute = AsyncMock(side_effect=_execute)
    return db


class TestLookback:
    @pytest.mark.asyncio
    async def test_unreachable_lake_is_could_not_check_never_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _boom(sql: str, **kwargs: Any) -> Any:
            raise ConnectionError("lake down")

        monkeypatch.setattr(svc, "execute_lake_query", _boom)
        db = _session_for_lookback(alert_count=3)
        profile = _profile()
        case_id = await svc.run_lookback(db, tenant_id=TENANT, profile=profile, reason="leaving", lookback_days=30)
        assert case_id is not None
        case = next(o for o in db.added if getattr(o, "case_type", "") == "insider_review")
        assert "unknown, not zero" in case.description
        assert "Could not check" in case.description
        indicator = next(o for o in db.added if getattr(o, "indicator_type", "") == "departure_lookback")
        assert any("lake" in item for item in indicator.evidence["could_not_check"])
        assert indicator.evidence["alerts_in_window"] == 3

    @pytest.mark.asyncio
    async def test_lake_counts_are_rendered_per_event_type(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _rows(sql: str, **kwargs: Any) -> Any:
            result = MagicMock()
            result.rows = [("FileUploaded", "m365_audit", 41, "2030-01-01", "2030-01-10")]
            return result

        monkeypatch.setattr(svc, "execute_lake_query", _rows)
        db = _session_for_lookback(alert_count=0)
        case_id = await svc.run_lookback(db, tenant_id=TENANT, profile=_profile(), reason="leaving", lookback_days=30)
        assert case_id is not None
        case = next(o for o in db.added if getattr(o, "case_type", "") == "insider_review")
        assert "FileUploaded via m365_audit: 41 event(s)" in case.description

    @pytest.mark.asyncio
    async def test_a_refless_profile_reports_both_gaps(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(svc, "execute_lake_query", AsyncMock())
        db = _session_for_lookback()
        await svc.run_lookback(db, tenant_id=TENANT, profile=_profile(ref=None), reason="leaving", lookback_days=30)
        indicator = next(o for o in db.added if getattr(o, "indicator_type", "") == "departure_lookback")
        gaps = indicator.evidence["could_not_check"]
        assert any(g.startswith("lake:") for g in gaps)
        assert any(g.startswith("alerts:") for g in gaps)
        svc.execute_lake_query.assert_not_called()  # type: ignore[attr-defined, union-attr]  # the monkeypatched AsyncMock


class TestApplyWatchlist:
    @pytest.mark.asyncio
    async def test_the_transition_rebuilds_and_runs_lookback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rebuild = AsyncMock(return_value=1)
        lookback = AsyncMock(return_value=uuid.uuid4())
        monkeypatch.setattr(svc, "rebuild_managed_rules", rebuild)
        monkeypatch.setattr(svc, "run_lookback", lookback)
        db = MagicMock()
        db.flush = AsyncMock()
        profile = _profile(watchlisted=False)

        outcome = await svc.apply_watchlist(
            db,
            profile,
            reason="resignation",
            expires_at=_FUTURE,
            source="manual",
            actor_id=uuid.uuid4(),
            lookback_days=30,
        )
        rebuild.assert_awaited_once()
        lookback.assert_awaited_once()
        assert outcome.elevation_active is True
        assert outcome.elevation_gap is None
        assert profile.watchlist_source == "manual"
        assert profile.watchlist_expires_at == _FUTURE

    @pytest.mark.asyncio
    async def test_a_refresh_does_not_open_a_second_case(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(svc, "rebuild_managed_rules", AsyncMock(return_value=1))
        lookback = AsyncMock()
        monkeypatch.setattr(svc, "run_lookback", lookback)
        db = MagicMock()
        db.flush = AsyncMock()
        outcome = await svc.apply_watchlist(
            db,
            _profile(watchlisted=True),
            reason="extended",
            expires_at=_FUTURE,
            source="manual",
            actor_id=None,
            lookback_days=30,
        )
        lookback.assert_not_awaited()
        assert outcome.lookback_case_id is None

    @pytest.mark.asyncio
    async def test_a_refless_identity_names_the_elevation_gap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(svc, "rebuild_managed_rules", AsyncMock(return_value=0))
        monkeypatch.setattr(svc, "run_lookback", AsyncMock(return_value=None))
        db = MagicMock()
        db.flush = AsyncMock()
        outcome = await svc.apply_watchlist(
            db,
            _profile(ref=""),
            reason="leaving",
            expires_at=_FUTURE,
            source="manual",
            actor_id=None,
            lookback_days=30,
        )
        assert outcome.elevation_active is False
        assert "external_user_ref" in (outcome.elevation_gap or "")


class TestHrDoor:
    @pytest.mark.asyncio
    async def test_an_already_listed_identity_is_never_touched(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The HR door must not overwrite — in particular never shorten — a
        manual watchlist row."""
        apply_mock = AsyncMock()
        monkeypatch.setattr(svc, "apply_watchlist", apply_mock)

        existing_id = uuid.uuid4()
        listed_profile = _profile(watchlisted=True)

        db = MagicMock()
        db.flush = AsyncMock()
        db.get = AsyncMock(return_value=listed_profile)

        async def _execute(stmt: Any, params: dict | None = None) -> MagicMock:
            result = MagicMock()
            text = str(getattr(stmt, "text", stmt))
            if "FROM insider_watchlist_policies" in text:
                result.fetchall.return_value = [(TENANT, 14, 30, 30)]
            elif "FROM workforce_members" in text:
                result.fetchall.return_value = [("w-1", "mallory@example.com", "Mallory", "terminated", None)]
            elif "FROM user_risk_profiles" in text:
                result.scalar_one_or_none.return_value = existing_id
            return result

        db.execute = AsyncMock(side_effect=_execute)
        summary = await svc.sweep_hr(db)
        assert summary.hr_tenants == 1
        assert summary.hr_watchlisted == 0
        apply_mock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_a_departing_member_is_listed_with_the_hr_fact(self, monkeypatch: pytest.MonkeyPatch) -> None:
        apply_mock = AsyncMock()
        monkeypatch.setattr(svc, "apply_watchlist", apply_mock)
        db = MagicMock()
        db.flush = AsyncMock()
        db.get = AsyncMock(return_value=None)

        async def _execute(stmt: Any, params: dict | None = None) -> MagicMock:
            result = MagicMock()
            text = str(getattr(stmt, "text", stmt))
            if "FROM insider_watchlist_policies" in text:
                result.fetchall.return_value = [(TENANT, 14, 30, 45)]
            elif "FROM workforce_members" in text:
                result.fetchall.return_value = [
                    ("w-2", "Leaver@Example.com", "Lea Ver", "terminated", datetime(2030, 1, 1, tzinfo=UTC).date())
                ]
            elif "FROM user_risk_profiles" in text:
                result.scalar_one_or_none.return_value = None
            return result

        db.execute = AsyncMock(side_effect=_execute)
        summary = await svc.sweep_hr(db)
        assert summary.hr_watchlisted == 1
        assert apply_mock.await_args is not None
        kwargs = apply_mock.await_args.kwargs
        assert kwargs["source"] == "hr_sync"
        assert "terminated" in kwargs["reason"]
        assert "2030-01-01" in kwargs["reason"]
        assert kwargs["lookback_days"] == 45
        # expiry = last day + grace(14), never in the past
        assert kwargs["expires_at"] == datetime(2030, 1, 1, tzinfo=UTC) + timedelta(days=14)
