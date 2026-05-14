"""Unit tests for the investigation-queue workbench backend (W7 / PR-5).

The queue service in ``app.services.alert_queue`` is split into pure
helpers + an async orchestrator, mirroring the alert-explain pattern
we already test in ``test_alert_explain.py``. We test it the same way:

* **Pure helpers** (``first_asset``, ``first_action``) get
  straightforward in-process tests with hand-built ``Alert``
  stand-ins. These lock in the "one anchor entity per row" and
  "top suggested action" projections the workbench renders.

* **SLA target resolution** (``load_sla_targets``) is exercised
  against an in-memory ``MagicMock(AsyncSession)``. The defaults
  matter: a tenant with zero overrides must still get a full
  ``severity → mttd_target_minutes`` map, otherwise the SQL
  ``CASE`` for ``sla_due_at`` would produce ``NULL`` rows and the
  workbench would drop them silently.

* **`sla_due_at_expression`** is a SQL expression. We only verify it
  compiles into a ``CASE`` block — full equivalence is covered by the
  integration tests in CI which exercise real Postgres.

* **`build_queue`** is unit-tested by mocking every
  ``AsyncSession.execute`` call. We exercise the owner filter,
  pagination math, the counts contract, and the row-projection
  pipeline (alert → ``QueueItem``). The opinionated SQL ordering
  itself is exercised end-to-end by the integration tests; here we
  prove that whatever rows the DB returns in order are projected in
  that same order, with the correct ``bucket`` / ``sla_*`` fields.

* **`claim_alert`** gets dedicated coverage for all four documented
  branches: unassigned-grab-succeeds, already-mine-idempotent,
  already-someone-else-409, lost-the-race-409. The latter walks the
  fallback re-read path so the error carries the *actual* owner.

The tests deliberately do NOT spin up FastAPI's TestClient or a real
Postgres. The endpoint module is a thin orchestration layer; the
service layer here is what carries the business rules. Mocking the
session keeps the suite fast (<1s) and deterministic.

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.services.alert_queue import (
    QUEUE_CLOSED_STATUSES,
    QUEUE_UNASSIGNED_SEVERITIES,
    AlertAlreadyClaimedError,
    AlertNotFoundError,
    QueueAction,
    QueueAsset,
    build_queue,
    claim_alert,
    first_action,
    first_asset,
    load_sla_targets,
    sla_due_at_expression,
)
from app.services.sla import DEFAULT_SLA_TARGETS

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _alert(
    *,
    alert_id: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None,
    title: str = "Suspicious login from new geo",
    severity: str = "high",
    status: str = "new",
    priority: int = 50,
    category: str | None = "identity",
    connector_type: str | None = "okta",
    assigned_to_id: uuid.UUID | None = None,
    case_id: uuid.UUID | None = None,
    affected_hosts: list[Any] | None = None,
    affected_users: list[Any] | None = None,
    affected_assets: list[Any] | None = None,
    affected_ips: list[Any] | None = None,
    ai_recommendations: list[Any] | None = None,
    first_seen: datetime | None = None,
    assigned_at: datetime | None = None,
    snoozed_until: datetime | None = None,
) -> SimpleNamespace:
    """Build a stand-in for the ``Alert`` ORM object.

    ``SimpleNamespace`` is the same pattern we use in
    ``test_alert_explain.py``: the service code only ever
    attribute-accesses fields it needs, never calls ORM-only methods.
    Using a namespace keeps the test free of SQLAlchemy setup / Postgres
    type wiring (``JSONB``/``UUID``) that would otherwise pin the
    suite to an integration harness.
    """
    return SimpleNamespace(
        id=alert_id or uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        title=title,
        severity=severity,
        status=status,
        priority=priority,
        category=category,
        connector_type=connector_type,
        assigned_to_id=assigned_to_id,
        case_id=case_id,
        affected_hosts=affected_hosts or [],
        affected_users=affected_users or [],
        affected_assets=affected_assets or [],
        affected_ips=affected_ips or [],
        ai_recommendations=ai_recommendations or [],
        first_seen=first_seen or datetime.now(UTC) - timedelta(minutes=10),
        assigned_at=assigned_at,
        snoozed_until=snoozed_until,
    )


def _scalar_one_or_none_result(value: Any) -> MagicMock:
    """Mock ``await session.execute(...).scalar_one_or_none() == value``."""
    result = MagicMock()
    result.scalar_one_or_none = MagicMock(return_value=value)
    return result


def _scalar_one_result(value: Any) -> MagicMock:
    """Mock ``await session.execute(...).scalar_one() == value``."""
    result = MagicMock()
    result.scalar_one = MagicMock(return_value=value)
    return result


def _scalars_all_result(values: list[Any]) -> MagicMock:
    """Mock ``await session.execute(...).scalars().all() == values``."""
    result = MagicMock()
    scalars = MagicMock()
    scalars.all = MagicMock(return_value=values)
    result.scalars = MagicMock(return_value=scalars)
    return result


def _rows_all_result(rows: list[tuple[Any, ...]]) -> MagicMock:
    """Mock ``await session.execute(...).all() == rows``.

    ``build_queue`` projects ``select(Alert, bucket_expr, sla_expr)``
    and iterates ``rows`` indexing as ``row[0]``, ``row[1]``,
    ``row[2]``. We use tuples to mirror that exactly.
    """
    result = MagicMock()
    result.all = MagicMock(return_value=rows)
    return result


def _tenant_sla_cfg(severity: str, mttd_target: int) -> SimpleNamespace:
    """Stand-in for a ``TenantSLAConfig`` row."""
    return SimpleNamespace(severity=severity, mttd_target=mttd_target)


# ---------------------------------------------------------------------------
# load_sla_targets — defaults + tenant overrides
# ---------------------------------------------------------------------------


class TestLoadSlaTargets:
    """Tenant overrides win, defaults fill the rest.

    A regression here would either (a) drop a severity that the
    tenant didn't override — silently dropping rows from the queue —
    or (b) ignore tenant overrides — pinning every tenant to the
    out-of-the-box MTTD targets.
    """

    @pytest.mark.asyncio
    async def test_returns_defaults_when_no_tenant_overrides(self) -> None:
        # Empty config → fall back to ``DEFAULT_SLA_TARGETS`` for
        # every severity. The dict must contain every key the
        # ``CASE`` expression branches on, including ``info``.
        db = MagicMock()
        db.execute = AsyncMock(return_value=_scalars_all_result([]))

        targets = await load_sla_targets(db, uuid.uuid4())

        assert set(targets.keys()) == set(DEFAULT_SLA_TARGETS.keys())
        for sev, default in DEFAULT_SLA_TARGETS.items():
            assert targets[sev] == default["mttd_target"]

    @pytest.mark.asyncio
    async def test_tenant_override_wins(self) -> None:
        # Only the overridden severity should change; the rest must
        # keep their defaults.
        db = MagicMock()
        db.execute = AsyncMock(return_value=_scalars_all_result([_tenant_sla_cfg("critical", 5)]))

        targets = await load_sla_targets(db, uuid.uuid4())

        assert targets["critical"] == 5
        # All other severities keep defaults.
        assert targets["high"] == DEFAULT_SLA_TARGETS["high"]["mttd_target"]
        assert targets["medium"] == DEFAULT_SLA_TARGETS["medium"]["mttd_target"]
        assert targets["low"] == DEFAULT_SLA_TARGETS["low"]["mttd_target"]
        assert targets["info"] == DEFAULT_SLA_TARGETS["info"]["mttd_target"]

    @pytest.mark.asyncio
    async def test_unknown_severity_override_is_ignored(self) -> None:
        # A row with a severity outside the canonical ladder
        # (mis-configured tenant table) must NOT inject a new key
        # into the result — that would break the SQL ``CASE`` (which
        # only branches on the canonical severities).
        db = MagicMock()
        db.execute = AsyncMock(return_value=_scalars_all_result([_tenant_sla_cfg("unknown_severity", 99)]))

        targets = await load_sla_targets(db, uuid.uuid4())

        assert "unknown_severity" not in targets
        # Defaults still present and unmodified.
        assert targets["critical"] == DEFAULT_SLA_TARGETS["critical"]["mttd_target"]

    @pytest.mark.asyncio
    async def test_multiple_overrides_apply_independently(self) -> None:
        # Each row overrides exactly one severity. We expect the
        # final dict to reflect every override, not just the last one.
        db = MagicMock()
        db.execute = AsyncMock(
            return_value=_scalars_all_result(
                [
                    _tenant_sla_cfg("critical", 10),
                    _tenant_sla_cfg("high", 20),
                    _tenant_sla_cfg("medium", 90),
                ]
            )
        )

        targets = await load_sla_targets(db, uuid.uuid4())

        assert targets["critical"] == 10
        assert targets["high"] == 20
        assert targets["medium"] == 90
        # Untouched severities still default.
        assert targets["low"] == DEFAULT_SLA_TARGETS["low"]["mttd_target"]


# ---------------------------------------------------------------------------
# sla_due_at_expression — compiles to a CASE expression
# ---------------------------------------------------------------------------


class TestSlaDueAtExpression:
    """Verify the SQL expression is well-formed.

    We don't try to execute it here — that requires a real Postgres
    session because ``Alert.first_seen + timedelta`` lowers to
    Postgres' interval arithmetic. The integration tests cover that.
    What we *can* lock in here is that the expression compiles into
    a ``CASE`` block with one branch per severity in our target map.
    """

    def test_returns_case_expression(self) -> None:
        targets = {sev: cfg["mttd_target"] for sev, cfg in DEFAULT_SLA_TARGETS.items()}
        expr = sla_due_at_expression(targets)

        # ``case`` returns a ``Case`` element; compiling it as a
        # generic SQL string is enough to prove it's well-formed.
        compiled = str(expr).upper()
        assert "CASE" in compiled

    def test_empty_targets_still_compiles(self) -> None:
        # Defensive: empty dict should not crash construction (the
        # fallback branch using DEFAULT_SLA_TARGETS["info"] always
        # exists).
        expr = sla_due_at_expression({})
        compiled = str(expr).upper()
        assert "CASE" in compiled


# ---------------------------------------------------------------------------
# first_asset — host > user > asset > ip
# ---------------------------------------------------------------------------


class TestFirstAsset:
    """Single-pivot extraction for queue rows.

    A regression here demotes the queue from "VPN brute force on
    web-01" back to "VPN brute force" — the entity is what makes a
    row scannable. We exhaustively cover every priority slot.
    """

    def test_prefers_host_over_others(self) -> None:
        alert = _alert(
            affected_hosts=["web-01"],
            affected_users=["alice@example.com"],
            affected_assets=["asset-1"],
            affected_ips=["10.0.0.1"],
        )
        asset = first_asset(alert)
        assert isinstance(asset, QueueAsset)
        assert asset.kind == "host"
        assert asset.value == "web-01"

    def test_falls_back_to_user_when_no_host(self) -> None:
        alert = _alert(
            affected_hosts=[],
            affected_users=["alice@example.com"],
            affected_ips=["10.0.0.1"],
        )
        asset = first_asset(alert)
        assert asset is not None and asset.kind == "user"
        assert asset.value == "alice@example.com"

    def test_falls_back_to_asset_when_no_host_or_user(self) -> None:
        alert = _alert(
            affected_hosts=[],
            affected_users=[],
            affected_assets=["crown-jewel-db"],
            affected_ips=["10.0.0.1"],
        )
        asset = first_asset(alert)
        assert asset is not None and asset.kind == "asset"
        assert asset.value == "crown-jewel-db"

    def test_falls_back_to_ip_last(self) -> None:
        alert = _alert(
            affected_hosts=[],
            affected_users=[],
            affected_assets=[],
            affected_ips=["192.168.1.42"],
        )
        asset = first_asset(alert)
        assert asset is not None and asset.kind == "ip"
        assert asset.value == "192.168.1.42"

    def test_returns_none_when_no_entities(self) -> None:
        # No entities → no anchor. The UI will omit the asset chip.
        alert = _alert(
            affected_hosts=[],
            affected_users=[],
            affected_assets=[],
            affected_ips=[],
        )
        assert first_asset(alert) is None

    def test_skips_blank_strings_and_non_strings(self) -> None:
        # Lists sometimes contain ``""`` or ``None`` after legacy
        # ingest pipelines stripped fields. The picker must skip
        # them rather than emit ``QueueAsset(value="")``.
        alert = _alert(
            affected_hosts=["", None, 42, "   "],
            affected_users=["bob"],
        )
        asset = first_asset(alert)
        assert asset is not None
        assert asset.kind == "user"
        assert asset.value == "bob"

    def test_strips_surrounding_whitespace(self) -> None:
        # Trailing spaces from a CSV-style ingest must not bleed
        # into the rendered chip.
        alert = _alert(affected_hosts=["  web-01  "])
        asset = first_asset(alert)
        assert asset is not None
        assert asset.value == "web-01"


# ---------------------------------------------------------------------------
# first_action — lowest priority wins, normalises shapes
# ---------------------------------------------------------------------------


class TestFirstAction:
    """Top suggested-next-action projection."""

    def test_returns_none_when_no_recommendations(self) -> None:
        alert = _alert(ai_recommendations=[])
        assert first_action(alert) is None

    def test_returns_none_when_field_is_not_list(self) -> None:
        # Defensive: older rows wrote dicts; the projection must
        # bail out instead of crashing.
        alert = _alert(ai_recommendations=None)  # type: ignore[arg-type]
        assert first_action(alert) is None

    def test_accepts_legacy_string_form(self) -> None:
        # Legacy: bare strings, no priority. Array index drives the
        # priority assignment (1-indexed).
        alert = _alert(ai_recommendations=["Reset password", "Notify user"])
        action = first_action(alert)
        assert isinstance(action, QueueAction)
        assert action.action == "Reset password"
        assert action.priority == 1
        # Risk defaults to "low" for legacy entries.
        assert action.risk == "low"

    def test_lowest_priority_wins(self) -> None:
        # Modern form: dict with explicit priority. Lower number =
        # more urgent. Out-of-order recommendations must still pick
        # the urgent one.
        alert = _alert(
            ai_recommendations=[
                {"action": "Low urgency", "priority": 3, "risk": "low"},
                {"action": "Highest urgency", "priority": 1, "risk": "high"},
                {"action": "Medium urgency", "priority": 2, "risk": "medium"},
            ]
        )
        action = first_action(alert)
        assert action is not None
        assert action.action == "Highest urgency"
        assert action.priority == 1
        assert action.risk == "high"

    def test_invalid_priority_falls_back_to_index(self) -> None:
        # Non-integer priority → use array-index fallback.
        alert = _alert(
            ai_recommendations=[
                {"action": "First", "priority": "garbage"},
                {"action": "Second", "priority": "also bad"},
            ]
        )
        action = first_action(alert)
        # Both fall back to idx+1 → first wins by index.
        assert action is not None
        assert action.action == "First"
        assert action.priority == 1

    def test_normalises_unknown_risk_to_low(self) -> None:
        # Risk must be one of low/medium/high. Anything else gets
        # clamped to ``low`` so the UI never paints a chip in an
        # unknown colour.
        alert = _alert(
            ai_recommendations=[
                {"action": "Quarantine host", "priority": 1, "risk": "EXTREME"},
            ]
        )
        action = first_action(alert)
        assert action is not None
        assert action.risk == "low"

    def test_normalises_risk_case_insensitively(self) -> None:
        # ``HIGH``/``High`` must be recognised, even though our enum
        # is lowercase. Pipelines sometimes capitalise risk labels.
        alert = _alert(
            ai_recommendations=[
                {"action": "Isolate", "priority": 1, "risk": "HIGH"},
            ]
        )
        action = first_action(alert)
        assert action is not None
        assert action.risk == "high"

    def test_skips_empty_action_strings(self) -> None:
        # An empty ``action`` field is useless to the analyst.
        # Skip and pick the next candidate.
        alert = _alert(
            ai_recommendations=[
                {"action": "  ", "priority": 1},
                {"action": "Real action", "priority": 2},
            ]
        )
        action = first_action(alert)
        assert action is not None
        assert action.action == "Real action"

    def test_priority_is_clamped_to_minimum_one(self) -> None:
        # ``priority=0`` or negative would distort the sort. We
        # clamp at 1 so 0-priority entries don't outrank
        # explicit-1 entries silently.
        alert = _alert(
            ai_recommendations=[
                {"action": "Sneaky", "priority": -10},
                {"action": "Honest", "priority": 1},
            ]
        )
        action = first_action(alert)
        # Both end up priority=1; first in array wins the stable sort.
        assert action is not None
        assert action.action == "Sneaky"
        assert action.priority == 1


# ---------------------------------------------------------------------------
# build_queue — owner filter, counts, ordering, pagination, projection
# ---------------------------------------------------------------------------


class TestBuildQueue:
    """End-to-end queue assembly with a mocked session.

    The opinionated SQL ordering itself is exercised by the
    integration tests in CI. Here we lock in:
      * counts are populated for both buckets regardless of filter,
      * the row projection produces correct ``QueueItem`` fields,
      * pagination math (``pages`` and ``offset``) is correct,
      * the ``owner=*`` selector picks the right total + filter.
    """

    def _setup_db(
        self,
        *,
        mine_count: int,
        unassigned_count: int,
        rows: list[tuple[Any, int, datetime]] | None = None,
        tenant_overrides: list[Any] | None = None,
    ) -> MagicMock:
        """Wire a session with the queue's 4-call execute pattern.

        Call order inside ``build_queue``:
          1) ``load_sla_targets``     → ``scalars().all()`` on tenant SLA config
          2) ``mine_count``           → ``scalar_one()``
          3) ``unassigned_count``     → ``scalar_one()``
          4) main projection query    → ``.all()`` of row tuples
        """
        db = MagicMock()
        db.execute = AsyncMock(
            side_effect=[
                _scalars_all_result(tenant_overrides or []),
                _scalar_one_result(mine_count),
                _scalar_one_result(unassigned_count),
                _rows_all_result(rows or []),
            ]
        )
        return db

    @pytest.mark.asyncio
    async def test_counts_populated_for_both_buckets(self) -> None:
        # Whatever the owner filter is, the response always carries
        # ``counts.mine`` and ``counts.unassigned`` so the workbench
        # tabs render without a second fetch.
        tenant_id = uuid.uuid4()
        user_id = uuid.uuid4()
        db = self._setup_db(mine_count=3, unassigned_count=7)

        resp = await build_queue(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            owner="me",
        )

        assert resp.counts == {"mine": 3, "unassigned": 7, "all": 10}
        # Even though owner="me" filters to mine only, the counts
        # *contract* never changes.
        assert resp.owner == "me"

    @pytest.mark.asyncio
    async def test_owner_me_uses_mine_count_as_total(self) -> None:
        db = self._setup_db(mine_count=3, unassigned_count=7)

        resp = await build_queue(
            db,
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            owner="me",
        )

        assert resp.total == 3

    @pytest.mark.asyncio
    async def test_owner_unassigned_uses_unassigned_count_as_total(self) -> None:
        db = self._setup_db(mine_count=3, unassigned_count=7)

        resp = await build_queue(
            db,
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            owner="unassigned",
        )

        assert resp.total == 7

    @pytest.mark.asyncio
    async def test_owner_all_uses_sum_as_total(self) -> None:
        db = self._setup_db(mine_count=3, unassigned_count=7)

        resp = await build_queue(
            db,
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            owner="all",
        )

        assert resp.total == 10

    @pytest.mark.asyncio
    async def test_empty_queue_returns_zero_total_and_no_pages(self) -> None:
        # No alerts at all → total=0, pages=0, items=[]. The
        # frontend uses ``pages > 0`` to decide whether to render the
        # paginator.
        db = self._setup_db(mine_count=0, unassigned_count=0, rows=[])

        resp = await build_queue(
            db,
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            owner="all",
        )

        assert resp.total == 0
        assert resp.pages == 0
        assert resp.items == []

    @pytest.mark.asyncio
    async def test_pages_math_rounds_up(self) -> None:
        # ceil(7 / 3) = 3 pages. Off-by-one here would either hide
        # the last page or show an empty trailing page.
        db = self._setup_db(mine_count=7, unassigned_count=0, rows=[])

        resp = await build_queue(
            db,
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            owner="me",
            page=1,
            page_size=3,
        )

        assert resp.pages == 3
        assert resp.page_size == 3

    @pytest.mark.asyncio
    async def test_page_size_clamped_to_max(self) -> None:
        # A misbehaving client passing ``page_size=1_000_000`` must
        # be clamped to ``QUEUE_MAX_PAGE_SIZE`` (200) so we don't
        # let them yank the whole tenant in one request.
        db = self._setup_db(mine_count=0, unassigned_count=0, rows=[])

        resp = await build_queue(
            db,
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            page_size=10_000,
        )

        assert resp.page_size == 200

    @pytest.mark.asyncio
    async def test_page_clamped_to_minimum_one(self) -> None:
        # ``page=0`` or negative pages must collapse to page 1.
        db = self._setup_db(mine_count=0, unassigned_count=0, rows=[])

        resp = await build_queue(
            db,
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            page=0,
        )

        assert resp.page == 1

    @pytest.mark.asyncio
    async def test_row_projection_fills_queue_item(self) -> None:
        # Single-row sanity check: the projection must carry every
        # field the frontend renders (severity, asset chip, action
        # chip, SLA countdown, age, bucket label).
        tenant_id = uuid.uuid4()
        user_id = uuid.uuid4()
        alert_id = uuid.uuid4()

        first_seen = datetime.now(UTC) - timedelta(minutes=10)
        sla_due = datetime.now(UTC) + timedelta(minutes=20)

        alert = _alert(
            alert_id=alert_id,
            tenant_id=tenant_id,
            severity="critical",
            title="Pod crashlooping",
            status="new",
            priority=80,
            assigned_to_id=user_id,
            affected_hosts=["k8s-node-3"],
            ai_recommendations=[{"action": "Drain node", "priority": 1, "risk": "high"}],
            first_seen=first_seen,
        )

        # bucket=0 (mine), sla_due in the future (not breached).
        db = self._setup_db(
            mine_count=1,
            unassigned_count=0,
            rows=[(alert, 0, sla_due)],
        )

        resp = await build_queue(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            owner="me",
        )

        assert len(resp.items) == 1
        item = resp.items[0]
        assert item.id == alert_id
        assert item.tenant_id == tenant_id
        assert item.title == "Pod crashlooping"
        assert item.severity == "critical"
        assert item.priority == 80
        assert item.bucket == "mine"
        assert item.sla_breached is False
        # Countdown is in the future, so > 0.
        assert item.sla_remaining_seconds > 0
        # Age is positive (first_seen was 10 minutes ago).
        assert item.age_seconds >= 0
        # Asset chip pulls host first.
        assert item.asset is not None
        assert item.asset.kind == "host"
        assert item.asset.value == "k8s-node-3"
        # Action chip carries the structured recommendation.
        assert item.suggested_action is not None
        assert item.suggested_action.action == "Drain node"
        assert item.suggested_action.risk == "high"

    @pytest.mark.asyncio
    async def test_breached_sla_flags_negative_remaining(self) -> None:
        # The frontend flips the timer red when ``sla_breached``
        # is true. We must report the boolean *and* a negative
        # countdown for downstream UI to match.
        tenant_id = uuid.uuid4()
        user_id = uuid.uuid4()
        alert = _alert(tenant_id=tenant_id)

        sla_due_past = datetime.now(UTC) - timedelta(minutes=5)

        db = self._setup_db(
            mine_count=1,
            unassigned_count=0,
            rows=[(alert, 0, sla_due_past)],
        )

        resp = await build_queue(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            owner="me",
        )

        item = resp.items[0]
        assert item.sla_breached is True
        assert item.sla_remaining_seconds < 0

    @pytest.mark.asyncio
    async def test_unassigned_bucket_label_is_unassigned(self) -> None:
        # bucket=1 maps to ``unassigned`` literal in the QueueItem.
        # If this regresses, the UI's bucket grouping silently swaps.
        tenant_id = uuid.uuid4()
        user_id = uuid.uuid4()
        alert = _alert(tenant_id=tenant_id, assigned_to_id=None)

        sla_due = datetime.now(UTC) + timedelta(minutes=20)
        db = self._setup_db(
            mine_count=0,
            unassigned_count=1,
            rows=[(alert, 1, sla_due)],
        )

        resp = await build_queue(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            owner="unassigned",
        )

        assert resp.items[0].bucket == "unassigned"

    @pytest.mark.asyncio
    async def test_naive_datetimes_are_treated_as_utc(self) -> None:
        # Postgres returns ``timestamptz`` rows as tz-aware datetimes
        # in production, but a SQLite-style stand-in (or some test
        # fixtures) may hand us naive datetimes. The projection must
        # coerce them to UTC instead of crashing the arithmetic.
        tenant_id = uuid.uuid4()
        user_id = uuid.uuid4()

        # Construct a naive datetime via UTC-now-stripped-tz so we are not
        # tripped up by the ``utcnow()`` deprecation while still exercising
        # the naive-coercion path that ``build_queue`` is meant to handle.
        naive_first_seen = datetime.now(UTC).replace(tzinfo=None)
        naive_sla_due = naive_first_seen + timedelta(minutes=10)
        alert = _alert(tenant_id=tenant_id, first_seen=naive_first_seen)

        db = self._setup_db(
            mine_count=1,
            unassigned_count=0,
            rows=[(alert, 0, naive_sla_due)],
        )

        resp = await build_queue(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            owner="me",
        )

        # No crash + the projection coerced both stamps to UTC so
        # they compare cleanly.
        item = resp.items[0]
        assert item.first_seen.tzinfo is not None
        assert item.sla_due_at.tzinfo is not None

    @pytest.mark.asyncio
    async def test_generated_at_is_utc(self) -> None:
        # The frontend uses ``generated_at`` for client-side clock
        # drift correction; it MUST be tz-aware UTC.
        db = self._setup_db(mine_count=0, unassigned_count=0, rows=[])

        resp = await build_queue(
            db,
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
        )

        assert resp.generated_at.tzinfo is not None
        assert resp.generated_at.utcoffset() == timedelta(0)

    @pytest.mark.asyncio
    async def test_queue_closed_statuses_constant_matches_contract(self) -> None:
        # Sanity check: any future status added to the alerts schema
        # that "exits" the queue must be added here, or the SLA
        # timer keeps ticking on resolved alerts.
        assert "resolved" in QUEUE_CLOSED_STATUSES
        assert "closed" in QUEUE_CLOSED_STATUSES
        # Both "false_positive" (new canonical) and "fp" (legacy)
        # must be honoured so a legacy disposition write doesn't
        # keep the alert visible in the queue.
        assert "false_positive" in QUEUE_CLOSED_STATUSES
        assert "fp" in QUEUE_CLOSED_STATUSES

    @pytest.mark.asyncio
    async def test_unassigned_severities_constant_matches_contract(self) -> None:
        # ``low``/``medium``/``info`` are deliberately NOT in the
        # unassigned bucket — they're triaged in bulk on /alerts.
        assert set(QUEUE_UNASSIGNED_SEVERITIES) == {"critical", "high"}


# ---------------------------------------------------------------------------
# claim_alert — atomic compare-and-set semantics
# ---------------------------------------------------------------------------


class TestClaimAlert:
    """All four documented branches of the claim path.

    Two analysts can race against the same row; the function does a
    SELECT, then an UPDATE guarded with ``WHERE assigned_to_id IS NULL``
    so only one update can win. A regression in any branch produces a
    bug visible in production (lost claims, false 409s, or silent
    cross-tenant claim grants).
    """

    @pytest.mark.asyncio
    async def test_claim_unassigned_succeeds(self) -> None:
        # Happy path. The SELECT returns an unassigned row, the
        # UPDATE returns ``user_id``, commit + refresh fire.
        tenant_id = uuid.uuid4()
        user_id = uuid.uuid4()
        alert_id = uuid.uuid4()
        alert = _alert(alert_id=alert_id, tenant_id=tenant_id, assigned_to_id=None)

        db = MagicMock()
        db.execute = AsyncMock(
            side_effect=[
                # SELECT lookup
                _scalar_one_or_none_result(alert),
                # UPDATE ... RETURNING assigned_to_id
                _scalar_one_or_none_result(user_id),
            ]
        )
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        result = await claim_alert(
            db,
            alert_id=alert_id,
            tenant_id=tenant_id,
            user_id=user_id,
        )

        assert result is alert
        db.commit.assert_awaited_once()
        db.refresh.assert_awaited_once_with(alert)

    @pytest.mark.asyncio
    async def test_claim_already_mine_is_idempotent(self) -> None:
        # If I refresh the queue and re-click claim, we MUST NOT
        # 409 — that would make the workbench feel broken. We
        # return the existing alert without issuing an UPDATE.
        tenant_id = uuid.uuid4()
        user_id = uuid.uuid4()
        alert_id = uuid.uuid4()
        alert = _alert(alert_id=alert_id, tenant_id=tenant_id, assigned_to_id=user_id)

        db = MagicMock()
        db.execute = AsyncMock(return_value=_scalar_one_or_none_result(alert))
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        result = await claim_alert(
            db,
            alert_id=alert_id,
            tenant_id=tenant_id,
            user_id=user_id,
        )

        assert result is alert
        # Only ONE execute call (the SELECT). No UPDATE issued.
        assert db.execute.await_count == 1
        # No commit/refresh either — nothing changed.
        db.commit.assert_not_awaited()
        db.refresh.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_claim_assigned_to_other_raises_409(self) -> None:
        # The classic conflict: another analyst already owns this
        # alert. We MUST surface the actual owner's ID so the UI
        # toast can render ``"already claimed by @bob"``.
        tenant_id = uuid.uuid4()
        my_id = uuid.uuid4()
        their_id = uuid.uuid4()
        alert_id = uuid.uuid4()
        alert = _alert(alert_id=alert_id, tenant_id=tenant_id, assigned_to_id=their_id)

        db = MagicMock()
        db.execute = AsyncMock(return_value=_scalar_one_or_none_result(alert))

        with pytest.raises(AlertAlreadyClaimedError) as exc_info:
            await claim_alert(
                db,
                alert_id=alert_id,
                tenant_id=tenant_id,
                user_id=my_id,
            )

        assert exc_info.value.alert_id == alert_id
        assert exc_info.value.owner_id == their_id

    @pytest.mark.asyncio
    async def test_claim_missing_alert_raises_not_found(self) -> None:
        # Wrong tenant, deleted alert, or typo in the URL → 404,
        # NOT 409. The endpoint maps NotFound → 404 and Conflict →
        # 409, so a regression here would silently swap the two.
        tenant_id = uuid.uuid4()
        user_id = uuid.uuid4()
        alert_id = uuid.uuid4()

        db = MagicMock()
        db.execute = AsyncMock(return_value=_scalar_one_or_none_result(None))

        with pytest.raises(AlertNotFoundError):
            await claim_alert(
                db,
                alert_id=alert_id,
                tenant_id=tenant_id,
                user_id=user_id,
            )

    @pytest.mark.asyncio
    async def test_claim_lost_race_falls_back_to_actual_owner(self) -> None:
        # Two analysts hit "Claim" at the same time:
        #   * Both SELECTs see ``assigned_to_id=NULL``.
        #   * The first UPDATE wins (returns winner_id).
        #   * The second UPDATE's guarded WHERE no longer matches
        #     so RETURNING is empty.
        # We must re-read to discover the *actual* owner and 409
        # with the right ID — telling the loser they collided with
        # themselves would be confusing.
        tenant_id = uuid.uuid4()
        my_id = uuid.uuid4()
        winner_id = uuid.uuid4()
        alert_id = uuid.uuid4()
        # SELECT shows the alert as unassigned (we lost the race
        # *after* this point).
        alert = _alert(alert_id=alert_id, tenant_id=tenant_id, assigned_to_id=None)

        db = MagicMock()
        db.execute = AsyncMock(
            side_effect=[
                _scalar_one_or_none_result(alert),  # SELECT
                _scalar_one_or_none_result(None),  # UPDATE RETURNING → empty (lost)
                _scalar_one_or_none_result(winner_id),  # re-read owner
            ]
        )

        with pytest.raises(AlertAlreadyClaimedError) as exc_info:
            await claim_alert(
                db,
                alert_id=alert_id,
                tenant_id=tenant_id,
                user_id=my_id,
            )

        assert exc_info.value.owner_id == winner_id

    @pytest.mark.asyncio
    async def test_claim_lost_race_with_no_owner_raises_not_found(self) -> None:
        # Pathological case: between our SELECT and UPDATE, the
        # alert was deleted (admin scrubbed it, or tenant teardown).
        # The re-read returns ``None`` and we surface 404 rather
        # than a confusing 409 with a missing owner.
        tenant_id = uuid.uuid4()
        my_id = uuid.uuid4()
        alert_id = uuid.uuid4()
        alert = _alert(alert_id=alert_id, tenant_id=tenant_id, assigned_to_id=None)

        db = MagicMock()
        db.execute = AsyncMock(
            side_effect=[
                _scalar_one_or_none_result(alert),
                _scalar_one_or_none_result(None),
                _scalar_one_or_none_result(None),  # re-read also returns None
            ]
        )

        with pytest.raises(AlertNotFoundError):
            await claim_alert(
                db,
                alert_id=alert_id,
                tenant_id=tenant_id,
                user_id=my_id,
            )

    @pytest.mark.asyncio
    async def test_claim_lost_race_where_we_actually_won(self) -> None:
        # Rare but real: the UPDATE returns no row (driver hiccup,
        # WHERE didn't trigger RETURNING), but the re-read shows
        # we own the alert anyway. Treat this as a successful claim
        # rather than 409-ing the legitimate owner.
        tenant_id = uuid.uuid4()
        my_id = uuid.uuid4()
        alert_id = uuid.uuid4()
        alert = _alert(alert_id=alert_id, tenant_id=tenant_id, assigned_to_id=None)

        db = MagicMock()
        db.execute = AsyncMock(
            side_effect=[
                _scalar_one_or_none_result(alert),
                _scalar_one_or_none_result(None),  # UPDATE returned nothing
                _scalar_one_or_none_result(my_id),  # but re-read shows we own it
            ]
        )
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        result = await claim_alert(
            db,
            alert_id=alert_id,
            tenant_id=tenant_id,
            user_id=my_id,
        )

        assert result is alert
        db.commit.assert_awaited_once()
        db.refresh.assert_awaited_once_with(alert)
