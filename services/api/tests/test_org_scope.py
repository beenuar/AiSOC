"""Scope resolution and limit arithmetic, without a database.

The live-Postgres proof that a portfolio aggregate cannot see outside its
portfolio is in `test_mssp_portfolio_isolation.py`. This file covers the
decisions that happen before any SQL runs, and the one structural property
that keeps the aggregate layer honest as it grows: a cross-tenant query
function must route its tenant list through `require_scope`, so adding a new
aggregate without scoping fails here rather than in production.
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pytest
from app.services import entitlements, mssp_portfolio
from app.services.org_scope import (
    EMPTY_SCOPE,
    PortfolioScope,
    PortfolioScopeError,
    narrow,
    require_scope,
)

A = uuid.UUID("11111111-1111-1111-1111-11111111000a")
B = uuid.UUID("11111111-1111-1111-1111-11111111000b")
OUTSIDE = uuid.UUID("99999999-9999-9999-9999-999999990000")

ORG = uuid.UUID("22222222-2222-2222-2222-222222222222")


def _scope(role: str = "admin", tenants: set[uuid.UUID] | None = None) -> PortfolioScope:
    return PortfolioScope(
        org_id=ORG,
        org_slug="provider",
        org_name="Provider",
        org_role=role,
        tenant_ids=frozenset(tenants if tenants is not None else {A, B}),
        portfolio_wide=role in {"owner", "admin"},
    )


# ---------------------------------------------------------------------------
# An absent scope must never behave like an unrestricted one
# ---------------------------------------------------------------------------


def test_require_scope_refuses_an_empty_portfolio() -> None:
    """The single most important assertion in the tenancy surface.

    Every cross-tenant leak in this codebase has had the same shape: a scope
    that was absent rather than narrow, and a query that read absent as "no
    filter". `require_scope` makes that combination raise.
    """
    with pytest.raises(PortfolioScopeError):
        require_scope(EMPTY_SCOPE)

    with pytest.raises(PortfolioScopeError):
        require_scope(_scope(tenants=set()))


def test_require_scope_returns_a_deterministic_list() -> None:
    assert require_scope(_scope()) == sorted({A, B})


def test_non_member_is_not_silently_treated_as_an_operator() -> None:
    assert EMPTY_SCOPE.is_member is False
    assert EMPTY_SCOPE.can_act is False
    assert EMPTY_SCOPE.can_administer is False
    assert EMPTY_SCOPE.tenant_ids == frozenset()


# ---------------------------------------------------------------------------
# A filter parameter must not become a selector for someone else's data
# ---------------------------------------------------------------------------


def test_narrow_cannot_reach_outside_the_portfolio() -> None:
    narrowed = narrow(_scope(), [OUTSIDE])
    assert narrowed.tenant_ids == frozenset()
    assert not narrowed.covers(OUTSIDE)


def test_narrow_keeps_only_the_intersection() -> None:
    narrowed = narrow(_scope(), [A, OUTSIDE])
    assert narrowed.tenant_ids == frozenset({A})


def test_narrow_preserves_identity_but_not_breadth() -> None:
    narrowed = narrow(_scope("owner"), [A])
    assert narrowed.org_id == ORG
    assert narrowed.org_role == "owner"
    # No longer the whole portfolio, and the payload should not claim it is.
    assert narrowed.portfolio_wide is False


# ---------------------------------------------------------------------------
# Authority
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "can_act", "can_administer"),
    [
        ("owner", True, True),
        ("admin", True, True),
        ("operator", True, False),
        ("viewer", False, False),
    ],
)
def test_role_authority(role: str, can_act: bool, can_administer: bool) -> None:
    scope = _scope(role)
    assert scope.can_act is can_act
    assert scope.can_administer is can_administer


# ---------------------------------------------------------------------------
# The structural gate: a new aggregate cannot forget to scope itself
# ---------------------------------------------------------------------------


def test_every_cross_tenant_query_routes_through_require_scope() -> None:
    """Any function here taking a `scope` must call `require_scope(scope)`.

    Reviewing for a missing `WHERE tenant_id` is exactly the check humans
    are worst at and that this codebase has failed several times. Reading
    `scope.tenant_ids` directly is not enough: it would produce
    `ANY('{}')` on an empty portfolio, which a later refactor could drop
    without anybody noticing the day it stopped filtering.
    """
    source = Path(mssp_portfolio.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    unscoped: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
            continue
        takes_scope = any(arg.arg == "scope" for arg in [*node.args.args, *node.args.kwonlyargs])
        if not takes_scope:
            continue
        calls = {child.func.id for child in ast.walk(node) if isinstance(child, ast.Call) and isinstance(child.func, ast.Name)}
        if "require_scope" not in calls:
            unscoped.append(node.name)

    assert not unscoped, f"cross-tenant function(s) that never call require_scope: {unscoped}"


def test_empty_summary_matches_the_computed_summary_shape() -> None:
    """A portfolio with no tenants must answer in the same shape as one with.

    Otherwise the empty case needs its own branch in every consumer, and the
    branch nobody exercises is the one that renders a blank card instead of
    a zero.
    """
    assert set(mssp_portfolio.EMPTY_SUMMARY) == set(mssp_portfolio.summarise([]))


# ---------------------------------------------------------------------------
# Limits: uncapped must read as uncapped, not as zero
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw", [-1, "-1", "unlimited", "UNLIMITED", "none", "", None, "not-a-number"])
def test_values_meaning_no_ceiling(raw: object) -> None:
    assert entitlements.limit_for({"connectors": raw}, "connectors") is None


def test_per_tenant_override_wins_over_the_deployment_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(entitlements, "_deployment_defaults", lambda: {"connectors": 5})
    assert entitlements.limit_for({}, "connectors") == 5
    # Raising as well as lowering: sizing one customer differently is the
    # whole reason the override exists.
    assert entitlements.limit_for({"connectors": 50}, "connectors") == 50
    assert entitlements.limit_for({"connectors": "unlimited"}, "connectors") is None


def test_unconfigured_key_is_uncapped_not_invented() -> None:
    """No plan, no ceiling.

    An open-source install has no billing tier, so drawing a headroom bar
    against an invented cap would put a fabricated number on every tenant
    row in the portfolio view.
    """
    assert entitlements.limit_for({}, "connectors") is None
    assert entitlements.limit_for(None, "seats") is None


@pytest.mark.parametrize(
    ("used", "limit", "expected"),
    [
        (0, None, "unlimited"),
        (10_000, None, "unlimited"),
        (0, 10, "ok"),
        (7, 10, "ok"),
        (8, 10, "warning"),
        (10, 10, "exhausted"),
        (11, 10, "exhausted"),
        (0, 0, "exhausted"),
    ],
)
def test_limit_states(used: int, limit: int | None, expected: str) -> None:
    assert entitlements.classify(used, limit) == expected


def test_uncapped_headroom_reports_none_not_a_plottable_zero() -> None:
    row = entitlements.Headroom(key="seats", label="Seats", used=3, limit=None, state="unlimited")
    assert row.remaining is None
    assert row.pct_used is None
    assert row.as_dict()["limit"] is None


def test_exhausted_headroom_never_reports_negative_remaining() -> None:
    row = entitlements.Headroom(key="seats", label="Seats", used=12, limit=10, state="exhausted")
    assert row.remaining == 0
    assert row.pct_used == 100.0


def test_every_usage_query_binds_the_tenant() -> None:
    """Usage counts are per tenant; the tenant is bound, never formatted in."""
    for key in entitlements.LIMIT_KEYS:
        assert ":tenant_id" in key.usage_sql, key.name
        assert "tenant_id = :tenant_id" in key.usage_sql, key.name
