"""Attribute conditions narrow a permission; elevation is time-boxed.

Gap-closure wave 13. `cases:write` was true everywhere, always, from
any address, so the only way to let an analyst isolate a host once was
to give them that power every day.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.security.abac import (
    PrivilegeGrant,
    effective_permissions,
    evaluate_conditions,
)

NOW = datetime(2026, 3, 4, 14, 30, tzinfo=UTC)


class TestConditionsNarrow:
    def test_an_address_inside_the_range_is_allowed(self) -> None:
        result = evaluate_conditions(
            [{"operator": "ip_in_cidr", "value": ["198.51.100.0/24"]}],
            {"source_ip": "198.51.100.14"},
        )
        assert result.allowed

    def test_an_address_outside_it_is_denied_by_name(self) -> None:
        """A bare 403 on an attribute condition is indistinguishable
        from a missing role, and people debug the wrong thing."""
        result = evaluate_conditions(
            [{"operator": "ip_in_cidr", "value": ["198.51.100.0/24"]}],
            {"source_ip": "203.0.113.9"},
        )
        assert not result.allowed
        assert "203.0.113.9" in (result.denied_by or "")

    def test_a_window_crossing_midnight_works(self) -> None:
        """The normal case for a night shift, so it is handled rather
        than rejected."""
        night = [{"operator": "time_between_utc", "value": ["22:00", "06:00"]}]
        assert evaluate_conditions(night, {"now": NOW.replace(hour=23)}).allowed
        assert evaluate_conditions(night, {"now": NOW.replace(hour=3)}).allowed
        assert not evaluate_conditions(night, {"now": NOW.replace(hour=14)}).allowed

    def test_every_condition_must_hold(self) -> None:
        result = evaluate_conditions(
            [
                {"operator": "ip_in_cidr", "value": ["198.51.100.0/24"]},
                {"operator": "mfa_satisfied", "value": True},
            ],
            {"source_ip": "198.51.100.14", "mfa_satisfied": False},
        )
        assert not result.allowed


class TestTheFailClosedDecisions:
    def test_a_condition_with_no_data_denies_rather_than_passes(self) -> None:
        """Treating it as satisfied would mean a caller who omits a
        header is less constrained than one who sends it, which
        inverts the control."""
        result = evaluate_conditions(
            [{"operator": "ip_in_cidr", "value": ["198.51.100.0/24"]}],
            {},
        )
        assert not result.allowed
        assert "could not evaluate" in (result.denied_by or "")
        assert result.indeterminate

    def test_an_unknown_operator_denies(self) -> None:
        """A condition nobody can evaluate is not a condition that
        passes."""
        result = evaluate_conditions([{"operator": "vibes_acceptable", "value": True}], {})
        assert not result.allowed
        assert "unknown operator" in (result.denied_by or "")

    def test_indeterminate_can_be_made_permissive_deliberately(self) -> None:
        """Available, and not the default — so a deployment that wants
        it has to say so."""
        result = evaluate_conditions(
            [{"operator": "ip_in_cidr", "value": ["198.51.100.0/24"]}],
            {},
            deny_on_indeterminate=False,
        )
        assert result.allowed
        assert result.indeterminate

    def test_no_conditions_at_all_allows(self) -> None:
        """The negative control. Conditions narrow; an unconditioned
        permission must behave exactly as it did before."""
        assert evaluate_conditions([], {"source_ip": "203.0.113.9"}).allowed


class TestTimeBoxedElevation:
    def test_a_live_grant_adds_its_permissions(self) -> None:
        effective = effective_permissions(
            frozenset({"cases:read"}),
            [PrivilegeGrant(permissions=("actions:isolate",), expires_at=NOW + timedelta(minutes=30))],
            now=NOW,
        )
        assert "actions:isolate" in effective
        assert "cases:read" in effective

    def test_an_expired_grant_adds_nothing(self) -> None:
        """Checked at use rather than by a sweep: a background job that
        revokes grants is a job that can be down, and a grant
        outliving its window because a worker crashed is the failure
        JIT elevation exists to remove."""
        effective = effective_permissions(
            frozenset({"cases:read"}),
            [PrivilegeGrant(permissions=("actions:isolate",), expires_at=NOW - timedelta(seconds=1))],
            now=NOW,
        )
        assert "actions:isolate" not in effective

    def test_a_revoked_grant_adds_nothing_even_inside_its_window(self) -> None:
        effective = effective_permissions(
            frozenset(),
            [
                PrivilegeGrant(
                    permissions=("actions:isolate",),
                    expires_at=NOW + timedelta(hours=1),
                    revoked_at=NOW - timedelta(minutes=5),
                )
            ],
            now=NOW,
        )
        assert "actions:isolate" not in effective

    def test_elevation_never_removes_a_standing_permission(self) -> None:
        base = frozenset({"cases:read", "cases:write"})
        assert base.issubset(effective_permissions(base, [], now=NOW))
