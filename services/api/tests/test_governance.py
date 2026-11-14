"""Legal hold beats retention; hidden fields are named; residency fails closed.

Gap-closure wave 14. The retention worker could purge and nothing
could stop it, so the answer to "preserve everything relating to this
account pending litigation" was to disable retention for the whole
tenant and remember to turn it back on.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.services.governance import (
    FieldRule,
    LegalHold,
    apply_field_access,
    residency_decision,
    retention_decision,
)

HOLD = LegalHold(id="h1", subject_kind="user", subject_value="svc-backup", matter_ref="MAT-2026-01")


class TestLegalHoldOutranksRetention:
    def test_an_expired_record_under_hold_is_not_purged(self) -> None:
        """The one outcome that cannot be apologised for."""
        decision = retention_decision(expired=True, subjects={"user": "svc-backup"}, holds=[HOLD])
        assert not decision.may_purge
        assert decision.held_by is HOLD
        assert "MAT-2026-01" in decision.reason

    def test_an_expired_record_under_no_hold_is_purged(self) -> None:
        """The negative control. A check that refused everything would
        satisfy the test above and break retention entirely."""
        decision = retention_decision(expired=True, subjects={"user": "someone-else"}, holds=[HOLD])
        assert decision.may_purge

    def test_the_hold_is_carried_not_flattened_to_a_boolean(self) -> None:
        """So a caller cannot treat 'held' as 'not expired' and move
        on without recording why."""
        decision = retention_decision(expired=True, subjects={"user": "svc-backup"}, holds=[HOLD])
        assert decision.held_by is not None

    def test_matching_is_case_insensitive(self) -> None:
        """`SVC-Backup` and `svc-backup` are one account, and a hold
        that missed one spelling would preserve half the evidence."""
        decision = retention_decision(expired=True, subjects={"user": "SVC-Backup"}, holds=[HOLD])
        assert not decision.may_purge

    def test_a_released_hold_no_longer_blocks(self) -> None:
        released = LegalHold(id="h2", subject_kind="user", subject_value="svc-backup", released_at=datetime.now(UTC))
        assert retention_decision(expired=True, subjects={"user": "svc-backup"}, holds=[released]).may_purge

    def test_an_unexpired_record_is_not_purged_either(self) -> None:
        decision = retention_decision(expired=False, subjects={}, holds=[])
        assert not decision.may_purge
        assert "has not elapsed" in decision.reason


class TestFieldAccess:
    def test_a_withheld_field_is_named(self) -> None:
        """A hidden field and an absent one look identical to a client,
        and they lead to opposite next steps."""
        result = apply_field_access(
            {"title": "x", "src_ip": "198.51.100.5"},
            [FieldRule(field_path="src_ip", visible_to_roles=("admin",))],
            role="viewer",
        )
        assert result.record["src_ip"] == "[redacted]"
        assert result.withheld == ["src_ip"]

    def test_a_permitted_role_sees_it_in_full(self) -> None:
        result = apply_field_access(
            {"src_ip": "198.51.100.5"},
            [FieldRule(field_path="src_ip", visible_to_roles=("admin",))],
            role="admin",
        )
        assert result.record["src_ip"] == "198.51.100.5"
        assert result.withheld == []

    def test_dotted_paths_reach_into_the_raw_event(self) -> None:
        """Where a source puts whatever it likes, and the field most
        worth constraining."""
        result = apply_field_access(
            {"raw_event": {"user": {"email": "a@example.com"}}},
            [FieldRule(field_path="raw_event.user.email", visible_to_roles=())],
            role="viewer",
        )
        assert result.record["raw_event"]["user"]["email"] == "[redacted]"

    def test_hashing_is_stable_so_values_stay_correlatable(self) -> None:
        rule = [FieldRule(field_path="user", visible_to_roles=(), treatment="hash")]
        one = apply_field_access({"user": "alice"}, rule, role="viewer").record["user"]
        two = apply_field_access({"user": "alice"}, rule, role="viewer").record["user"]
        three = apply_field_access({"user": "bob"}, rule, role="viewer").record["user"]
        assert one == two and one != three

    def test_masking_keeps_the_tail(self) -> None:
        result = apply_field_access(
            {"card": "4111111111111234"},
            [FieldRule(field_path="card", visible_to_roles=(), treatment="mask")],
            role="viewer",
        )
        assert result.record["card"].endswith("1234")

    def test_a_rule_for_an_absent_field_is_not_reported_as_withheld(self) -> None:
        """Otherwise the response claims to be hiding something it
        never had."""
        result = apply_field_access(
            {"title": "x"},
            [FieldRule(field_path="src_ip", visible_to_roles=())],
            role="viewer",
        )
        assert result.withheld == []

    def test_the_input_record_is_not_mutated(self) -> None:
        original = {"raw_event": {"user": "alice"}}
        apply_field_access(original, [FieldRule(field_path="raw_event.user", visible_to_roles=())], role="viewer")
        assert original["raw_event"]["user"] == "alice"


class TestResidencyFailsClosed:
    def test_a_cross_region_operation_is_refused_and_recorded(self) -> None:
        decision = residency_decision(tenant_region="eu-west-1", target_region="us-east-1", enforced=True, operation="export")
        assert not decision.allowed
        assert decision.record_violation

    def test_enforcement_with_no_declared_region_refuses(self) -> None:
        """Permitting everything under a setting an operator believes
        is strict is the worse reading."""
        decision = residency_decision(tenant_region=None, target_region="eu-west-1", enforced=True, operation="export")
        assert not decision.allowed

    def test_an_operation_declaring_no_region_refuses(self) -> None:
        decision = residency_decision(tenant_region="eu-west-1", target_region=None, enforced=True, operation="export")
        assert not decision.allowed

    def test_same_region_is_allowed(self) -> None:
        """The negative control: enforcement must not block ordinary
        in-region work."""
        decision = residency_decision(tenant_region="eu-west-1", target_region="eu-west-1", enforced=True, operation="export")
        assert decision.allowed

    def test_unenforced_tenants_are_unaffected(self) -> None:
        """Off by default: turning it on for a tenant whose data
        already spans regions would break it silently."""
        decision = residency_decision(tenant_region="eu-west-1", target_region="us-east-1", enforced=False, operation="export")
        assert decision.allowed
