"""Fields the engine can compute, and the ones it must refuse to guess.

138 of 833 executable rules matched on fields no connector emits. Most need
something that does not exist — a windowed evaluator, identity enrichment,
per-tenant allowlists. A handful needed nothing: both values were already
in the event and nothing was comparing them.

The rule that governs this module, and most of what is tested below: **an
underivable field is absent, not false.** Defaulting a missing comparison to
`False` would make every event with incomplete data satisfy
`actor_eq_target: false` — a cross-account-access detection that fires on
ignorance, on every tenant, forever.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from app.services.derived_fields import (
    comparison_fields,
    enrich,
    requested_derived_fields,
    time_of_day_fields,
)


class TestComparisons:
    def test_equal_fields_compare_equal(self) -> None:
        event = {"actor": "alice", "target": "alice"}
        assert comparison_fields(event, {"actor_eq_target"}) == {"actor_eq_target": True}

    def test_neq_is_the_inverse(self) -> None:
        event = {"actor_uid": "1000", "owner_uid": "0"}
        result = comparison_fields(event, {"actor_uid_neq_owner_uid"})
        assert result == {"actor_uid_neq_owner_uid": True}

    def test_a_missing_operand_yields_no_key_rather_than_false(self) -> None:
        """The failure that would fire on every incomplete event."""
        event = {"actor": "alice"}
        assert comparison_fields(event, {"actor_eq_target"}) == {}

    def test_both_operands_missing_yields_no_key(self) -> None:
        assert comparison_fields({}, {"actor_eq_target"}) == {}

    def test_case_differences_are_the_same_principal(self) -> None:
        """`Alice` and `alice` are one account in every directory we read;
        saying otherwise produces a finding for a casing difference."""
        event = {"actor": "Alice", "target": "alice "}
        assert comparison_fields(event, {"actor_eq_target"})["actor_eq_target"] is True

    def test_splits_at_the_first_separator(self) -> None:
        """`actor_uid_neq_owner_uid` is (actor_uid, owner_uid), not
        (actor, uid_neq_owner_uid)."""
        event = {"actor_uid": "1", "owner_uid": "1"}
        assert comparison_fields(event, {"actor_uid_neq_owner_uid"}) == {"actor_uid_neq_owner_uid": False}

    def test_only_requested_fields_are_computed(self) -> None:
        """Enumerating every pair of event keys is quadratic and produces
        thousands of keys nothing reads."""
        event = {"a": 1, "b": 1, "c": 1}
        assert comparison_fields(event, {"a_eq_b"}) == {"a_eq_b": True}

    def test_no_request_means_no_work(self) -> None:
        assert comparison_fields({"a": 1, "b": 1}, None) == {}

    def test_a_name_that_is_not_a_comparison_is_ignored(self) -> None:
        assert comparison_fields({"user_name": "x"}, {"user_name"}) == {}

    @pytest.mark.parametrize(
        ("left", "right", "equal"),
        [(0, 0, True), (0, False, True), (1, "1", False), (None, None, None)],
    )
    def test_non_string_operands(self, left: object, right: object, equal: object) -> None:
        event = {}
        if left is not None:
            event["a"] = left
        if right is not None:
            event["b"] = right
        result = comparison_fields(event, {"a_eq_b"})
        if equal is None:
            assert result == {}
        else:
            assert result["a_eq_b"] is equal


class TestTimeOfDay:
    def test_a_weekday_afternoon_is_business_hours(self) -> None:
        # 2026-09-22 is a Tuesday.
        result = time_of_day_fields({"event_time": datetime(2026, 9, 22, 14, 0)})
        assert result["is_business_hours"] is True
        assert result["is_after_hours"] is False
        assert result["is_weekend"] is False

    def test_a_weekday_night_is_not(self) -> None:
        result = time_of_day_fields({"event_time": datetime(2026, 9, 22, 3, 0)})
        assert result["is_business_hours"] is False
        assert result["is_after_hours"] is True

    def test_a_saturday_afternoon_is_not_business_hours(self) -> None:
        # 2026-09-26 is a Saturday.
        result = time_of_day_fields({"event_time": datetime(2026, 9, 26, 14, 0)})
        assert result["is_weekend"] is True
        assert result["is_business_hours"] is False

    def test_no_timestamp_yields_nothing(self) -> None:
        """An unknown time is not "outside business hours"."""
        assert time_of_day_fields({"user_name": "alice"}) == {}

    def test_an_unparseable_timestamp_yields_nothing(self) -> None:
        assert time_of_day_fields({"event_time": "not a date"}) == {}

    def test_event_time_wins_over_ingest_time(self) -> None:
        """Using ingest time would make a batch import at 03:00 look like a
        night-time attack."""
        result = time_of_day_fields(
            {
                "event_time": datetime(2026, 9, 22, 14, 0),
                "ingest_time": datetime(2026, 9, 22, 3, 0),
            }
        )
        assert result["is_business_hours"] is True

    def test_iso_strings_parse(self) -> None:
        result = time_of_day_fields({"event_time": "2026-09-22T14:00:00Z"})
        assert result["is_business_hours"] is True

    def test_epoch_milliseconds_parse(self) -> None:
        ms = int(datetime(2026, 9, 22, 14, 0).timestamp() * 1000)
        assert time_of_day_fields({"event_time": ms})["is_business_hours"] is True

    def test_business_hours_are_configurable(self) -> None:
        """ "Outside business hours" means nothing without knowing whose
        business; a hardcoded window fires all night for half the world."""
        event = {"event_time": datetime(2026, 9, 22, 20, 0)}
        assert time_of_day_fields(event)["is_business_hours"] is False
        assert time_of_day_fields(event, business_start=9, business_end=23)["is_business_hours"] is True


class TestEnrich:
    def test_a_vendor_value_is_never_overwritten(self) -> None:
        """A vendor's own answer about its own tenant's hours beats ours."""
        event = {"event_time": datetime(2026, 9, 22, 3, 0), "is_business_hours": True}
        assert enrich(event)["is_business_hours"] is True

    def test_returns_the_event_unchanged_when_nothing_is_derivable(self) -> None:
        event = {"user_name": "alice"}
        assert enrich(event) is event

    def test_combines_both_families(self) -> None:
        event = {
            "event_time": datetime(2026, 9, 22, 3, 0),
            "actor": "alice",
            "target": "bob",
        }
        result = enrich(event, {"actor_eq_target"})
        assert result["is_after_hours"] is True
        assert result["actor_eq_target"] is False
        assert result["actor"] == "alice"


class TestRequestedFields:
    def test_collects_comparison_and_time_fields(self) -> None:
        rules = [
            {"match_when": {"actor_eq_target": False, "event_name": "CreateAccessKey"}},
            {"match_when": {"is_business_hours": False}},
        ]
        assert requested_derived_fields(rules) == {"actor_eq_target", "is_business_hours"}

    def test_walks_nested_clauses(self) -> None:
        rules = [{"match_when": {"any_of": [{"actor_eq_target": True}, {"x": 1}]}}]
        assert "actor_eq_target" in requested_derived_fields(rules)

    def test_strips_operator_suffixes(self) -> None:
        """Rules write `is_business_hours: false` bare, but a clause can
        carry an operator and the field name still has to be recovered."""
        rules = [{"match_when": {"is_business_hours_in": [False]}}]
        assert "is_business_hours" in requested_derived_fields(rules)

    def test_ordinary_fields_are_not_collected(self) -> None:
        rules = [{"match_when": {"user_name": "alice", "process_name_contains": "x"}}]
        assert requested_derived_fields(rules) == set()


class TestNeqOperator:
    """`neq` is used by rules in the shipped corpus and never existed in the
    matcher, so `approver_role_neq: "codeowner"` was read as a field
    literally named `approver_role_neq` — which nothing emits."""

    def test_neq_matches_a_different_value(self) -> None:
        from app.services.detection_matcher import matches

        assert matches({"approver_role_neq": "codeowner"}, {"approver_role": "dev"})

    def test_neq_does_not_match_an_equal_value(self) -> None:
        from app.services.detection_matcher import matches

        assert not matches({"approver_role_neq": "codeowner"}, {"approver_role": "codeowner"})

    def test_neq_does_not_fire_on_a_missing_field(self) -> None:
        """Otherwise every neq rule fires on every event lacking the field —
        a detection that fires on absence of data."""
        from app.services.detection_matcher import matches

        assert not matches({"approver_role_neq": "codeowner"}, {"user_name": "alice"})

    def test_the_operator_split_does_not_capture_comparison_names(self) -> None:
        """`actor_uid_neq_owner_uid` is a derived field, not `actor_uid`
        with a neq operator. Adding the operator must not break it."""
        from app.services.detection_matcher import _split_op

        assert _split_op("actor_uid_neq_owner_uid") == ("actor_uid_neq_owner_uid", "eq")
        assert _split_op("actor_uid_neq") == ("actor_uid", "neq")
