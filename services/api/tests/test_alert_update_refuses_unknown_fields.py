"""``PATCH /alerts/{id}`` refuses a field it cannot apply (issue #1280).

``AlertUpdateRequest`` set no ``extra=``, so pydantic v2's default
``extra="ignore"`` applied and every key outside the declared five was
dropped before the handler ran. The response was a 200 carrying the
unchanged row, which is indistinguishable from a successful write.

The fields that reach this endpoint are not nonsense — ``disposition``,
``severity``, ``confidence`` and ``snoozed_until`` are all real ``Alert``
columns, three of them writable through a different route. That is what
made the silent drop expensive: a caller closing an alert with a
disposition got a 200 and no disposition, and nothing in the response
distinguished "applied" from "ignored".
"""

from __future__ import annotations

import uuid

import pytest
from app.api.v1.endpoints.alerts import AlertUpdateRequest
from pydantic import ValidationError


def _message(exc: ValidationError) -> str:
    return str(exc)


class TestAnUnapplicableFieldIsRefused:
    def test_the_reported_payload_is_refused_rather_than_half_applied(self) -> None:
        """The exact body from the report: status lands, disposition does not."""
        with pytest.raises(ValidationError) as caught:
            AlertUpdateRequest(status="resolved", disposition="false_positive")

        assert "disposition" in _message(caught.value)

    @pytest.mark.parametrize(
        "field",
        ["disposition", "severity", "confidence", "resolution", "snoozed_until"],
    )
    def test_every_silently_dropped_field_is_refused(self, field: str) -> None:
        """The report named one; the drop list was wider than one."""
        with pytest.raises(ValidationError) as caught:
            AlertUpdateRequest(**{field: "x"})

        assert field in _message(caught.value)

    def test_a_typo_in_a_real_field_is_refused_rather_than_ignored(self) -> None:
        """`statuss` used to be a 200 that changed nothing."""
        with pytest.raises(ValidationError):
            AlertUpdateRequest(statuss="resolved")


class TestTheRefusalNamesSomewhereToGo:
    """A 422 that only says "not permitted" tells an operator their call
    was wrong without telling them what is right, and three of these
    fields have a route that does apply them."""

    @pytest.mark.parametrize(
        ("field", "route"),
        [
            ("disposition", "/feedback/alert-override"),
            ("severity", "/escalate"),
            ("snoozed_until", "/snooze"),
        ],
    )
    def test_a_field_with_a_home_elsewhere_names_that_route(self, field: str, route: str) -> None:
        with pytest.raises(ValidationError) as caught:
            AlertUpdateRequest(**{field: "x"})

        assert route in _message(caught.value)

    def test_a_field_with_no_home_lists_what_is_accepted(self) -> None:
        """No route is invented for a field that has none."""
        with pytest.raises(ValidationError) as caught:
            AlertUpdateRequest(nonsense=1)

        message = _message(caught.value)
        assert "status" in message
        assert "assignee" in message


class TestTheAcceptedSurfaceIsUnchanged:
    """`extra="forbid"` is a behaviour change on a published endpoint, so
    the controls matter as much as the refusal. Every shape the console
    and the SDK already send must still be accepted."""

    def test_the_five_declared_fields_are_accepted(self) -> None:
        parsed = AlertUpdateRequest(
            status="triaged",
            priority=80,
            tags=["a"],
            assigned_to_id=None,
            case_id=None,
        )
        assert parsed.status == "triaged"
        assert parsed.priority == 80

    def test_the_assignee_alias_is_not_extra(self) -> None:
        """A declared alias is not an unknown field. The queue releases an
        alert with `{"assignee": null}` and that must keep working."""
        parsed = AlertUpdateRequest(assignee=None)
        assert "assigned_to_id" in parsed.model_fields_set

    def test_assigning_by_alias_still_binds_the_value(self) -> None:
        who = uuid.uuid4()
        assert AlertUpdateRequest(assignee=who).assigned_to_id == who

    def test_the_canonical_field_name_still_works(self) -> None:
        who = uuid.uuid4()
        assert AlertUpdateRequest(assigned_to_id=who).assigned_to_id == who

    def test_an_empty_body_is_still_a_no_op_rather_than_an_error(self) -> None:
        assert AlertUpdateRequest().model_fields_set == set()
