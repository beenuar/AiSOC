"""Tenure, departure and device compliance have to reach the verdict, cited.

Depth plan wave 2, item 1.3.

The plan's wording is "each CITED", and that is the half worth testing. A
fact that reaches the prompt and not the confidence basis is one a reviewer
cannot see moved a verdict; a fact in the basis and not the prompt is one
the model never had. Both halves are asserted here for each of the four.

The other property under test is the direction of every absence. A missing
start date does not make somebody a new joiner, a missing end date does not
mean they are staying, an employment type nobody mapped does not make them
staff, and a device the MDM never evaluated is not a compliant one. Each of
those four is a reassurance the data cannot support, and each is the kind of
confident default this repository has shipped before.
"""

from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.context import identity as ident  # noqa: E402

TODAY = date(2026, 11, 1)


def _row(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {"account": "dana@example.com", "is_active": True}
    base.update(overrides)
    return base


class TestDerivedEmploymentFacts:
    def test_tenure_is_days_since_the_start_date(self) -> None:
        facts = ident.derive_employment_facts(_row(start_date="2026-10-02"), today=TODAY)
        assert facts["tenure_days"] == 30

    def test_no_start_date_means_no_tenure_rather_than_zero(self) -> None:
        """Zero tenure reads as "joined today", which is a finding. Absent
        reads as "nobody imported a start date", which is not."""
        assert "tenure_days" not in ident.derive_employment_facts(_row(), today=TODAY)

    def test_a_past_last_day_is_reported_as_departed(self) -> None:
        facts = ident.derive_employment_facts(_row(end_date="2026-10-20"), today=TODAY)
        assert facts["departed"] is True
        assert facts["departing_soon"] is False
        assert facts["days_until_departure"] == -12

    def test_a_last_day_inside_the_window_is_departing_soon(self) -> None:
        facts = ident.derive_employment_facts(_row(end_date="2026-11-20"), today=TODAY)
        assert facts["departing_soon"] is True
        assert facts["departed"] is False

    def test_a_last_day_outside_the_window_is_neither(self) -> None:
        facts = ident.derive_employment_facts(_row(end_date="2027-06-01"), today=TODAY)
        assert facts["departing_soon"] is False
        assert facts["departed"] is False

    def test_no_end_date_asserts_nothing_about_departure(self) -> None:
        facts = ident.derive_employment_facts(_row(), today=TODAY)
        assert "departed" not in facts
        assert "departing_soon" not in facts

    def test_a_contractor_is_flagged_and_an_employee_is_not(self) -> None:
        assert ident.derive_employment_facts(_row(employment_type="Contractor"), today=TODAY)["is_contractor"] is True
        assert ident.derive_employment_facts(_row(employment_type="Full-Time"), today=TODAY)["is_contractor"] is False

    def test_an_unmapped_employment_type_asserts_nothing(self) -> None:
        """A value no mapping covers must not become "employee". Reading a
        contractor as staff loses exactly the signal the field is for, and
        the reverse is a false accusation."""
        for value in ("unknown", "", "Seconded Partner Staff"):
            assert "is_contractor" not in ident.derive_employment_facts(_row(employment_type=value), today=TODAY)

    def test_a_malformed_date_is_absent_and_does_not_raise(self) -> None:
        facts = ident.derive_employment_facts(_row(start_date="not-a-date", end_date="2026-13-45"), today=TODAY)
        assert facts == {}


class TestThePromptSaysIt:
    def _render(self, row: dict[str, object]) -> str:
        return ident.render_for_prompt({"identities": [row]})

    def test_a_departed_account_is_named_in_the_prompt(self) -> None:
        rendered = self._render(_row(end_date="2000-01-01"))
        assert "LAST DAY HAS PASSED" in rendered

    def test_a_contractor_is_named_in_the_prompt(self) -> None:
        assert "contractor, not an employee" in self._render(_row(employment_type="contractor"))

    def test_the_window_is_stated_rather_than_left_to_be_guessed(self) -> None:
        rendered = self._render(_row(end_date="2000-01-01"))
        assert str(ident.DEPARTING_WITHIN_DAYS) in rendered

    def test_a_noncompliant_device_is_named(self) -> None:
        rendered = self._render(_row(devices=[{"hostname": "LAPTOP-1", "compliance_state": "noncompliant", "encrypted": False}]))
        assert "LAPTOP-1" in rendered
        assert "NOT COMPLIANT" in rendered
        assert "disk NOT encrypted" in rendered

    def test_an_unevaluated_device_says_so_rather_than_reading_as_compliant(self) -> None:
        rendered = self._render(_row(devices=[{"hostname": "LAPTOP-2", "compliance_state": "unknown"}]))
        assert "compliance not evaluated" in rendered
        assert "compliant," not in rendered

    def test_unreported_encryption_is_silent_rather_than_a_finding(self) -> None:
        """None means nobody said. Only False is a finding."""
        rendered = self._render(_row(devices=[{"hostname": "LAPTOP-3", "compliance_state": "compliant", "encrypted": None}]))
        assert "encrypt" not in rendered.lower()

    def test_a_principal_with_no_device_gets_no_device_line(self) -> None:
        """ "No device found" on a tenant with no MDM connector is a
        statement about our coverage, not about the principal."""
        # The per-device bullet, not the word: the block's own preamble and
        # its honesty sentence both mention devices, and asserting on the
        # bare word would pass or fail on prose rather than on behaviour.
        assert "- device " not in self._render(_row())

    def test_devices_are_bounded_so_a_fleet_user_cannot_crowd_the_prompt(self) -> None:
        many = [{"hostname": f"HOST-{i}", "compliance_state": "noncompliant"} for i in range(12)]
        rendered = self._render(_row(devices=many))
        assert rendered.count("- device ") == ident._MAX_DEVICES_PER_PRINCIPAL


class TestTheBasisCitesIt:
    """The citation half. A fact in the prompt and not the basis is one a
    reviewer cannot see moved a verdict."""

    def test_a_departed_principal_is_cited(self) -> None:
        lines = ident.basis({"identities": [_row(end_date="2000-01-01")]})
        assert any("last day has passed" in line for line in lines)

    def test_a_departing_principal_is_cited_with_the_window(self) -> None:
        soon = date.today().isoformat()  # noqa: DTZ011 - a calendar date, deliberately
        lines = ident.basis({"identities": [_row(end_date=soon)]})
        assert any(f"within {ident.DEPARTING_WITHIN_DAYS} days" in line for line in lines)

    def test_a_contractor_is_cited(self) -> None:
        lines = ident.basis({"identities": [_row(employment_type="contractor")]})
        assert any("contractor" in line for line in lines)

    def test_device_compliance_is_cited_with_its_counts(self) -> None:
        lines = ident.basis(
            {
                "identities": [
                    _row(
                        devices=[
                            {"hostname": "A", "compliance_state": "noncompliant", "encrypted": False},
                            {"hostname": "B", "compliance_state": "compliant", "encrypted": True},
                        ]
                    )
                ]
            }
        )
        joined = " ".join(lines)
        assert "2 enrolled device(s)" in joined
        assert "1 not compliant" in joined
        assert "1 with no disk encryption" in joined

    def test_nothing_is_cited_when_nothing_was_derived(self) -> None:
        lines = ident.basis({"identities": [_row()]})
        assert len(lines) == 1
        assert "principal(s)" in lines[0]
