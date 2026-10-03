"""Queues, SLA clocks and escalation.

Gap-closure wave 12. `sla_due_at` existed and nothing set it from a
policy; there were no queues; there was no escalation, so a case
nobody picked up stayed unpicked and the SLA passed in silence.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.services.case_orchestration import (
    CaseFacts,
    QueueRule,
    SlaPolicy,
    escalation_due,
    resolve_queue,
    sla_targets,
)

NOW = datetime(2026, 3, 4, 12, 0, tzinfo=UTC)


class TestQueueRoutingIsDeterministic:
    def test_precedence_decides_between_two_matching_queues(self) -> None:
        case = CaseFacts(severity="critical")
        queues = [
            QueueRule(id="b", name="catch-all", precedence=500),
            QueueRule(id="a", name="critical", precedence=10, match_severity=("critical",)),
        ]
        chosen = resolve_queue(case, queues)
        assert chosen is not None, "no queue matched a case that two queues declare"
        assert chosen.id == "a"

    def test_the_name_breaks_a_precedence_tie(self) -> None:
        """Not cosmetic. Without it two equally-ranked queues resolve
        by row order and a case appears to move between them."""
        case = CaseFacts(severity="high")
        queues = [
            QueueRule(id="z", name="zulu", precedence=100),
            QueueRule(id="a", name="alpha", precedence=100),
        ]
        forward = resolve_queue(case, queues)
        reverse = resolve_queue(case, list(reversed(queues)))
        assert forward is not None and reverse is not None
        assert forward.id == reverse.id == "a", "row order decided the queue"

    def test_criteria_are_anded_not_ored(self) -> None:
        """A queue declaring critical AND pci means critical PCI cases.
        Under OR it collects every critical case in the estate, which
        is how a team's queue becomes everyone's."""
        rule = QueueRule(id="q", name="pci-critical", match_severity=("critical",), match_tags=("pci",))
        assert rule.matches(CaseFacts(severity="critical", tags=("pci",)))
        assert not rule.matches(CaseFacts(severity="critical", tags=("corp",)))

    def test_a_case_matching_nothing_gets_no_queue(self) -> None:
        assert resolve_queue(CaseFacts(severity="low"), [QueueRule(id="q", name="q", match_severity=("critical",))]) is None


class TestThreeClocksNotOne:
    def test_each_target_is_set_from_the_policy(self) -> None:
        targets = sla_targets(
            CaseFacts(severity="high", opened_at=NOW),
            SlaPolicy(id="p", severity="high", ack_minutes=15, resolve_minutes=240, close_minutes=1440),
        )
        assert targets.ack_due_at == NOW + timedelta(minutes=15)
        assert targets.resolve_due_at == NOW + timedelta(minutes=240)
        assert targets.close_due_at == NOW + timedelta(minutes=1440)

    def test_they_are_measured_from_when_the_case_opened(self) -> None:
        """Not from now. Re-running this on an existing case must not
        silently extend its deadline, which would make every breach
        disappear on the next edit."""
        opened = NOW - timedelta(hours=6)
        targets = sla_targets(
            CaseFacts(severity="high", opened_at=opened),
            SlaPolicy(id="p", severity="high", resolve_minutes=240),
            now=NOW,
        )
        assert targets.resolve_due_at is not None, "no resolution target was set"
        assert targets.resolve_due_at < NOW, "the deadline moved when the case was re-read"

    def test_no_policy_gives_no_target_and_says_why(self) -> None:
        """An empty due date with no explanation reads as 'met' on
        every dashboard that counts breaches."""
        targets = sla_targets(CaseFacts(severity="high", opened_at=NOW), None)
        assert targets.resolve_due_at is None
        assert "no SLA policy" in (targets.reason or "")

    def test_a_mismatched_policy_is_refused_rather_than_applied(self) -> None:
        targets = sla_targets(
            CaseFacts(severity="critical", opened_at=NOW),
            SlaPolicy(id="p", severity="low", resolve_minutes=10_000),
        )
        assert targets.resolve_due_at is None
        assert "low" in (targets.reason or "")


class TestEscalation:
    def test_a_passed_acknowledgement_deadline_escalates(self) -> None:
        targets = sla_targets(
            CaseFacts(severity="critical", opened_at=NOW - timedelta(hours=2)),
            SlaPolicy(id="p", severity="critical", ack_minutes=15),
        )
        check = escalation_due(targets=targets, acknowledged=False, current_level=0, now=NOW)
        assert check.due
        assert check.level == 1
        assert "nobody on the case" in check.reason

    def test_an_acknowledged_case_does_not_escalate(self) -> None:
        """A case somebody is working on and has not finished is not
        the failure an escalation ladder addresses."""
        targets = sla_targets(
            CaseFacts(severity="critical", opened_at=NOW - timedelta(hours=2)),
            SlaPolicy(id="p", severity="critical", ack_minutes=15),
        )
        check = escalation_due(targets=targets, acknowledged=True, current_level=0, now=NOW)
        assert not check.due

    def test_a_case_inside_its_window_does_not_escalate(self) -> None:
        """The negative control. A check that escalated everything
        would satisfy the first test and page constantly."""
        targets = sla_targets(
            CaseFacts(severity="critical", opened_at=NOW),
            SlaPolicy(id="p", severity="critical", ack_minutes=60),
        )
        check = escalation_due(targets=targets, acknowledged=False, current_level=0, now=NOW)
        assert not check.due
        assert "remain" in check.reason

    def test_escalating_twice_climbs_the_ladder(self) -> None:
        """So an unanswered page progresses rather than repeats."""
        targets = sla_targets(
            CaseFacts(severity="critical", opened_at=NOW - timedelta(hours=4)),
            SlaPolicy(id="p", severity="critical", ack_minutes=15),
        )
        assert escalation_due(targets=targets, acknowledged=False, current_level=2, now=NOW).level == 3

    def test_no_deadline_means_no_escalation_and_a_stated_reason(self) -> None:
        targets = sla_targets(CaseFacts(severity="high", opened_at=NOW), None)
        check = escalation_due(targets=targets, acknowledged=False, current_level=0, now=NOW)
        assert not check.due
        assert check.reason
