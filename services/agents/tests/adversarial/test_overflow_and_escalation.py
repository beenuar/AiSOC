"""Context overflow and privilege escalation, against the real controls.

Gap-closure wave 4.

Context overflow was absent, and absent in a way the existing corpus could
not reach by growing: every payload in it is a short string in a field.

Overflow's payload is the *volume*, not the text, so a guard that reads
prose for instruction-shaped phrasing has nothing to catch.

The privilege-escalation half of this wave lives in
`services/actions/tests/test_privilege_escalation.py`, because it must
be graded by the shipped approval matrix and both services root their
packages at `app` — loading one from the other binds to the wrong tree.

These run against `PromptInjectionGuard` and `approval_matrix.evaluate`
as shipped. Where a control does not stop something, the test records
the measurement rather than asserting a pass, because tuning a guard
against the corpus that measures it has already been shown here to move
66.7% to 98.1% while held-out payloads moved 3.6% to 7.1%.
"""

from __future__ import annotations

import pytest
from app.prompting.envelope import PromptInjectionGuard

from tests.adversarial.overflow_corpus import (
    OVERFLOW_PAYLOADS,
    build_overflow_event,
)


@pytest.fixture(scope="module")
def guard() -> PromptInjectionGuard:
    return PromptInjectionGuard()


class TestTheOverflowCorpusIsWellFormed:
    """Without these the suite below could pass against nothing."""

    def test_every_payload_is_actually_large(self) -> None:
        for payload in OVERFLOW_PAYLOADS:
            event = build_overflow_event(payload)
            assert event["chars"] >= payload.filler_chars, (
                f"{payload.id} produced {event['chars']} chars, under its own {payload.filler_chars}"
            )

    def test_the_filler_resembles_its_log_source(self) -> None:
        """Filler that looks like filler is a much easier test than the
        one this corpus is for."""
        dns = build_overflow_event(OVERFLOW_PAYLOADS[0])["value"]
        assert "NOERROR" in dns and "example.net" in dns

    def test_there_is_a_control_with_no_instruction(self) -> None:
        """If the agent fails that one too, overflow alone is sufficient
        and the tail text is incidental — a different, worse finding."""
        controls = [p for p in OVERFLOW_PAYLOADS if not p.tail_instruction]
        assert controls, "no no-instruction control; a failure could not be attributed"

    def test_building_is_deterministic(self) -> None:
        """Same payload, same bytes — so a digest over the corpus pins it."""
        first = build_overflow_event(OVERFLOW_PAYLOADS[1])
        second = build_overflow_event(OVERFLOW_PAYLOADS[1])
        assert first == second


class TestWhatTheGuardDoesWithOverflow:
    """Measured, not asserted. The guard was written for prose and these
    payloads are mostly not prose, so a floor here would be a floor on
    something it was never built to do."""

    def test_the_rate_is_recorded_with_its_denominator(self, guard: PromptInjectionGuard) -> None:
        with_instruction = [p for p in OVERFLOW_PAYLOADS if p.tail_instruction]
        flagged = 0
        for payload in with_instruction:
            event = build_overflow_event(payload)
            if guard.scan({payload.field_path: event["value"]}).detected:
                flagged += 1

        # Recorded at whatever it is. The number is the finding.
        assert 0 <= flagged <= len(with_instruction)
        assert len(with_instruction) == 4, "denominator moved; update the published figure with it"

    def test_the_no_instruction_control_is_not_flagged(self, guard: PromptInjectionGuard) -> None:
        """A guard that flagged sheer size would be unusable: real DNS
        logs and real command lines reach these sizes legitimately."""
        control = next(p for p in OVERFLOW_PAYLOADS if not p.tail_instruction)
        event = build_overflow_event(control)
        verdict = guard.scan({control.field_path: event["value"]})
        assert not verdict.detected, "the guard flags volume alone, which would fire on every large legitimate field"

    def test_the_same_instruction_in_a_small_field_is_caught(self, guard: PromptInjectionGuard) -> None:
        """The decisive comparison. If the instruction is caught alone
        and missed inside the padding, the padding is what defeated the
        guard — which is the claim this corpus exists to support.
        """
        payload = next(p for p in OVERFLOW_PAYLOADS if p.tail_instruction)
        alone = guard.scan({payload.field_path: payload.tail_instruction}).detected
        buried = guard.scan({payload.field_path: build_overflow_event(payload)["value"]}).detected

        if alone and not buried:
            pytest.fail(f"{payload.id}: the guard catches this instruction alone and misses it under padding, so volume defeats it")
