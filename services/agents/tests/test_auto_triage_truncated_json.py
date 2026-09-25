"""A small local model that stops mid-object must not lose its verdict.

CORE ships a model now — `llama3.2:3b-instruct-q4_K_M`, ~2 GB, CPU-only — so
the auto-triage parser's tolerance stopped being a nicety. Measured against
that model on the real triage prompt, a response came back as::

    {
      "verdict": "true_positive",
      "confidence": 0.8,
      "rationale": "…some uncertainty remains due to the lack of IOCs.

`finish_reason` was `"stop"`, not a token limit — the model simply ended
without closing the string or the object. Every field the caller reads was
present and correct. `json.loads` raised, the brace-slice fallback found no
closing `}` to slice to, and the alert fell through to deterministic triage:
a real LLM call, real tokens billed, and its verdict thrown away.

The repair closes what was opened and nothing more. These tests pin that it
cannot become a verdict generator — the case it must still refuse is as
important as the ones it must fix.
"""

from __future__ import annotations

import json

import pytest
from app.agents.auto_triage_agent import _close_truncated_json, _parse_llm_response
from app.agents.dispositions import TRUE_POSITIVE


class TestRepair:
    """The closer, on its own."""

    @pytest.mark.parametrize(
        ("fragment", "expected"),
        [
            (
                '{\n "verdict": "true_positive",\n "confidence": 0.8,\n "rationale": "no IOCs present.',
                {"verdict": "true_positive", "confidence": 0.8, "rationale": "no IOCs present."},
            ),
            ('{"verdict": "benign", "confidence": 0.9', {"verdict": "benign", "confidence": 0.9}),
            ('{"verdict": "benign", "confidence": 0.9,', {"verdict": "benign", "confidence": 0.9}),
            ('{"verdict": "benign", "findings": ["a", "b"', {"verdict": "benign", "findings": ["a", "b"]}),
            ('{"verdict": "benign"}', {"verdict": "benign"}),
        ],
        ids=["mid-string", "after-value", "trailing-comma", "open-array", "already-closed"],
    )
    def test_it_closes_what_the_model_opened(self, fragment: str, expected: dict) -> None:
        assert json.loads(_close_truncated_json(fragment)) == expected

    def test_a_backslash_at_the_cut_does_not_eat_the_closing_quote(self) -> None:
        """`"path C:\\` + `"` is an escaped quote, not a terminator."""
        assert json.loads(_close_truncated_json('{"rationale": "path C:\\\\')) == {"rationale": "path C:\\"}

    def test_a_quote_inside_the_rationale_is_not_mistaken_for_the_end(self) -> None:
        fragment = '{"verdict": "benign", "rationale": "the user ran \\"whoami\\" interactively'
        assert json.loads(_close_truncated_json(fragment))["rationale"] == 'the user ran "whoami" interactively'


class TestParser:
    """The parser's behaviour end to end."""

    def test_a_truncated_verdict_is_recovered_rather_than_discarded(self) -> None:
        raw = '{\n  "verdict": "true_positive",\n  "confidence": 0.8,\n  "rationale": "Encoded PowerShell under WINWORD.EXE.'
        result = _parse_llm_response(raw)
        assert result["verdict"] == TRUE_POSITIVE
        assert result["confidence"] == 0.8
        assert result["rationale"].startswith("Encoded PowerShell")

    def test_a_fragment_too_damaged_to_read_still_raises(self) -> None:
        """The deterministic fallback must still be reachable.

        Repairing this into `{}` would hand the caller a verdict-less object,
        which `normalize_disposition` would turn into a conservative
        `true_positive` — a fabricated verdict wearing a real one's clothes.
        Raising sends it to deterministic triage, which is honest about what
        produced it.
        """
        with pytest.raises(json.JSONDecodeError):
            _parse_llm_response('{"confi')

    def test_prose_with_no_object_at_all_still_raises(self) -> None:
        with pytest.raises(json.JSONDecodeError):
            _parse_llm_response("I am unable to assess this alert.")

    def test_a_well_formed_response_is_unaffected(self) -> None:
        raw = '{"verdict": "benign", "confidence": 0.95, "rationale": "scheduled scan"}'
        assert _parse_llm_response(raw) == {"verdict": "benign", "confidence": 0.95, "rationale": "scheduled scan"}

    def test_a_fenced_response_is_still_unfenced_first(self) -> None:
        raw = '```json\n{"verdict": "benign", "confidence": 0.5, "rationale": "x"}\n```'
        assert _parse_llm_response(raw)["verdict"] == "benign"

    def test_a_fenced_and_truncated_response_is_both_unfenced_and_closed(self) -> None:
        raw = '```json\n{"verdict": "needs_review", "confidence": 0.4, "rationale": "not enough'
        result = _parse_llm_response(raw)
        assert result["verdict"] == "needs_review"
        assert result["rationale"] == "not enough"
