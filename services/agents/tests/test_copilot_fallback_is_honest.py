"""The copilot says what happened instead of inventing an investigation.

Issue #1275. Two defects on the same code path.

**The fallback text named the wrong cause.** One string served both
fallback conditions and ended "Configure an LLM key to get a real
investigation". That branch is reached on *any* provider failure,
including a timeout from the bundled local model, which needs no API key
at all — so an operator whose model had merely timed out was told to go
and configure a credential their deployment does not use. The same lesson
is already recorded here from the RBA banner that blamed fusion while
fusion was healthy.

**The canned body was fabricated security analysis.** ``_synthetic_reply``
ignored its argument and returned the next of five rotating paragraphs,
each asserting specific findings about an estate it had never read — "this
IP was seen in 3 other alerts", "attacker dwell time appears short
(< 2 hours)". The reporter watched a ransomware alert come back described
as "credential-access activity ... LOLBin pattern". The console appends a
disclaimer above it, which does not make the body true.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.api import copilot
from app.llm import contract as llm_contract
from app.llm import factory as llm_factory


class TestTheTwoReasonsAreDistinguished:
    """Driven through the real `_get_openai_reply`, because the defect was
    that both conditions arrived at one string — a test calling the two
    message builders directly would never have noticed."""

    @pytest.mark.asyncio
    async def test_no_model_configured_is_reported_as_such(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(llm_factory, "resolve_api_key", lambda _m: "")

        _text, source, reason = await copilot._get_openai_reply({"messages": []}, "what happened?")

        assert source == "template"
        assert reason == copilot.NO_MODEL

    @pytest.mark.asyncio
    async def test_a_configured_model_that_fails_is_not_called_a_missing_key(self, monkeypatch: Any) -> None:
        """The exact situation from the report: a model *is* configured and
        the call timed out."""
        monkeypatch.setattr(llm_factory, "resolve_api_key", lambda _m: "sk-present")
        monkeypatch.setattr(llm_factory, "chat_completions_url", lambda _m=None: "http://local/v1/chat/completions")

        async def _boom(**_kwargs: Any) -> Any:
            raise TimeoutError()

        monkeypatch.setattr(llm_contract, "safe_chat_completions_request", _boom)

        text, source, reason = await copilot._get_openai_reply({"messages": []}, "what happened?")

        assert source == "template"
        assert reason == copilot.CALL_FAILED
        assert "not a missing credential" in text
        assert "not a missing API key" in (copilot._notice_for(reason) or "")

    @pytest.mark.asyncio
    async def test_an_empty_exception_message_still_names_the_failure(self, monkeypatch: Any) -> None:
        """`str(exc)` is empty for several httpx timeout classes, which is
        why the report saw `copilot.openai_error` with no message."""
        monkeypatch.setattr(llm_factory, "resolve_api_key", lambda _m: "sk-present")
        monkeypatch.setattr(llm_factory, "chat_completions_url", lambda _m=None: "http://local/v1/chat/completions")

        async def _boom(**_kwargs: Any) -> Any:
            raise TimeoutError()

        monkeypatch.setattr(llm_contract, "safe_chat_completions_request", _boom)

        text, _source, _reason = await copilot._get_openai_reply({"messages": []}, "q")
        assert "TimeoutError" in text

    def test_the_two_notices_differ(self) -> None:
        assert copilot._notice_for(copilot.NO_MODEL) != copilot._notice_for(copilot.CALL_FAILED)

    def test_only_the_unconfigured_notice_mentions_configuring_one(self) -> None:
        """The whole defect in one assertion."""
        failed = copilot._notice_for(copilot.CALL_FAILED) or ""
        assert "not a missing API key" in failed
        assert "A model is configured" in failed

    def test_a_model_answer_carries_no_notice(self) -> None:
        assert copilot._notice_for(None) is None


class TestTheFallbackBodyAssertsNothingAboutTheEstate:
    """Every one of these strings was in a reply the product shipped as a
    200, under a `source` field most callers never read."""

    @pytest.mark.parametrize(
        "fabricated",
        [
            "seen in 3 other alerts",
            "dwell time",
            "LOLBin",
            "unusual geolocation",
            "T1078",
            "T1021.002",
            "T1110",
            "isolating the host",
            "step-up MFA",
            "credential-stuffing",
        ],
    )
    def test_no_fabricated_finding_survives_in_any_fallback(self, fabricated: str) -> None:
        bodies = [
            copilot._fallback_reply(copilot.NO_MODEL),
            copilot._fallback_reply(copilot.CALL_FAILED, model="llama3.2:3b", detail="timeout"),
        ]
        for body in bodies:
            assert fabricated.lower() not in body.lower()

    def test_the_module_no_longer_carries_the_canned_corpus(self) -> None:
        """The paragraphs are gone, not merely unreferenced. A constant left
        in place is one edit away from being used again."""
        assert not hasattr(copilot, "_SYNTHETIC_REPLIES")
        assert not hasattr(copilot, "_synthetic_reply")

    def test_the_reply_states_plainly_that_nothing_was_read(self) -> None:
        for body in (
            copilot._fallback_reply(copilot.NO_MODEL),
            copilot._fallback_reply(copilot.CALL_FAILED),
        ):
            assert "unanswered question rather than a finding" in body

    def test_the_failed_call_names_the_model_and_the_error(self) -> None:
        body = copilot._fallback_reply(copilot.CALL_FAILED, model="llama3.2:3b", detail="ReadTimeout")
        assert "llama3.2:3b" in body
        assert "ReadTimeout" in body

    def test_it_points_at_the_contention_the_reporter_actually_hit(self) -> None:
        """CPU-only deployments share one local model between interactive
        copilot and the auto-triage backlog. Naming it is the difference
        between a retry and an afternoon of debugging."""
        body = copilot._fallback_reply(copilot.CALL_FAILED)
        assert "auto-triage" in body

    def test_the_same_question_does_not_get_a_different_canned_answer(self) -> None:
        """`_synthetic_reply` cycled, so asking twice produced two
        unrelated 'analyses' of one alert."""
        first = copilot._fallback_reply(copilot.NO_MODEL)
        second = copilot._fallback_reply(copilot.NO_MODEL)
        assert first == second


class TestTheWireContractCarriesTheReason:
    def test_the_response_model_declares_the_reason(self) -> None:
        fields = copilot.CopilotChatResponse.model_fields
        assert "template_reason" in fields

    def test_it_is_optional_so_existing_clients_are_unaffected(self) -> None:
        """Additive, not a third `source` value — the console branches on
        `source === 'template'` and must keep working."""
        built = copilot.CopilotChatResponse(
            conversationId="c",
            reply=copilot.CopilotMessage(role="assistant", content="x"),
        )
        assert built.template_reason is None
        assert built.source == "llm"
