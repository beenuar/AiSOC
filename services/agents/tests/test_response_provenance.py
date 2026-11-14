"""Synthetic output must never be indistinguishable from real output.

Two endpoints returned generated content as an ordinary 200 with nothing on the
wire to mark it:

  * ``POST /api/v1/hunt/search`` always returned ``_synthetic_hits`` — it did
    not query the lake at all — and the console read the 200 as success and
    rendered a green "Live backend" pill over fabricated CrowdStrike events.
    That generator is now deleted and the handler reads the lake, so the
    provenance question here changed from "is this labelled sample?" to
    "does it say whether a query ran?"
  * ``POST /api/v1/copilot/chat`` falls back to a canned paragraph whenever
    ``OPENAI_API_KEY`` is unset or the call raises, so an analyst read generic
    claims as analysis of their own environment.

These tests pin the provenance fields that let a caller tell the difference.
They are deliberately about the contract, not the prose: the fixtures may
change, but a consumer must always be able to ask "did a model produce this?"
and "is this my data?" and get a truthful answer.
"""

from __future__ import annotations

import uuid

import pytest
from app.api import copilot as copilot_mod
from app.api import hunt_search as hunt_mod
from app.security.tenant_scope import TenantPrincipal

#: The real principal. The handler now binds one, and a hand-rolled double
#: would skip the scope resolution it depends on.
_PRINCIPAL = TenantPrincipal(
    tenant_ids=frozenset({uuid.UUID("00000000-0000-0000-0000-000000000001")}),
    subject="analyst@example.com",
)


class TestHuntSearchProvenance:
    """The provenance contract, now that the handler queries something.

    The old pair of cases asserted ``source == "sample"`` and that hits came
    back regardless — both of which described the fabricating path and would
    pass again if anyone restored it. The contract that survives the change
    is narrower and stronger: the response always says whether a query ran,
    and nothing is ever invented when one did not.
    """

    @pytest.mark.asyncio
    async def test_an_unreachable_lake_says_no_query_ran(self, monkeypatch: pytest.MonkeyPatch):
        async def _unavailable(*_a, **_kw):
            return hunt_mod.LakeAnswer(available=False, reason="ClickHouse is not reachable", hits=[])

        monkeypatch.setattr(hunt_mod, "_search_lake", _unavailable)
        res = await hunt_mod.hunt_search(hunt_mod.HuntQuery(query="process_name:powershell"), _PRINCIPAL)

        assert res.source == "unavailable"
        assert res.notice and "no query ran" in res.notice.lower()
        assert res.hits == [], "nothing may be invented for a query that did not run"
        assert res.took_ms is None, "there is no latency to publish for work nobody did"

    @pytest.mark.asyncio
    async def test_a_lake_answer_is_declared_live_and_returns_its_rows(self, monkeypatch: pytest.MonkeyPatch):
        async def _answered(*_a, **_kw):
            return hunt_mod.LakeAnswer(
                available=True,
                reason=None,
                hits=[
                    {
                        "id": "e1",
                        "timestamp": "2026-11-03T00:00:00+00:00",
                        "source": "crowdstrike",
                        "event_type": "4688",
                        "raw": {"process_name": "powershell.exe"},
                        "highlights": ["process_name:powershell"],
                    }
                ],
            )

        monkeypatch.setattr(hunt_mod, "_search_lake", _answered)
        res = await hunt_mod.hunt_search(hunt_mod.HuntQuery(query="process_name:powershell", limit=5), _PRINCIPAL)

        assert res.source == "live"
        assert res.hits and res.total == len(res.hits)

    def test_the_fabricating_generator_is_gone_rather_than_relabelled(self):
        assert not hasattr(hunt_mod, "_synthetic_hits")


class TestCopilotProvenance:
    @pytest.mark.asyncio
    async def test_no_api_key_is_reported_as_template(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        text, source, reason = await copilot_mod._get_openai_reply({"messages": []}, "what happened?")
        assert source == "template"
        assert text, "the fallback should still say something useful"
        # The reason is carried alongside the source (issue #1275): "nothing
        # is configured" and "what is configured did not answer" used to be
        # the same answer, and only one of them is fixed by a credential.
        assert reason == copilot_mod.NO_MODEL

    @pytest.mark.asyncio
    async def test_llm_failure_is_reported_as_template(self, monkeypatch: pytest.MonkeyPatch):
        """A provider error must degrade visibly, not silently."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-real-key")

        def _boom(*args, **kwargs):
            raise RuntimeError("provider unreachable")

        monkeypatch.setattr("app.llm.factory.make_chat_model", _boom, raising=False)
        _text, source, reason = await copilot_mod._get_openai_reply({"messages": []}, "hello")
        assert source == "template"
        assert reason == copilot_mod.CALL_FAILED

    def test_response_model_defaults_to_llm_but_can_carry_template(self):
        """The field must exist on the wire, not just in the handler."""
        fields = copilot_mod.CopilotChatResponse.model_fields
        assert "source" in fields
        assert "notice" in fields
        msg = copilot_mod.CopilotMessage(id="m1", role="assistant", content="hi", timestamp="2026-01-01T00:00:00Z")
        templated = copilot_mod.CopilotChatResponse(conversationId="c1", reply=msg, source="template", notice="canned")
        assert templated.source == "template"
