"""Organisation memory reaches the triage prompt, or it is not a feature.

``services/api/app/services/analyst_feedback.py`` compiles repeated, tagged
analyst disagreement into durable statements. It is tested, gated in the
claim-to-gate matrix, and until now a repo-wide grep for its read function
``active_statements`` returned exactly one match: the definition. The platform
recorded what analysts taught it and triaged the next identical alert knowing
none of it.

The load-bearing assertion in this file is
:func:`test_the_prompt_the_model_receives_actually_changes` — it captures the
messages handed to the model with and without a statement and diffs them.
Everything else here is a property of that block: that it is absent when there
is nothing to say, that it does not become an instruction, and that it cannot
be used to smuggle one.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from app.agents import auto_triage_agent as ata
from app.agents.dispositions import BENIGN_TRUE_POSITIVE
from app.context import organisation_memory as om
from app.models.state import AgentStatus, InvestigationState

STATEMENT = "PowerShell launched by svc_backup on BACKUP01 is expected during the 02:00 backup window."


def _state(memory: list[dict] | None = None) -> InvestigationState:
    return InvestigationState(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        alert_summary="Encoded PowerShell command on BACKUP01",
        raw_alert={"severity": "medium", "hostname": "BACKUP01", "username": "svc_backup"},
        organisation_memory=memory or [],
        status=AgentStatus.PENDING,
    )


def _capture_prompt(monkeypatch) -> list[list]:
    """Patch the model out and keep every message list it was handed."""
    seen: list[list] = []
    payload = json.dumps({"verdict": BENIGN_TRUE_POSITIVE, "confidence": 0.9, "rationale": "expected"})

    async def _fake_ainvoke(_llm, messages):
        seen.append(messages)
        return SimpleNamespace(content=payload)

    monkeypatch.setattr(ata, "make_chat_model", lambda *a, **k: object())
    monkeypatch.setattr(ata, "safe_ainvoke", _fake_ainvoke)
    return seen


def _human_text(messages: list) -> str:
    return "\n".join(str(m.content) for m in messages if m.__class__.__name__ == "HumanMessage")


# ── The claim ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_prompt_the_model_receives_actually_changes(monkeypatch):
    """With a disagreement recorded, the model sees something it did not before.

    This is the whole point, so it is asserted by diffing two real prompts
    rather than by checking that a helper returns a string.
    """
    seen = _capture_prompt(monkeypatch)

    await ata.run_auto_triage(_state())
    without = _human_text(seen[-1])

    await ata.run_auto_triage(_state([{"statement": STATEMENT, "observations": 3, "reason_code": "expected_service_account"}]))
    with_memory = _human_text(seen[-1])

    assert with_memory != without
    assert STATEMENT in with_memory
    assert STATEMENT not in without
    # And the alert itself is still all there — the memory is added, not
    # substituted for the evidence.
    assert "BACKUP01" in without and "BACKUP01" in with_memory
    assert len(with_memory) > len(without)


@pytest.mark.asyncio
async def test_no_statements_adds_nothing_at_all(monkeypatch):
    # "Organisation memory: none" would teach the model that this tenant has
    # no conventions, which is a claim rather than the absence of one.
    seen = _capture_prompt(monkeypatch)

    await ata.run_auto_triage(_state())

    text = _human_text(seen[-1])
    assert "Organisation memory" not in text


@pytest.mark.asyncio
async def test_the_observation_count_travels_with_the_statement(monkeypatch):
    # A statement backed by five analysts is stronger evidence than one backed
    # by the corroboration minimum, and the model can only weigh that if it is
    # told. Dropping it would flatten the corroboration design into a boolean.
    seen = _capture_prompt(monkeypatch)

    await ata.run_auto_triage(_state([{"statement": STATEMENT, "observations": 5}]))

    assert "5 analyst(s)" in _human_text(seen[-1])


# ── Properties of the block ──────────────────────────────────────────────────


class TestRenderForPrompt:
    def test_empty_in_empty_out(self):
        assert om.render_for_prompt([]) == ""
        assert om.render_for_prompt([{"statement": "   "}]) == ""

    def test_statements_are_advisory_not_instructions(self):
        # A statement needs two analysts. Phrasing it as fact would hand anyone
        # who can produce two benign votes a suppression the model obeys.
        text = om.render_for_prompt([{"statement": STATEMENT, "observations": 2}])

        assert "not as" in text and "instructions" in text
        assert "never overrides direct evidence of compromise" in text

    def test_most_corroborated_statements_win_the_budget(self):
        rows = [{"statement": f"s{i}", "observations": i} for i in range(40)]

        text = om.render_for_prompt(rows)

        assert text.count("\n- ") + text.count("- ") >= 1
        lines = [ln for ln in text.splitlines() if ln.startswith("- ")]
        assert len(lines) == om.MAX_STATEMENTS
        # Highest observation count first, so truncation drops the weakest.
        assert "s39" in lines[0]
        assert not any("s0 " in ln for ln in lines)

    def test_a_long_statement_is_capped(self):
        text = om.render_for_prompt([{"statement": "A" * 5000, "observations": 1}])

        assert len(text) < 1200


class TestFetchStatementsFailsSoft:
    @pytest.mark.asyncio
    async def test_no_tenant_means_no_call(self, monkeypatch):
        monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "t")
        om.clear_cache()

        assert await om.fetch_statements(None) == []
        assert await om.fetch_statements("") == []

    @pytest.mark.asyncio
    async def test_a_missing_service_token_is_loud_and_empty(self, monkeypatch):
        # Silence here means every triage runs without the memory an operator
        # believes they are teaching it.
        monkeypatch.delenv("AISOC_AGENTS_SERVICE_TOKEN", raising=False)
        om.clear_cache()
        warnings: list[str] = []
        monkeypatch.setattr(om.logger, "warning", lambda event, **kw: warnings.append(event))

        assert await om.fetch_statements("t-1") == []
        assert "org_memory.no_service_token" in warnings

    @pytest.mark.asyncio
    async def test_disabled_by_flag(self, monkeypatch):
        monkeypatch.setenv("AISOC_ORG_MEMORY_ENABLED", "0")
        om.clear_cache()

        assert await om.fetch_statements("t-1") == []

    @pytest.mark.asyncio
    async def test_an_unreachable_api_serves_the_last_known_statements(self, monkeypatch):
        # A brief API outage must not silently drop a tenant's suppressions and
        # re-raise alerts they have already dispositioned twice.
        monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "t")
        om.clear_cache()
        om._cache["t-1"] = (0.0, [{"statement": STATEMENT, "observations": 2}])

        class _Boom:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, *a, **k):
                raise om.httpx.ConnectError("refused")

        monkeypatch.setattr(om.httpx, "AsyncClient", lambda **k: _Boom())

        rows = await om.fetch_statements("t-1")

        assert rows and rows[0]["statement"] == STATEMENT
