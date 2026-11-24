"""Linked alert observations must not be guessed by the report model."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from app.investigator import forensic_agent, report_writer_agent
from app.investigator.evidence_context import LINKED_OBSERVATIONS_HEADING, render_alert_observations, select_alert_observations
from app.investigator.state import InvestigatorState, StepKind
from app.investigator.tools import sha256_of
from app.llm import contract
from app.llm.response_cache import ResponseCache
from langchain_core.messages import AIMessage


def _alert_id(i: int) -> str:
    return f"00000000-0000-4000-8000-{i:012d}"


def _alerts() -> list[dict[str, str]]:
    return [
        {
            "id": _alert_id(i),
            "event_time": f"2026-11-24T{i:02d}:00:00+08:00",
            "severity": "high" if i == 7 else "low",
            "source": "wazuh",
            "full_log": "RAW_LOG_NOT_A_REPORT_ROW",
        }
        for i in range(10)
    ]


def test_selects_late_severe_observation_and_retains_boundaries() -> None:
    alerts = _alerts()
    rows, omitted = select_alert_observations({"alerts": [*reversed(alerts), alerts[7]]})
    assert [row.alert_id for row in rows] == [_alert_id(i) for i in (0, 1, 2, 7, 9)]
    assert omitted == 5
    assert rows[0].when.isoformat() == "2026-11-23T16:00:00+00:00"


def test_compaction_retains_disagreeing_observations() -> None:
    primary = _alerts()[0]
    conflict = {**primary, "severity": "high"}
    rows, omitted = select_alert_observations({"alerts": [conflict, primary, primary, conflict]})
    assert [row.severity for row in rows] == ["high", "low"]
    assert omitted == 0


def test_unknown_or_unusable_report_metadata_is_not_guessed() -> None:
    alerts = _alerts()
    alerts[0]["source"] = "wazuh|unexpected column"
    alerts[1]["event_time"] = "2026-11-24T01:00:00"
    report = render_alert_observations({"alerts": alerts[:2]})
    assert f"| {_alert_id(0)} | unknown | low |" in report
    assert _alert_id(1) not in report
    assert "unexpected column" not in report
    assert "RAW_LOG_NOT_A_REPORT_ROW" not in report
    empty_copy = "No usable linked alert observations were available."
    assert empty_copy in render_alert_observations({})
    assert empty_copy in render_alert_observations({"alerts": [{**alerts[0], "id": "not-a-uuid"}]})
    assert "Too many linked alerts" in render_alert_observations({"alerts": alerts * 103})


@pytest.mark.asyncio
async def test_real_forensic_entry_passes_risk_selected_projection(monkeypatch: pytest.MonkeyPatch) -> None:
    invoke = AsyncMock(return_value=SimpleNamespace(content='{"summary": "Observed alert metadata."}', response_metadata={}))
    monkeypatch.setattr(forensic_agent, "safe_ainvoke", invoke)
    monkeypatch.setattr(forensic_agent, "make_chat_model", lambda *args, **kwargs: object())
    monkeypatch.setattr(forensic_agent, "record_llm_call", lambda *args, **kwargs: None)
    state = InvestigatorState(case_id="CASE-EVIDENCE", raw_alert={"alerts": _alerts()})

    await forensic_agent._llm_forensic(state)
    assert invoke.await_args is not None
    prompt = invoke.await_args.args[1][1].content
    ranked_data = prompt.split('<UNTRUSTED_DATA source="linked_alert_observations">\n', 1)[1].split("</UNTRUSTED_DATA>", 1)[0]
    assert _alert_id(7) in ranked_data
    assert _alert_id(4) not in ranked_data
    assert "RAW_LOG_NOT_A_REPORT_ROW" not in ranked_data


@pytest.mark.asyncio
@pytest.mark.parametrize("reply", ["# Incident Report\n\nExisting summary", None, []])
async def test_report_entry_renders_and_hashes_its_source_observations(monkeypatch: pytest.MonkeyPatch, reply) -> None:
    assert "## Timeline of Events" not in report_writer_agent.prompt_text("report_writer.system")
    monkeypatch.setattr(report_writer_agent, "make_chat_model", lambda *args, **kwargs: object())
    monkeypatch.setattr(report_writer_agent, "record_llm_call", lambda *args, **kwargs: None)
    if reply is None:
        invoke = AsyncMock(side_effect=RuntimeError("Test model unavailable"))
    else:
        invoke = AsyncMock(return_value=SimpleNamespace(content=reply, response_metadata={}))
    monkeypatch.setattr(report_writer_agent, "safe_ainvoke", invoke)
    state = InvestigatorState(case_id="CASE-EVIDENCE", raw_alert={"alerts": _alerts()})
    state.forensic.timeline = [{"ts": "1999-12-31", "event": "UNVERIFIED_TIMELINE"}]

    result = InvestigatorState.from_dict(await report_writer_agent.run_report_writer(state.to_dict()))
    assert result.report_md.count("## Timeline of linked alert observations") == 1
    assert "not a confirmed incident chronology" in result.report_md
    assert _alert_id(7) in result.report_md
    assert _alert_id(4) not in result.report_md
    assert "UNVERIFIED_TIMELINE" not in result.report_md
    assert "RAW_LOG_NOT_A_REPORT_ROW" not in result.report_md
    assert _alert_id(7) in result.report_html
    if reply:
        assert "Existing summary" in result.report_md
    else:
        assert StepKind.ERROR in [entry.kind for entry in result.audit_log]
    entry = next(entry for entry in result.audit_log if entry.kind == StepKind.REPORT)
    assert entry.metadata["report_hash"] == sha256_of(result.report_md)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("heading", "duplicate_fallback_heading"),
    [
        ("## Timeline of linked alert observations", False),
        ("Timeline of [linked alert](https://example.com) observations\n---", False),
        ("<h2>Timeline of <em>linked alert</em> observ&#97;tions</h2>", True),
    ],
)
async def test_report_entry_rejects_prose_reusing_the_reserved_label(
    monkeypatch: pytest.MonkeyPatch, heading: str, duplicate_fallback_heading: bool
) -> None:
    false_date = "1999-12-31"
    reply = SimpleNamespace(
        content=f"{heading}\n\n{false_date}: synthetic contradiction",
        response_metadata={"token_usage": {"total_tokens": 37}},
    )
    monkeypatch.setattr(report_writer_agent, "make_chat_model", lambda *args, **kwargs: object())
    monkeypatch.setattr(report_writer_agent, "safe_ainvoke", AsyncMock(return_value=reply))
    monkeypatch.setattr(report_writer_agent, "record_llm_call", lambda *args, **kwargs: None)
    state = InvestigatorState(case_id="CASE-REVIEW", raw_alert={"alerts": _alerts()[:1]})
    if duplicate_fallback_heading:
        state.recon.summary = f"## {LINKED_OBSERVATIONS_HEADING}\n\n{false_date}"

    result = InvestigatorState.from_dict(await report_writer_agent.run_report_writer(state.to_dict()))

    for report in (result.report_md, result.report_html):
        assert report.count(LINKED_OBSERVATIONS_HEADING) == 1
        assert false_date not in report
        assert _alert_id(0) in report
    assert StepKind.ERROR in [entry.kind for entry in result.audit_log]
    (response,) = [entry for entry in result.audit_log if entry.kind == StepKind.LLM_RESPONSE]
    (prompt,) = [entry for entry in result.audit_log if entry.kind == StepKind.LLM_PROMPT]
    assert response.input_hash == response.metadata["prompt_hash"] == prompt.input_hash
    assert response.output_hash == sha256_of(reply.content)
    assert response.metadata["tokens_used"] == 37
    assert response.metadata["outcome"] == "rejected"
    assert response.metadata["rejection_reason"] == "reserved_evidence_heading"
    assert "response" not in response.metadata
    assert "synthetic contradiction" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_truncated_report_cannot_swallow_the_linked_alert_table(monkeypatch: pytest.MonkeyPatch) -> None:
    content = "## Executive Summary\n\n<table><tr><td>INCOMPLETE_NARRATIVE"
    reply = SimpleNamespace(
        content=content,
        response_metadata={"finish_reason": "length"},
        usage_metadata={"total_tokens": 41},
    )
    monkeypatch.setattr(report_writer_agent, "make_chat_model", lambda *args, **kwargs: object())
    monkeypatch.setattr(report_writer_agent, "safe_ainvoke", AsyncMock(return_value=reply))
    monkeypatch.setattr(report_writer_agent, "record_llm_call", lambda *args, **kwargs: None)
    state = InvestigatorState(case_id="CASE-TRUNCATED-NARRATIVE", raw_alert={"alerts": _alerts()[:1]})

    result = InvestigatorState.from_dict(await report_writer_agent.run_report_writer(state.to_dict()))

    assert result.status == "completed"
    assert result.report_md.count(f"## {LINKED_OBSERVATIONS_HEADING}") == 1
    assert result.report_html.count(f"<h2>{LINKED_OBSERVATIONS_HEADING}</h2>") == 1
    assert result.report_html.count("<th>Event time (UTC)</th>") == 1
    assert result.report_html.count("<th>Alert ID</th>") == 1
    assert _alert_id(0) in result.report_html
    assert "INCOMPLETE_NARRATIVE" not in result.model_dump_json()
    (response,) = [entry for entry in result.audit_log if entry.kind == StepKind.LLM_RESPONSE]
    assert response.output_hash == sha256_of(content)
    assert response.metadata["tokens_used"] == 41
    assert response.metadata["rejection_reason"] == "completion_token_limit"
    (audit,) = [entry for entry in result.audit_log if entry.kind == StepKind.REPORT]
    assert audit.metadata["report_hash"] == sha256_of(result.report_md)


@pytest.mark.asyncio
async def test_identical_retries_cannot_reuse_truncated_text_from_the_response_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    content = "## Executive Summary\n\n<table><tr><td>INCOMPLETE_RETRY"
    invoke = AsyncMock(return_value=AIMessage(content=content, response_metadata={"finish_reason": "length"}))
    model = SimpleNamespace(model="fixture-local-model", ainvoke=invoke)
    monkeypatch.setattr(contract, "_RESPONSE_CACHE", ResponseCache())
    monkeypatch.setattr(contract, "_RESPONSE_CACHE_ENABLED", True)
    monkeypatch.setattr(report_writer_agent, "make_chat_model", lambda *args, **kwargs: model)
    state = InvestigatorState(case_id="CASE-CACHE-RETRY", raw_alert={"alerts": _alerts()[:1]})

    for _ in range(2):
        result = InvestigatorState.from_dict(await report_writer_agent.run_report_writer(state.to_dict()))
        assert f"<h2>{LINKED_OBSERVATIONS_HEADING}</h2>" in result.report_html
        assert "<th>Event time (UTC)</th>" in result.report_html
        assert "INCOMPLETE_RETRY" not in result.model_dump_json()
        (audit,) = [entry for entry in result.audit_log if entry.kind == StepKind.LLM_RESPONSE]
        assert audit.metadata["rejection_reason"] == "completion_token_limit"
    assert invoke.await_count == 2
    first, second = invoke.await_args_list
    assert [entry.content for entry in first.args[0]] == [entry.content for entry in second.args[0]]
    assert first.kwargs == second.kwargs == {}


@pytest.mark.asyncio
async def test_rejected_structured_report_digest_preserves_type_and_canonical_key_order(monkeypatch: pytest.MonkeyPatch) -> None:
    first = [{"type": "text", "text": "structured"}]
    second = [{"text": "structured", "type": "text"}]
    third = str(first)
    invoke = AsyncMock(side_effect=[SimpleNamespace(content=x) for x in (first, second, third)])
    monkeypatch.setattr(report_writer_agent, "make_chat_model", lambda *args, **kwargs: object())
    monkeypatch.setattr(report_writer_agent, "safe_ainvoke", invoke)
    monkeypatch.setattr(report_writer_agent, "record_llm_call", lambda *args, **kwargs: None)
    state = InvestigatorState(case_id="CASE-TYPED-HASH", raw_alert={"alerts": _alerts()[:1]})

    for expected in (first, second, third):
        result = InvestigatorState.from_dict(await report_writer_agent.run_report_writer(state.to_dict()))
        (audit,) = [entry for entry in result.audit_log if entry.kind == StepKind.LLM_RESPONSE]
        assert audit.output_hash == sha256_of(expected)
        if not isinstance(expected, str):
            assert audit.metadata["rejection_reason"] == "no_markdown_text"
            assert "response" not in audit.metadata

    assert sha256_of(first) == sha256_of(second) != sha256_of(third)
