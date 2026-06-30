"""Unit tests for the NL → playbook drafter (T3.7).

Three concerns covered:

1. **Substrate-mode determinism.** The no-LLM path is exercised by
   :func:`draft_from_nl_substrate` and by the async
   :func:`draft_from_nl` with ``allow_llm=False``. Steps must come out
   in prompt order, the trigger must be inferred correctly, every
   draft must ship with ``enabled=False``.

2. **Pydantic + JSON-Schema validity.** Every draft must round-trip
   through :class:`Playbook.model_validate` AND, when ``jsonschema``
   is installed, pass ``schemas/playbook.schema.json`` (the file CI
   uses via ``scripts/lint_playbooks.py``).

3. **LLM-failure resilience.** A LLM that returns malformed JSON, a
   non-object, or text wrapped in a ```json fence must NOT crash —
   the drafter falls back to the substrate path and the response
   surface stays identical (``DraftResult`` shape).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from app.playbook import (
    DraftResult,
    Playbook,
    StepType,
    draft_from_nl,
    draft_from_nl_substrate,
    nl_drafter,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro: Any) -> Any:
    """Run an awaitable synchronously, with one event loop per call."""

    return asyncio.run(coro)


def _step_types(pb: Playbook) -> list[str]:
    return [s.type.value for s in pb.steps]


# ---------------------------------------------------------------------------
# Substrate — deterministic step extraction
# ---------------------------------------------------------------------------


class TestSubstrateExtraction:
    def test_empty_prompt_yields_single_investigate_fallback(self) -> None:
        pb = draft_from_nl_substrate("")
        assert isinstance(pb, Playbook)
        assert len(pb.steps) == 1
        assert pb.steps[0].type == StepType.INVESTIGATE
        assert pb.enabled is False, "drafts must ship disabled"

    def test_whitespace_only_prompt_is_treated_as_empty(self) -> None:
        pb = draft_from_nl_substrate("   \n   \t   ")
        assert len(pb.steps) == 1
        assert pb.steps[0].type == StepType.INVESTIGATE

    def test_steps_emit_in_prompt_order(self) -> None:
        prompt = "When a high-severity alert fires, enrich the entity, " "isolate the host, then notify the SOC and create a ticket."
        pb = draft_from_nl_substrate(prompt)
        types = _step_types(pb)
        # Each verb should appear once, in prompt order.
        assert types == ["enrich", "isolate_host", "notify", "create_ticket"]

    def test_each_step_type_emits_at_most_once(self) -> None:
        # "isolate" appears twice — only ONE isolate_host step should emerge.
        prompt = "isolate the host, then later also isolate the host again"
        pb = draft_from_nl_substrate(prompt)
        assert _step_types(pb).count("isolate_host") == 1

    def test_block_ip_distinct_from_block_ioc(self) -> None:
        prompt = "Block the IP and also block the IOC hash."
        pb = draft_from_nl_substrate(prompt)
        types = _step_types(pb)
        assert "block_ip" in types
        assert "block_ioc" in types

    def test_trigger_on_inferred_to_case_when_case_word_present(self) -> None:
        pb = draft_from_nl_substrate("On a high-severity case, enrich the entity")
        assert pb.trigger["on"] == "case"

    def test_trigger_on_inferred_to_alert_by_default(self) -> None:
        pb = draft_from_nl_substrate("Notify the SOC and enrich the entity")
        # No "case" / "schedule" keyword → default is "alert".
        assert pb.trigger["on"] == "alert"

    def test_trigger_severity_inferred_from_high_token(self) -> None:
        pb = draft_from_nl_substrate("When a high-severity alert fires, isolate the host")
        assert pb.trigger.get("severity") == ["high"]

    def test_trigger_severity_inferred_from_critical_token(self) -> None:
        pb = draft_from_nl_substrate("Critical alert: block the IP and notify the SOC")
        assert "critical" in pb.trigger.get("severity", [])

    def test_iam_role_isolation_maps_to_isolate_host(self) -> None:
        # IAM-role isolation maps to ``isolate_host`` for now since
        # ``isolate_iam_role`` is not in the StepType enum.
        pb = draft_from_nl_substrate("Isolate the IAM role attached to the bucket")
        assert StepType.ISOLATE_HOST in [s.type for s in pb.steps]

    def test_bucket_snapshot_maps_to_quarantine_file(self) -> None:
        pb = draft_from_nl_substrate("Snapshot the bucket policy for forensics")
        assert StepType.QUARANTINE_FILE in [s.type for s in pb.steps]

    def test_steps_carry_humanised_names(self) -> None:
        pb = draft_from_nl_substrate("When a high-severity alert fires, isolate the host")
        step = next(s for s in pb.steps if s.type == StepType.ISOLATE_HOST)
        # Name must be more descriptive than just the bare type.
        assert step.name and step.name != "isolate_host"
        assert "Isolate Host" in step.name or "isolate" in step.name.lower()

    def test_tags_include_nl_drafted_and_draft(self) -> None:
        pb = draft_from_nl_substrate("Notify the SOC")
        assert "nl-drafted" in pb.tags
        assert "draft" in pb.tags

    def test_draft_always_disabled(self) -> None:
        pb = draft_from_nl_substrate("Isolate the host immediately")
        assert pb.enabled is False

    def test_draft_carries_iso8601_timestamps(self) -> None:
        pb = draft_from_nl_substrate("Enrich the entity")
        assert pb.created_at.endswith("+00:00") or pb.created_at.endswith("Z")
        assert pb.updated_at == pb.created_at


# ---------------------------------------------------------------------------
# Pydantic + JSON Schema validity
# ---------------------------------------------------------------------------


class TestSchemaValidity:
    def test_substrate_draft_passes_pydantic(self) -> None:
        pb = draft_from_nl_substrate(
            "When a high-severity alert fires, enrich the entity, " "isolate the host, notify the SOC, create a ticket"
        )
        # Round-trip via the Pydantic model — this is the contract the
        # editor consumes.
        rehydrated = Playbook.model_validate(pb.model_dump())
        assert rehydrated.id == pb.id
        assert _step_types(rehydrated) == _step_types(pb)

    def test_step_type_collapse_preserves_original_type(self) -> None:
        # ``run_av_scan`` is Pydantic-only — schema collapse must map it
        # to a schema-allowed type and stash the original in params.
        payload = {
            "id": "test-id",
            "name": "Test",
            "version": "1.0.0",
            "trigger": {"on": "alert"},
            "steps": [
                {
                    "id": "s1",
                    "name": "Run AV Scan",
                    "type": "run_av_scan",
                    "params": {},
                }
            ],
        }
        collapsed = nl_drafter._collapse_step_types_for_schema(payload)
        assert collapsed["steps"][0]["type"] in nl_drafter._SCHEMA_STEP_TYPES
        assert collapsed["steps"][0]["params"]["original_type"] == "run_av_scan"

    def test_schema_collapse_is_pure(self) -> None:
        # The collapse helper must NOT mutate its input.
        payload = {
            "id": "test-id",
            "name": "Test",
            "version": "1.0.0",
            "trigger": {"on": "alert"},
            "steps": [{"id": "s1", "name": "x", "type": "block_ioc", "params": {}}],
        }
        before = json.dumps(payload, sort_keys=True)
        nl_drafter._collapse_step_types_for_schema(payload)
        after = json.dumps(payload, sort_keys=True)
        assert before == after, "collapse must not mutate its input"

    def test_schema_allowed_types_unchanged_by_collapse(self) -> None:
        payload = {
            "id": "test-id",
            "name": "Test",
            "version": "1.0.0",
            "trigger": {"on": "alert"},
            "steps": [
                {"id": "s1", "name": "x", "type": "enrich", "params": {}},
                {"id": "s2", "name": "y", "type": "notify", "params": {}},
            ],
        }
        collapsed = nl_drafter._collapse_step_types_for_schema(payload)
        assert collapsed["steps"][0]["type"] == "enrich"
        assert collapsed["steps"][1]["type"] == "notify"

    def test_draft_result_to_dict_round_trip(self) -> None:
        async def _go() -> DraftResult:
            return await draft_from_nl("Notify the SOC and enrich the entity", allow_llm=False)

        result = asyncio.run(_go())
        d = result.to_dict()
        assert set(d.keys()) == {"playbook", "rationale", "used_llm", "schema_validated"}
        assert d["used_llm"] is False
        # When jsonschema isn't installed schema_validated still defaults to
        # True — the drafter never emits ``False`` for a Pydantic-valid draft.
        assert d["schema_validated"] is True
        assert d["playbook"]["enabled"] is False


# ---------------------------------------------------------------------------
# LLM-failure resilience
# ---------------------------------------------------------------------------


class _FakeLLMReturning:
    """Sync stand-in for the chat-model factory output.

    The drafter's ``_llm_factory`` lazily imports ``app.llm.factory``;
    we patch ``_llm_factory`` directly so the test never has to load
    that subsystem (langchain etc.) and stays hermetic.
    """

    def __init__(self, payload: Any) -> None:
        self._payload = payload

    async def ainvoke(self, _messages: Any) -> Any:
        return self._payload


class _Resp:
    def __init__(self, content: str) -> None:
        self.content = content


class TestLLMResilience:
    def _patch_llm(self, monkeypatch: pytest.MonkeyPatch, payload: Any) -> None:
        monkeypatch.setattr(nl_drafter, "_llm_factory", lambda: _FakeLLMReturning(payload))
        # safe_ainvoke is normally enforced via app.llm; the drafter
        # imports it lazily, so stub it to call the fake directly.

        async def _fake_safe(llm: Any, messages: Any, **_: Any) -> Any:
            return await llm.ainvoke(messages)

        # The drafter imports ``app.llm.safe_ainvoke`` lazily inside
        # ``_llm_draft`` — patch the import target.
        import sys
        import types

        fake = types.ModuleType("app.llm")
        fake.safe_ainvoke = _fake_safe  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "app.llm", fake)

    def test_llm_returning_valid_json_is_used(self, monkeypatch: pytest.MonkeyPatch) -> None:
        good = {
            "id": "llm-test-id",
            "name": "LLM Draft",
            "version": "1.0.0",
            "trigger": {"on": "alert"},
            "steps": [
                {
                    "id": "abc12345",
                    "name": "Enrich",
                    "type": "enrich",
                    "params": {},
                    "on_failure": "abort",
                    "retry_max": 0,
                    "timeout_seconds": 30,
                }
            ],
            "enabled": True,  # drafter MUST override this back to False
        }
        self._patch_llm(monkeypatch, _Resp(json.dumps(good)))
        result = asyncio.run(draft_from_nl("Enrich the entity", allow_llm=True))
        assert result.used_llm is True
        assert result.playbook.id == "llm-test-id"
        assert result.playbook.enabled is False, "drafter must override LLM enabled flag"
        assert "nl-drafted" in result.playbook.tags

    def test_llm_returning_json_in_fence_is_unwrapped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        good = {
            "id": "fenced-id",
            "name": "Fenced",
            "version": "1.0.0",
            "trigger": {"on": "alert"},
            "steps": [
                {
                    "id": "s1abcdef",
                    "name": "Notify",
                    "type": "notify",
                    "params": {},
                    "on_failure": "abort",
                    "retry_max": 0,
                    "timeout_seconds": 30,
                }
            ],
        }
        fenced = "```json\n" + json.dumps(good) + "\n```"
        self._patch_llm(monkeypatch, _Resp(fenced))
        result = asyncio.run(draft_from_nl("Notify the SOC", allow_llm=True))
        assert result.used_llm is True
        assert result.playbook.id == "fenced-id"

    def test_llm_returning_malformed_json_falls_back_to_substrate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_llm(monkeypatch, _Resp("not even close to JSON {{{"))
        result = asyncio.run(draft_from_nl("Isolate the host and notify the SOC", allow_llm=True))
        assert result.used_llm is False
        assert "isolate_host" in _step_types(result.playbook)
        assert "notify" in _step_types(result.playbook)

    def test_llm_returning_array_falls_back_to_substrate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Drafter requires a JSON OBJECT, never an array.
        self._patch_llm(monkeypatch, _Resp(json.dumps([1, 2, 3])))
        result = asyncio.run(draft_from_nl("Enrich the entity", allow_llm=True))
        assert result.used_llm is False
        assert "enrich" in _step_types(result.playbook)

    def test_llm_raising_exception_falls_back_to_substrate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Boom:
            async def ainvoke(self, _messages: Any) -> Any:
                raise RuntimeError("LLM is down")

        monkeypatch.setattr(nl_drafter, "_llm_factory", lambda: _Boom())

        async def _fake_safe(llm: Any, messages: Any, **_: Any) -> Any:
            return await llm.ainvoke(messages)

        import sys
        import types

        fake = types.ModuleType("app.llm")
        fake.safe_ainvoke = _fake_safe  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "app.llm", fake)

        result = asyncio.run(draft_from_nl("Notify the SOC", allow_llm=True))
        assert result.used_llm is False
        assert "notify" in _step_types(result.playbook)

    def test_no_llm_configured_uses_substrate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(nl_drafter, "_llm_factory", lambda: None)
        result = asyncio.run(draft_from_nl("Enrich the entity", allow_llm=True))
        assert result.used_llm is False
        assert "enrich" in _step_types(result.playbook)

    def test_allow_llm_false_skips_llm_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        called: dict[str, int] = {"n": 0}

        def _factory() -> Any:
            called["n"] += 1
            return _FakeLLMReturning(_Resp("{}"))

        monkeypatch.setattr(nl_drafter, "_llm_factory", _factory)
        result = asyncio.run(draft_from_nl("Notify the SOC", allow_llm=False))
        assert called["n"] == 0, "_llm_factory must not be consulted when allow_llm=False"
        assert result.used_llm is False


# ---------------------------------------------------------------------------
# Public draft_from_nl shape
# ---------------------------------------------------------------------------


class TestDraftFromNL:
    def test_returns_draft_result_dataclass(self) -> None:
        result = asyncio.run(draft_from_nl("Notify the SOC", allow_llm=False))
        assert isinstance(result, DraftResult)
        assert isinstance(result.playbook, Playbook)
        assert isinstance(result.rationale, str) and result.rationale
        assert isinstance(result.used_llm, bool)
        assert isinstance(result.schema_validated, bool)

    def test_rationale_mentions_step_types(self) -> None:
        result = asyncio.run(
            draft_from_nl(
                "Isolate the host, notify the SOC and create a ticket",
                allow_llm=False,
            )
        )
        for verb in ("isolate_host", "notify", "create_ticket"):
            assert verb in result.rationale

    def test_non_string_prompt_is_coerced(self) -> None:
        # The endpoint validates this, but draft_from_nl itself must not
        # crash on a non-string input (called directly by tests / CLI).
        result = asyncio.run(draft_from_nl(12345, allow_llm=False))  # type: ignore[arg-type]
        assert isinstance(result, DraftResult)
