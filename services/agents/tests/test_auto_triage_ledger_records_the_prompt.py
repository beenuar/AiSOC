"""Auto-triage records what it asked the model, not only what it decided.

Issue #1276. The launch claim is that investigations are replayable "with
prompts, tool calls and evidence captured", and the MCP tool
``aisoc_explain_step`` is documented as returning "the prompt, response,
and tools used". Both held on the manual path and neither held on the one
that handles every fused alert.

Three concrete gaps, all reproduced below:

* ``run_auto_triage`` discarded the prompt. ``log_llm_prompt`` exists and
  works, but its four callers are all manual agents — no worker called it,
  so the most common AI decision in the platform left nothing to replay.
* ``persist_auto_triage``'s hardcoded ``INSERT`` named neither
  ``input_hash`` nor ``output_hash``, so both landed NULL, and
  ``duration_ms`` was the literal ``0``.
* ``graph/runner.py`` called ``record_event`` without a duration, so every
  ``graph_step`` row also reported zero.

A zero duration and a null hash are not missing data in the harmless
sense: they read as measurements. "This step took no time" is a claim.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import pytest
from app.models.state import InvestigationState


def _state() -> InvestigationState:
    return InvestigationState(incident_id=uuid4(), tenant_id=uuid4())


class TestTheExchangeIsRecorded:
    def test_a_model_call_leaves_a_replayable_record(self) -> None:
        state = _state()
        state.record_llm_exchange(
            agent="auto_triage",
            purpose="triage.classify",
            model="llama3.2:3b",
            prompt=[{"role": "system", "content": "classify this"}],
            response='{"verdict": "false_positive"}',
            duration_ms=1234,
        )

        assert len(state.llm_exchanges) == 1
        recorded = state.llm_exchanges[0]
        assert "classify this" in recorded["prompt"]
        assert recorded["response"] == '{"verdict": "false_positive"}'
        assert recorded["duration_ms"] == 1234
        assert recorded["model"] == "llama3.2:3b"

    def test_both_hashes_are_present_and_differ(self) -> None:
        """The two NULL columns from the report, from the other end."""
        state = _state()
        recorded = state.record_llm_exchange(
            agent="auto_triage",
            purpose="triage.classify",
            model=None,
            prompt="ask",
            response="answer",
            duration_ms=1,
        )

        assert len(recorded["input_hash"]) == 64
        assert len(recorded["output_hash"]) == 64
        assert recorded["input_hash"] != recorded["output_hash"]

    def test_the_hash_covers_the_whole_prompt_not_the_truncated_copy(self) -> None:
        """The convention the manual path uses, and the reason for it: the
        literal is bounded because it carries customer data, so a hash over
        the bounded copy would verify the wrong thing."""
        long_prompt = "x" * 9000
        a = _state().record_llm_exchange(agent="a", purpose="p", model=None, prompt=long_prompt, response="r", duration_ms=0)
        b = _state().record_llm_exchange(agent="a", purpose="p", model=None, prompt=long_prompt + "DIFFERENT", response="r", duration_ms=0)

        assert a["prompt"] == b["prompt"], "both literals truncate to the same 8000 chars"
        assert a["input_hash"] != b["input_hash"], "the hashes must still tell them apart"
        assert a["prompt_truncated"] is True

    def test_a_run_that_called_no_model_records_nothing(self) -> None:
        """The deterministic path must stay distinguishable from a model
        call whose prompt went missing. An empty list is the honest value."""
        assert _state().llm_exchanges == []

    def test_the_record_survives_serialisation_through_the_graph(self) -> None:
        """LangGraph round-trips the state as a dict."""
        state = _state()
        state.record_llm_exchange(agent="auto_triage", purpose="p", model=None, prompt="ask", response="answer", duration_ms=5)
        assert state.to_dict()["llm_exchanges"][0]["response"] == "answer"


class TestTheWorkerPathActuallyCallsIt:
    """The mechanism existing is not the claim. ``log_llm_prompt`` existed,
    worked and was unit-tested the whole time — and its four callers were
    all manual agents, so nothing on the path that handles every fused
    alert ever reached it. Drive the real ``run_auto_triage``."""

    @pytest.mark.asyncio
    async def test_a_real_triage_run_records_its_prompt(self, monkeypatch: Any) -> None:
        from types import SimpleNamespace

        from app.agents import auto_triage_agent as ata

        payload = json.dumps({"verdict": "false_positive", "confidence": 0.93, "rationale": "scanner"})
        seen: list[Any] = []

        async def _fake_ainvoke(_llm: Any, messages: Any) -> Any:
            seen.append(messages)
            return SimpleNamespace(content=payload)

        monkeypatch.setattr(ata, "make_chat_model", lambda *a, **k: object())
        monkeypatch.setattr(ata, "safe_ainvoke", _fake_ainvoke)

        state = InvestigationState(
            incident_id=uuid4(),
            tenant_id=uuid4(),
            alert_summary="Port scan from 10.0.0.5",
            raw_alert={"severity": "medium", "hostname": "WEB-01"},
        )
        out = await ata.run_auto_triage(state)

        assert out.verdict == "false_positive"
        assert len(out.llm_exchanges) == 1, "the verdict was reached with no recorded prompt"

        recorded = out.llm_exchanges[0]
        # What was recorded is what was sent, not a reconstruction of it.
        sent = json.dumps([{"role": m.type, "content": m.content} for m in seen[0]], default=str)
        assert "WEB-01" in recorded["prompt"], "the alert context is missing from the record"
        assert "WEB-01" in sent
        assert recorded["response"] == payload
        assert recorded["duration_ms"] >= 0
        assert len(recorded["input_hash"]) == 64

    @pytest.mark.asyncio
    async def test_a_response_that_fails_to_parse_still_leaves_a_record(self, monkeypatch: Any) -> None:
        """The case where a transcript is worth most: a parse failure whose
        message is a character offset into text nobody kept."""
        from types import SimpleNamespace

        from app.agents import auto_triage_agent as ata

        async def _fake_ainvoke(_llm: Any, _messages: Any) -> Any:
            return SimpleNamespace(content="not json at all")

        monkeypatch.setattr(ata, "make_chat_model", lambda *a, **k: object())
        monkeypatch.setattr(ata, "safe_ainvoke", _fake_ainvoke)

        state = InvestigationState(incident_id=uuid4(), tenant_id=uuid4(), alert_summary="x")
        try:
            await ata.run_auto_triage(state)
        except Exception:
            # Swallowed on purpose: the subject here is what the agent
            # *recorded* before the unparseable reply took it down, asserted
            # below. Whether it raises or falls back is a different question
            # and a different test; letting either outcome through keeps this
            # one from failing for a reason it is not about.
            pass

        assert state.llm_exchanges, "nothing recorded for the call that failed to parse"
        assert state.llm_exchanges[0]["response"] == "not json at all"


class TestTheLedgerWritesIt:
    """Drives the real ``persist_auto_triage`` against a connection that
    records what it was asked to execute. The assertion is on the SQL and
    the bound parameters, because the defect *was* the column list — a
    double that accepted any INSERT would reproduce the bug happily."""

    @staticmethod
    async def _run(exchanges: list[dict[str, Any]] | None) -> list[tuple[str, tuple]]:
        from app.investigator import ledger as ledger_module

        executed: list[tuple[str, tuple]] = []
        tenant = uuid4()

        class _Conn:
            async def execute(self, sql: str, *args: Any) -> str:
                executed.append((sql, args))
                return "INSERT 0 1"

            async def fetchval(self, *_a: Any, **_k: Any) -> Any:
                return tenant

            def transaction(self) -> Any:
                return _Txn()

        class _Txn:
            async def __aenter__(self) -> None:
                return None

            async def __aexit__(self, *_a: Any) -> bool:
                return False

        class _Acquire:
            async def __aenter__(self) -> _Conn:
                return _Conn()

            async def __aexit__(self, *_a: Any) -> bool:
                return False

        class _Pool:
            def acquire(self) -> _Acquire:
                return _Acquire()

        async def _pool() -> _Pool:
            return _Pool()

        async def _resolve(_conn: Any, _ref: str) -> Any:
            return tenant

        # Through `MonkeyPatch` rather than a hand-rolled save/assign/restore.
        # Assigning the module attribute directly is a rebind CodeQL can see,
        # and it makes `py/import-of-mutable-attribute` fire on
        # `test_ledger_tenant.py`, which imports `_resolve_tenant_id` by value
        # and would therefore keep the original — a real hazard, just not one
        # this test was trying to create.
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(ledger_module, "get_pool", _pool)
            mp.setattr(ledger_module, "_resolve_tenant_id", _resolve)
            await ledger_module.persist_auto_triage(
                run_id=uuid4(),
                alert_id=str(uuid4()),
                tenant_ref=str(tenant),
                alert_summary="s",
                raw_alert={},
                tier="L1",
                verdict="false_positive",
                confidence=0.9,
                rationale="because",
                llm_exchanges=exchanges,
            )
        return executed

    @pytest.mark.asyncio
    async def test_the_verdict_insert_names_both_hash_columns(self) -> None:
        executed = await self._run([])
        verdict_sql = [s for s, _ in executed if "triage_verdict" in s]
        assert verdict_sql, "no verdict row was written"
        assert "input_hash" in verdict_sql[0]
        assert "output_hash" in verdict_sql[0]

    @pytest.mark.asyncio
    async def test_the_verdict_no_longer_hardcodes_a_zero_duration(self) -> None:
        executed = await self._run([])
        verdict_sql = [s for s, _ in executed if "triage_verdict" in s][0]
        # The original literal was `..., $6::jsonb, 0, now())`.
        assert ", 0, now())" not in verdict_sql

    @pytest.mark.asyncio
    async def test_the_prompt_is_written_as_its_own_step(self) -> None:
        exchange = {
            "agent": "auto_triage",
            "purpose": "triage.classify",
            "prompt": "the literal prompt",
            "response": "the literal response",
            "input_hash": "a" * 64,
            "output_hash": "b" * 64,
            "duration_ms": 742,
        }
        executed = await self._run([exchange])

        llm_steps = [(s, a) for s, a in executed if "'llm_call'" in s]
        assert len(llm_steps) == 1, "the model call left no step of its own"
        sql, args = llm_steps[0]
        assert ", 0, now()," in sql or " 0, now(), 'llm_call'" in sql, "the prompt must precede the verdict"
        assert "a" * 64 in args
        assert "b" * 64 in args
        assert 742 in args
        assert any("the literal prompt" in json.dumps(a) for a in args if isinstance(a, str))

    @pytest.mark.asyncio
    async def test_the_transcript_is_attached_for_explain_step(self) -> None:
        """`/investigations/{run}/explain` inlines the artifacts of the
        focal event, which is how `aisoc_explain_step` returns a literal
        transcript rather than a hash."""
        executed = await self._run(
            [
                {
                    "prompt": "the literal prompt",
                    "response": "the literal response",
                    "input_hash": "a" * 64,
                    "output_hash": "b" * 64,
                    "duration_ms": 1,
                }
            ]
        )

        artifacts = [a for s, a in executed if "investigation_artifacts" in s]
        kinds = {a[4] for a in artifacts}
        assert kinds == {"llm_prompt", "llm_response"}
        assert any("the literal prompt" in str(a) for a in artifacts[0])

    @pytest.mark.asyncio
    async def test_a_run_with_no_model_call_writes_no_transcript(self) -> None:
        """No invented artifact for the deterministic path."""
        executed = await self._run([])
        assert [s for s, _ in executed if "investigation_artifacts" in s] == []
        assert [s for s, _ in executed if "'llm_call'" in s] == []


class TestReplayDoesNotDuplicateTheTranscript:
    def test_a_suppressed_insert_is_detected(self) -> None:
        """`investigation_artifacts` has no key to conflict on, so the
        artifact write is gated on whether the verdict row was new. The
        run id is deterministic, so this path is taken on every replay."""
        from app.investigator.ledger import _inserted_a_row

        assert _inserted_a_row("INSERT 0 1") is True
        assert _inserted_a_row("INSERT 0 0") is False

    def test_an_unreadable_tag_writes_nothing(self) -> None:
        """A missing transcript is visibly missing; a duplicated one
        silently doubles on every replay."""
        from app.investigator.ledger import _inserted_a_row

        assert _inserted_a_row(None) is False
        assert _inserted_a_row("weird") is False


class TestGraphStepsCarryTheirDuration:
    """`record_event` defaults ``duration_ms`` to 0 and the call site never
    passed it, so every escalation step recorded as instantaneous. Driven
    through the real ``_run`` against a graph that takes measurable time —
    reading the source would pass on a call that passes a literal zero."""

    @pytest.mark.asyncio
    async def test_a_step_that_took_time_does_not_record_zero(self, monkeypatch: Any) -> None:
        import asyncio

        from app.graph import runner as runner_mod

        recorded: list[dict[str, Any]] = []

        async def _record_event(**kwargs: Any) -> None:
            recorded.append(kwargs)

        async def _resolve(_ref: str) -> Any:
            return uuid4()

        async def _start_run(**_kwargs: Any) -> Any:
            return uuid4()

        monkeypatch.setattr(runner_mod.ledger_module, "record_event", _record_event)
        monkeypatch.setattr(runner_mod.ledger_module, "resolve_tenant", _resolve)
        monkeypatch.setattr(runner_mod.ledger_module, "start_run", _start_run)

        class _Graph:
            async def astream(self, _state: dict[str, Any]) -> Any:
                await asyncio.sleep(0.05)
                yield {"triage": {}}
                await asyncio.sleep(0.05)
                yield {"respond": {}}

        await runner_mod._run(
            _Graph(),
            _state(),
            budget=runner_mod.default_budget(),
            persist=True,
            seq_start=1,
        )

        steps = [e for e in recorded if e.get("kind") == "graph_step"]
        assert len(steps) == 2, f"expected two graph steps, got {len(steps)}"
        assert all(s["duration_ms"] > 0 for s in steps), [s["duration_ms"] for s in steps]
