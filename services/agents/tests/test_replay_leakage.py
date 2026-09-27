"""The test window must not be able to influence its own triage.

Gap-closure Phase 1.5, and the test the phase is really about. A replay report
whose test window fed itself is worse than no report: it is a number with a
method section that reads correctly and a result that is circular.

Four routes exist from a test-window decision back into a later test-window
decision, and they run through four different stores. Each gets its own test,
because "no leakage" failing as one assertion tells a future reader nothing
about which of them broke.

1. **Outcome memory.** Production writes every durable verdict back as a
   per-signature prior, and looks a prior up *before* triage. Two findings
   with the same canonical evidence therefore chain: the first alert's verdict
   auto-closes the second without re-triage. Under replay that is the
   evaluation answering its own next question.
2. **The cost governor's dedup cache.** Keyed on the same evidence
   fingerprint, and it short-circuits earlier still, returning the cached
   verdict as tier ``cached``. It leaves no ledger row and no memory prior, so
   the first two defences would both report clean while this one leaked.
3. **Organisation memory.** Compiled from analyst feedback and read into the
   triage prompt. Nothing in the test window writes a statement directly, but
   the read is live in production and a mid-run refresh picks up whatever the
   console wrote while the replay was running.
4. **Tenant skills** (Phase 6.1). Customer-authored guidance that reaches the
   same prompt, and the one store here whose rows are *written to influence
   verdicts on purpose*. A skill activated during the test window, or authored
   after it by somebody who read it, steers every later alert it matches.
   Unlike organisation memory these rows carry ``activated_at``, so the split
   filter has something to test and the freeze can be complete rather than
   partial.

   The deliberate bypass is tested here too, in its own test rather than as an
   exception buried in another. ``skills_under_test`` is how a backtest
   applies a candidate to a window that closed before it was written, and the
   property under test is not that it is refused, it is that the method note
   **names it and carries the caveat**. An unfiltered store nobody is told
   about is indistinguishable from a leak.

Every test here is checked for sensitivity
-------------------------------------------
A leakage test that passes because nothing happens is the most likely thing to
ship and the least useful. So each test also runs the *unprotected*
configuration and asserts it leaks. If a future change makes the leak
unreachable for some unrelated reason, the sensitivity half fails and says so,
rather than the whole file going quietly green over a property it no longer
tests.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from app.agents.dispositions import BENIGN, FALSE_POSITIVE, NEEDS_REVIEW, normalize_disposition
from app.context import organisation_memory
from app.context import tenant_skills as tenant_skills_module
from app.memory import outcomes as outcomes_module
from app.models.state import AgentStatus, InvestigationState
from app.replay.findings import HistoricalFinding
from app.replay.runner import ReplayRunner
from app.replay.shadow import ContextSnapshot, FrozenTriageContextReader, ShadowTriageWriter, capture_context
from app.workers import fused_alert_consumer as worker_module
from app.workers.fused_alert_consumer import FusedAlertTriageWorker
from app.workers.triage_persistence import LiveTriageContextReader

_SPLIT = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)

#: Two findings, different ids, identical evidence. `canonical_evidence`
#: excludes the row id and the raw payload, so both hash to one fingerprint,
#: which is exactly the condition every leak below needs.
_SHARED_EVIDENCE = {"search_name": "Repeated service logon", "src": "10.9.9.9", "host": "APPSRV-01"}


class _Normalizer:
    connector_id = "splunk"

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "source": "splunk",
            "title": raw.get("search_name"),
            "severity": "low",
            "src_ip": raw.get("src"),
            "hostname": raw.get("host"),
            "raw_event": raw,
        }


def _twin_findings() -> list[HistoricalFinding]:
    """Two test-window findings that share a fingerprint, closed an hour apart."""
    return [
        HistoricalFinding(
            vendor="splunk",
            finding_id=f"ES-TWIN-{index}",
            title="Repeated service logon",
            disposition=FALSE_POSITIVE,
            vendor_disposition="disposition:3",
            closed_at=_SPLIT + timedelta(hours=index + 1),
            rule_id="rule-service-logon",
            raw=dict(_SHARED_EVIDENCE),
        )
        for index in range(2)
    ]


def _history() -> list[HistoricalFinding]:
    """Enough train-window rows that a 70/30 split puts both twins in the test window."""
    train = [
        HistoricalFinding(
            vendor="splunk",
            finding_id=f"ES-OLD-{index:02d}",
            title="Historic finding",
            disposition=FALSE_POSITIVE,
            vendor_disposition="disposition:3",
            closed_at=_SPLIT - timedelta(days=index + 1),
            rule_id="rule-historic",
            raw={"search_name": "Historic finding", "host": f"OLD-{index:02d}"},
        )
        for index in range(5)
    ]
    return [*train, *_twin_findings()]


@dataclass
class _StubLlmConfig:
    """Just enough of ``LlmConfig`` for the worker to take the LLM branch."""

    allowed: bool = True
    api_key: str = "test-key"
    base_url: str = "http://gateway"
    model: str = "aisoc-triage"
    api_key_from_tenant: bool = False
    base_url_from_tenant: bool = False
    model_from_tenant: bool = False


# --------------------------------------------------------------------------
# 1. Outcome memory
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_verdict_in_the_test_window_never_becomes_a_prior_for_a_later_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AISOC_DETERMINISTIC", "1")
    runner = ReplayRunner(normalizer=_Normalizer(), tenant_id=str(uuid.uuid4()))

    run = await runner.run(_history())

    twins = [d for d in run.decisions if d.finding_id.startswith("ES-TWIN")]
    assert len(twins) == 2, "the split did not put both twins in the test window; the fixture is stale"
    # Neither is decided from memory, and in particular the second is not
    # decided from the first. `memory` is the tier the suppression path sets.
    assert [d.tier for d in twins] == ["deterministic", "deterministic"]
    # Production *would* have written the prior. That it tried is what proves
    # the leak was live and was refused, rather than never arising.
    assert run.writes_attempted.get("record_outcome", 0) >= 2


@pytest.mark.asyncio
async def test_the_same_run_leaks_through_memory_once_the_shadow_sinks_are_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sensitivity check: the protection above is protecting against something real.

    One stubbed model, one prior store, two configurations, everything else
    held constant. With the shadow writer and the frozen reader, four repeats
    of the same evidence are each triaged. Swap in the live reader and a writer
    that records, and the fourth is auto-closed from the first three's prior at
    tier ``memory``, without reaching triage at all.

    The verdict is stubbed at ``benign`` / 0.95 rather than lowering the
    corroboration thresholds, because those thresholds are what the leak needs
    to clear and a test that relaxes them is testing a configuration nobody
    runs. A confident benign on a repeat is what production's LLM tier
    produces on exactly this shape of alert.
    """
    monkeypatch.delenv("AISOC_DETERMINISTIC", raising=False)

    async def _confident_benign(state: InvestigationState) -> InvestigationState:
        state.verdict = BENIGN
        state.confidence = 0.95
        state.status = AgentStatus.COMPLETED
        return state

    async def _resolve(tenant_id: str) -> _StubLlmConfig:
        return _StubLlmConfig()

    monkeypatch.setattr(worker_module, "run_auto_triage", _confident_benign)
    monkeypatch.setattr(worker_module, "resolve_llm_config", _resolve)

    store: dict[str, dict[str, Any]] = {}

    async def _fake_record(tenant_id: str, signature: str, **kwargs: Any) -> dict[str, Any]:
        prior = {
            "signature": signature,
            # Normalised exactly as the real ``record_outcome`` does. A stub
            # that skipped this step would leave a disposition outside
            # ``AUTO_CLOSEABLE_DISPOSITIONS``, the leak would look unreachable,
            # and this whole file would disarm itself quietly.
            "disposition": normalize_disposition(kwargs["disposition"], default=NEEDS_REVIEW),
            "confidence": kwargs["confidence"],
            "author": kwargs["author"],
            "count": store.get(signature, {}).get("count", 0) + 1,
        }
        store[signature] = prior
        return prior

    async def _fake_lookup(tenant_id: str, signature: str) -> dict[str, Any] | None:
        return store.get(signature)

    monkeypatch.setattr(outcomes_module, "record_outcome", _fake_record)
    monkeypatch.setattr(outcomes_module, "lookup_prior", _fake_lookup)

    class _MemoryWritingShadow(ShadowTriageWriter):
        async def record_outcome(self, tenant_id: str, signature: str, **kwargs: Any) -> None:
            await outcomes_module.record_outcome(tenant_id, signature, **kwargs)

    protected = await _tiers_for_repeats(
        FusedAlertTriageWorker(
            bootstrap_servers="",
            writer=ShadowTriageWriter(),
            context_reader=FrozenTriageContextReader(ContextSnapshot(split_at=_SPLIT)),
        )
    )
    assert "memory" not in protected, protected

    store.clear()
    leaking = await _tiers_for_repeats(
        FusedAlertTriageWorker(
            bootstrap_servers="",
            writer=_MemoryWritingShadow(),
            context_reader=LiveTriageContextReader(),
        )
    )
    assert leaking[-1] == "memory", (
        "the last repeat was not suppressed from the earlier ones' prior, so the leak this "
        f"file guards against is no longer reachable and the guard above proves nothing: {leaking}"
    )


async def _tiers_for_repeats(worker: FusedAlertTriageWorker, repeats: int = 4) -> list[str]:
    """Triage the same evidence ``repeats`` times; return the tier each took."""
    tenant = str(uuid.uuid4())
    tiers: list[str] = []
    for index in range(repeats):
        summary = await worker.triage(
            {
                "id": f"ES-REPEAT-{index}",
                "alert_row_id": f"ES-REPEAT-{index}",
                "tenant_id": tenant,
                "alert": {
                    "id": f"ES-REPEAT-{index}",
                    "title": "Repeated service logon",
                    "rule_id": "rule-service-logon",
                    "severity": "low",
                    "src_ip": _SHARED_EVIDENCE["src"],
                    "hostname": _SHARED_EVIDENCE["host"],
                },
            }
        )
        assert summary is not None
        tiers.append(str(summary["tier"]))
    return tiers


# --------------------------------------------------------------------------
# 2. The cost governor's dedup cache
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_test_window_verdict_is_not_served_back_from_the_dedup_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The cache leaks without touching memory or the ledger, so it needs its own test."""
    monkeypatch.setenv("AISOC_DETERMINISTIC", "1")
    runner = ReplayRunner(normalizer=_Normalizer(), tenant_id=str(uuid.uuid4()))

    run = await runner.run(_history())

    assert "cached" not in {d.tier for d in run.decisions}
    # Declined rather than never reached: the worker asked the sink to cache
    # every verdict it produced.
    assert run.writes_attempted.get("cache_verdict", 0) == len(run.decisions)


# --------------------------------------------------------------------------
# 3. Organisation memory
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_triage_reads_the_frozen_statements_not_whatever_the_store_holds_now(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The statements that reach the prompt are the snapshot's, at the split.

    Organisation memory is only read on the LLM branch, so this drives that
    branch directly and captures what the agent was handed. Asserting on the
    prompt input rather than on the verdict is deliberate: a verdict can be
    unchanged by a leak that nonetheless happened, and the property under test
    is what the model was allowed to see.
    """
    captured: list[list[dict[str, Any]]] = []

    async def _capture(state: InvestigationState) -> InvestigationState:
        captured.append(list(state.organisation_memory or []))
        state.verdict = FALSE_POSITIVE
        state.confidence = 0.5
        state.status = AgentStatus.RUNNING
        return state

    async def _resolve(tenant_id: str) -> _StubLlmConfig:
        return _StubLlmConfig()

    async def _live_statements(tenant_id: str | None) -> list[dict[str, Any]]:
        return [{"statement": "POISON: written after the split", "observations": 99}]

    monkeypatch.delenv("AISOC_DETERMINISTIC", raising=False)
    monkeypatch.setattr(worker_module, "run_auto_triage", _capture)
    monkeypatch.setattr(worker_module, "resolve_llm_config", _resolve)
    monkeypatch.setattr(organisation_memory, "fetch_statements", _live_statements)

    frozen = capture_context(
        split_at=_SPLIT,
        statements=[{"statement": "Frozen at the split", "observations": 3, "updated_at": "2026-04-01T00:00:00Z"}],
    )
    worker = FusedAlertTriageWorker(
        bootstrap_servers="",
        writer=ShadowTriageWriter(),
        context_reader=FrozenTriageContextReader(frozen),
    )

    summary = await worker.triage(_envelope())

    assert summary is not None
    assert captured == [[{"statement": "Frozen at the split", "observations": 3, "updated_at": "2026-04-01T00:00:00Z"}]]

    # Sensitivity: the same worker with the live reader does see the poison.
    live_worker = FusedAlertTriageWorker(
        bootstrap_servers="",
        writer=ShadowTriageWriter(),
        context_reader=LiveTriageContextReader(),
    )
    captured.clear()
    await live_worker.triage(_envelope())
    assert captured == [[{"statement": "POISON: written after the split", "observations": 99}]]


def _envelope() -> dict[str, Any]:
    return {
        "id": "ES-PROMPT-1",
        "alert_row_id": "ES-PROMPT-1",
        "tenant_id": str(uuid.uuid4()),
        "alert": {
            "id": "ES-PROMPT-1",
            "title": "Repeated service logon",
            "rule_id": "rule-service-logon",
            "severity": "low",
            "hostname": "APPSRV-01",
        },
    }


# --------------------------------------------------------------------------
# 4. Tenant skills
# --------------------------------------------------------------------------


def _skill_row(skill_id: str, *, activated_at: str, guidance: str) -> dict[str, Any]:
    """One resolved-skill row in the shape the API's internal route serves."""
    return {
        "skill_id": skill_id,
        "version": 1,
        "activated_at": activated_at,
        "expires_at": "2099-01-01T00:00:00+00:00",
        "body": {
            "id": skill_id,
            "name": skill_id,
            "owner": "soc@example.com",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "match": {"rule_ids": ["rule-service-logon"], "techniques": [], "sources": [], "keywords": []},
            "guidance": guidance,
            "verdict_guidance": "",
            "required_evidence": [],
            "escalate_when": [],
            "plan": ["Check what executed on the host."],
            "expected_pivots": ["process_activity", "entity_timeline"],
            "min_pivots": 2,
        },
    }


@pytest.mark.asyncio
async def test_triage_reads_the_skills_frozen_at_the_split_not_whatever_is_active_now(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The skill that reaches the prompt is the snapshot's, at the split.

    Asserting on the prompt input rather than on the verdict, for the same
    reason the organisation-memory test does: a verdict can be unchanged by a
    leak that nonetheless happened, and the property under test is what the
    model was allowed to see.
    """
    captured: list[dict[str, Any] | None] = []

    async def _capture(state: InvestigationState) -> InvestigationState:
        captured.append(dict(state.tenant_skill) if state.tenant_skill else None)
        state.verdict = FALSE_POSITIVE
        state.confidence = 0.5
        state.status = AgentStatus.RUNNING
        return state

    async def _resolve(tenant_id: str) -> _StubLlmConfig:
        return _StubLlmConfig()

    async def _live_skills(tenant_id: str | None) -> list[dict[str, Any]]:
        return [_skill_row("poison-skill", activated_at="2026-06-01T00:00:00Z", guidance="POISON: activated after the split")]

    monkeypatch.delenv("AISOC_DETERMINISTIC", raising=False)
    monkeypatch.setattr(worker_module, "run_auto_triage", _capture)
    monkeypatch.setattr(worker_module, "resolve_llm_config", _resolve)
    monkeypatch.setattr(tenant_skills_module, "fetch_skills", _live_skills)
    tenant_skills_module.clear_cache()

    frozen = capture_context(
        split_at=_SPLIT,
        skills=[
            _skill_row("frozen-skill", activated_at="2026-04-01T00:00:00Z", guidance="Frozen at the split"),
            _skill_row("poison-skill", activated_at="2026-06-01T00:00:00Z", guidance="POISON: activated after the split"),
        ],
    )
    # The freeze did something, and the number says so rather than the absence
    # of a poisoned prompt implying it.
    assert frozen.dropped_skills == 1
    assert frozen.undated_skills == 0

    worker = FusedAlertTriageWorker(
        bootstrap_servers="",
        writer=ShadowTriageWriter(),
        context_reader=FrozenTriageContextReader(frozen),
    )
    summary = await worker.triage(_envelope())
    assert summary is not None

    assert len(captured) == 1 and captured[0] is not None
    assert captured[0]["skill_id"] == "frozen-skill"
    assert "Frozen at the split" in captured[0]["triage_guidance"]
    assert "POISON" not in captured[0]["triage_guidance"]

    # Sensitivity: the same worker with the live reader does see the poison.
    # Without this the test above passes just as well against a build where
    # skills never reach the prompt at all.
    live_worker = FusedAlertTriageWorker(
        bootstrap_servers="",
        writer=ShadowTriageWriter(),
        context_reader=LiveTriageContextReader(),
    )
    captured.clear()
    await live_worker.triage(_envelope())
    assert len(captured) == 1 and captured[0] is not None
    assert captured[0]["skill_id"] == "poison-skill"
    assert "POISON: activated after the split" in captured[0]["triage_guidance"]


@pytest.mark.asyncio
async def test_a_skill_under_test_reaches_the_prompt_and_is_named_in_the_method_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The backtest bypass works, and it is published rather than silent.

    Two assertions, and the second is the one that matters. A candidate
    authored after the window *must* reach the prompt or a backtest measures
    nothing. It must also appear in the method note with its caveat, because
    an accuracy figure produced by guidance written after the window is a
    statement about that window and not a forecast, and a reader who is not
    told cannot know which they are holding.
    """
    captured: list[dict[str, Any] | None] = []

    async def _capture(state: InvestigationState) -> InvestigationState:
        captured.append(dict(state.tenant_skill) if state.tenant_skill else None)
        state.verdict = FALSE_POSITIVE
        state.confidence = 0.5
        state.status = AgentStatus.RUNNING
        return state

    async def _resolve(tenant_id: str) -> _StubLlmConfig:
        return _StubLlmConfig()

    monkeypatch.delenv("AISOC_DETERMINISTIC", raising=False)
    monkeypatch.setattr(worker_module, "run_auto_triage", _capture)
    monkeypatch.setattr(worker_module, "resolve_llm_config", _resolve)

    candidate = _skill_row("candidate-skill", activated_at="2026-09-01T00:00:00Z", guidance="Authored after the window")
    snapshot = capture_context(split_at=_SPLIT, skills=[], skills_under_test=[candidate])

    # Not filtered, unlike everything else in the snapshot.
    assert snapshot.skills == ()
    assert snapshot.dropped_skills == 0
    assert [dict(s) for s in snapshot.skills_under_test] == [candidate]

    note = snapshot.as_method_note()
    assert note["skills_under_test"] == ["candidate-skill@v1"]
    assert "authored after this window closed" in note["skills_under_test_caveat"]
    assert "not a forecast" in note["skills_under_test_caveat"]

    worker = FusedAlertTriageWorker(
        bootstrap_servers="",
        writer=ShadowTriageWriter(),
        context_reader=FrozenTriageContextReader(snapshot),
    )
    await worker.triage(_envelope())
    assert len(captured) == 1 and captured[0] is not None
    assert captured[0]["ref"] == "candidate-skill@v1"

    # Sensitivity: an ordinary replay of the same instant freezes it out, so
    # the bypass is the backtest's and not the snapshot's default behaviour.
    ordinary = capture_context(split_at=_SPLIT, skills=[candidate])
    assert ordinary.skills == ()
    assert ordinary.dropped_skills == 1
    assert "skills_under_test" not in ordinary.as_method_note()


# --------------------------------------------------------------------------
# The snapshot itself
# --------------------------------------------------------------------------


def test_rows_recorded_after_the_split_are_dropped_from_the_snapshot() -> None:
    snapshot = capture_context(
        split_at=_SPLIT,
        statements=[
            {"statement": "before", "updated_at": "2026-04-01T00:00:00Z"},
            {"statement": "after", "updated_at": "2026-06-01T00:00:00Z"},
            {"statement": "undated"},
        ],
        priors={
            "sig-before": {"disposition": FALSE_POSITIVE, "last_seen": "2026-04-02T00:00:00Z"},
            "sig-after": {"disposition": FALSE_POSITIVE, "last_seen": "2026-06-02T00:00:00Z"},
        },
    )

    assert [s["statement"] for s in snapshot.statements] == ["before", "undated"]
    assert set(snapshot.priors) == {"sig-before"}
    assert snapshot.dropped_statements == 1
    assert snapshot.dropped_priors == 1
    # The one statement whose age could not be checked is counted, not hidden.
    # Organisation memory as the API serves it carries no creation time at
    # all, so this number is how a reader sees the limit of the freeze.
    assert snapshot.undated_statements == 1
    assert snapshot.as_method_note()["statements_without_timestamp"] == 1


def test_a_skill_with_no_activation_stamp_is_counted_the_way_an_undated_statement_is() -> None:
    """Kept, and counted, rather than dropped or silently trusted.

    A resolved skill carries ``activated_at`` by construction, so this should
    never fire in production. It is tested because "should be zero" is exactly
    how the organisation-memory gap went unnoticed for a phase: the number is
    published either way, so a reader sees the limit of the freeze instead of
    inferring it from a clean-looking block.
    """
    snapshot = capture_context(
        split_at=_SPLIT,
        skills=[
            {"skill_id": "dated", "version": 1, "activated_at": "2026-04-01T00:00:00Z", "body": {}},
            {"skill_id": "undated", "version": 1, "body": {}},
        ],
    )

    assert [s["skill_id"] for s in snapshot.skills] == ["dated", "undated"]
    assert snapshot.undated_skills == 1
    assert snapshot.dropped_skills == 0
    assert snapshot.as_method_note()["skills_without_timestamp"] == 1


def test_a_snapshot_taken_at_a_different_instant_is_refused() -> None:
    """A freeze from the wrong moment is not a freeze, and must not pass silently."""
    runner = ReplayRunner(normalizer=_Normalizer(), tenant_id=str(uuid.uuid4()))
    wrong = ContextSnapshot(split_at=_SPLIT + timedelta(days=30))

    with pytest.raises(ValueError, match="not a freeze"):
        import asyncio

        asyncio.run(runner.run(_history(), snapshot=wrong))
