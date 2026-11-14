"""
Smoke tests for the four-agent public façade (T2.5 — v8.0).

Locks down the public contract we promise to buyers and to the docs site:

* exactly four branded agent classes are importable from
  ``app.agents``: ``DetectAgent``, ``TriageAgent``, ``HuntAgent``,
  ``RespondAgent``,
* each is instantiable / callable with the expected interface,
* sub-agents (phishing / identity / cloud / insider) are exposed only as
  capabilities of ``TriageAgent``, *not* as top-level public agents,
* deprecated back-compat aliases (``AutoTriageAgent``, ``PhishingAgent``,
  ``IdentityAgent``, ``CloudAgent``, ``InsiderThreatAgent``,
  ``ResponderAgent``) still resolve.

These tests deliberately avoid running real LLMs or HTTP calls — every
async path is exercised against monkeypatched runners so the suite stays
deterministic and offline-safe (CI gate per AISOC v8 progress doc).
"""

from __future__ import annotations

import asyncio
import inspect
import sys
from pathlib import Path
from uuid import uuid4

import pytest

# Match the path-mutation pattern used by the rest of services/agents/tests/.
_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app import agents as agents_pkg  # noqa: E402
from app.agents import (  # noqa: E402
    AutoTriageAgent,
    CloudAgent,
    DetectAgent,
    HuntAgent,
    IdentityAgent,
    InsiderThreatAgent,
    PhishingAgent,
    RespondAgent,
    ResponderAgent,
    TriageAgent,
)
from app.models.state import AgentStatus, InvestigationState  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _state() -> InvestigationState:
    return InvestigationState(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        alert_summary="Synthetic alert for façade smoke test",
        raw_alert={"severity": "medium", "risk_score": 0.5},
        status=AgentStatus.PENDING,
    )


# ---------------------------------------------------------------------------
# Public surface — exactly four branded agents
# ---------------------------------------------------------------------------


def test_exactly_four_branded_agents_exported() -> None:
    """The buyer-facing surface promises exactly four agent names.

    Anything more would dilute the rebrand; anything less would break the
    docs / hero-copy contract. The capability classes (PHISHING, IDENTITY,
    …) are *not* counted because they live in their own taxonomy.
    """
    branded = {"DetectAgent", "TriageAgent", "HuntAgent", "RespondAgent"}
    assert branded.issubset(set(agents_pkg.__all__))


@pytest.mark.parametrize(
    ("cls", "expected_name"),
    [
        (DetectAgent, "Detect"),
        (TriageAgent, "Triage"),
        (HuntAgent, "Hunt"),
        (RespondAgent, "Respond"),
    ],
)
def test_branded_agent_basics(cls: type, expected_name: str) -> None:
    """Each branded agent is instantiable and self-describes consistently."""
    instance = cls()
    assert isinstance(instance, cls)
    assert cls.name == expected_name

    described = cls.describe()
    assert isinstance(described, dict)
    assert described["name"] == expected_name
    assert described["description"]
    assert isinstance(described["capabilities"], list)
    assert isinstance(described["internal_modules"], list)
    assert described["internal_modules"], "internal_modules should be non-empty"


def test_triage_capabilities_are_not_top_level_agents() -> None:
    """Phishing/identity/cloud/insider must NOT appear as branded agents.

    They live as capabilities of TriageAgent. Promoting any of them would
    break the four-agent narrative.
    """
    branded = {"DetectAgent", "TriageAgent", "HuntAgent", "RespondAgent"}
    forbidden = {"PhishingAgent", "IdentityAgent", "CloudAgent", "InsiderThreatAgent"}

    # The forbidden names *exist* (they're back-compat aliases) but they
    # must not be in the branded set itself.
    assert branded.isdisjoint(forbidden)

    # And the package's "branded" set must only contain the four names.
    branded_in_pkg = {
        name for name in agents_pkg.__all__ if name.endswith("Agent") and name not in {"AutoTriageAgent", "ResponderAgent"} | forbidden
    }
    assert branded_in_pkg == branded


# ---------------------------------------------------------------------------
# TriageAgent — capabilities surface
# ---------------------------------------------------------------------------


def test_triage_capability_registry() -> None:
    assert set(TriageAgent.capabilities) == {"phishing", "identity", "cloud", "insider"}
    for name, cap in TriageAgent.capabilities.items():
        assert cap.name == name
        assert callable(cap)


@pytest.mark.asyncio
async def test_triage_auto_triage_delegates(monkeypatch: pytest.MonkeyPatch) -> None:
    """``TriageAgent.auto_triage`` must hit the real internal entry point."""
    called = {"flag": False}

    async def _fake_run_auto_triage(state: InvestigationState) -> InvestigationState:
        called["flag"] = True
        state.add_finding("fake auto triage")
        return state

    monkeypatch.setattr("app.agents.auto_triage_agent.run_auto_triage", _fake_run_auto_triage)
    monkeypatch.setattr("app.agents._run_auto_triage", _fake_run_auto_triage)

    result = await TriageAgent.auto_triage(_state())
    assert called["flag"] is True
    assert any("fake auto triage" in f for f in result.findings)


@pytest.mark.asyncio
async def test_triage_heuristic_delegates(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"flag": False}

    async def _fake_run_triage(state: InvestigationState) -> InvestigationState:
        called["flag"] = True
        return state

    monkeypatch.setattr("app.agents.triage_agent.run_triage", _fake_run_triage)
    monkeypatch.setattr("app.agents._run_triage", _fake_run_triage)

    await TriageAgent.heuristic_triage(_state())
    assert called["flag"] is True


@pytest.mark.asyncio
async def test_triage_capability_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each capability dispatches to its underlying ``run_*`` function."""
    flags = dict.fromkeys(("phishing", "identity", "cloud", "insider"), False)

    def _make_fake(name: str):
        async def _runner(state: InvestigationState) -> InvestigationState:
            flags[name] = True
            return state

        return _runner

    # Patch the bound runner inside each TriageCapability so analyse() picks
    # up the fake without needing to walk module attributes.
    for name in flags:
        TriageAgent.capabilities[name]._runner = _make_fake(name)

    for name in flags:
        await TriageAgent.analyse(_state(), capability=name)
    assert all(flags.values()), flags


def test_triage_analyse_unknown_capability_raises() -> None:
    with pytest.raises(KeyError):
        asyncio.run(TriageAgent.analyse(_state(), capability="nonsense"))


# ---------------------------------------------------------------------------
# HuntAgent — engine + NL surface
# ---------------------------------------------------------------------------


def test_hunt_engine_returns_engine_instance() -> None:
    from app.hunt import HuntEngine

    engine = HuntAgent.engine()
    assert isinstance(engine, HuntEngine)
    # Engine should be reusable / cap-configurable per call.
    capped = HuntAgent.engine(max_findings_per_run=7)
    assert isinstance(capped, HuntEngine)


def test_hunt_translate_returns_translated_query() -> None:
    from app.nl_query import TranslatedQuery

    result = HuntAgent.translate("show me failed logins from 10.0.0.1 in the last 2 hours")
    assert isinstance(result, TranslatedQuery)
    assert result.esql.strip()
    assert result.kql.strip()
    assert result.spl.strip()


def test_hunt_corpus_factory_with_explicit_dir(tmp_path: Path) -> None:
    """``HuntAgent.corpus(dir)`` should return a HuntCorpus rooted there."""
    from app.hunt import HuntCorpus

    corpus = HuntAgent.corpus(tmp_path)
    assert isinstance(corpus, HuntCorpus)
    assert corpus.directory == tmp_path
    # Empty directory loads cleanly to zero hunts.
    assert corpus.list() == []


# ---------------------------------------------------------------------------
# RespondAgent — plan delegation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_respond_plan_delegates(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, dict] = {}

    async def _fake_run_responder(state_dict: dict) -> dict:
        captured["state"] = state_dict
        return {**state_dict, "responder_called": True}

    monkeypatch.setattr(
        "app.investigator.responder_agent.run_responder",
        _fake_run_responder,
    )

    out = await RespondAgent.plan({"case_id": "INC-1"})
    assert captured["state"] == {"case_id": "INC-1"}
    assert out.get("responder_called") is True


@pytest.mark.asyncio
async def test_respond_call_is_callable(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_run_responder(state_dict: dict) -> dict:
        return {**state_dict, "ok": True}

    monkeypatch.setattr(
        "app.investigator.responder_agent.run_responder",
        _fake_run_responder,
    )

    instance = RespondAgent()
    out = await instance({"case_id": "INC-2"})
    assert out["ok"] is True


# ---------------------------------------------------------------------------
# DetectAgent — façade exists and self-describes (process is in flight)
# ---------------------------------------------------------------------------


def test_detect_agent_describe_lists_fusion_modules() -> None:
    described = DetectAgent.describe()
    assert "fusion" in described["capabilities"]
    assert any("fusion" in mod for mod in described["internal_modules"])


# ---------------------------------------------------------------------------
# Back-compat aliases
# ---------------------------------------------------------------------------


def test_back_compat_aliases_resolve() -> None:
    # Aliases remain importable so existing internal code paths don't break.
    assert AutoTriageAgent is not None
    assert ResponderAgent is not None
    assert PhishingAgent is not None
    assert IdentityAgent is not None
    assert CloudAgent is not None
    assert InsiderThreatAgent is not None


def test_back_compat_aliases_are_subclasses() -> None:
    """Old class names should still type-check against the new ones."""
    assert issubclass(AutoTriageAgent, TriageAgent)
    assert issubclass(ResponderAgent, RespondAgent)


@pytest.mark.parametrize(
    ("alias", "capability_name"),
    [
        (PhishingAgent, "phishing"),
        (IdentityAgent, "identity"),
        (CloudAgent, "cloud"),
        (InsiderThreatAgent, "insider"),
    ],
)
def test_capability_aliases_point_at_capability_registry(
    alias: type,
    capability_name: str,
) -> None:
    """Each capability alias must expose the matching :class:`TriageCapability`."""
    cap = alias.capability  # type: ignore[attr-defined]
    assert cap.name == capability_name
    assert cap is TriageAgent.capabilities[capability_name]


@pytest.mark.asyncio
async def test_capability_alias_run_dispatches(monkeypatch: pytest.MonkeyPatch) -> None:
    """``PhishingAgent.run(state)`` must still execute without errors."""
    called = {"flag": False}

    async def _fake(state: InvestigationState) -> InvestigationState:
        called["flag"] = True
        return state

    PhishingAgent.capability._runner = _fake

    await PhishingAgent.run(_state())
    assert called["flag"] is True


# ---------------------------------------------------------------------------
# Re-exported function entrypoints (orchestrator import safety)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "run_auto_triage",
        "run_triage",
        "run_phishing",
        "run_identity",
        "run_cloud",
        "run_insider_threat",
        "run_enrichment",
        "run_investigation",
    ],
)
def test_function_entrypoints_remain_async_callables(name: str) -> None:
    """Existing orchestrators import these helpers from ``app.agents``.

    Locking them down ensures the four-agent rebrand doesn't silently break
    the LangGraph node wiring elsewhere in the service.
    """
    fn = getattr(agents_pkg, name)
    assert callable(fn)
    assert inspect.iscoroutinefunction(fn)
