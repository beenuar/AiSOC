"""
T2.2 — RouterOrchestrator.stream_kwargs() investigator-compatible adapter.

These tests pin the adapter that lets ``/investigate`` swap between
``InvestigatorOrchestrator.stream()`` and ``RouterOrchestrator.stream_kwargs()``
behind a feature flag without touching the endpoint. They cover:

* Signature parity with :meth:`InvestigatorOrchestrator.stream`.
* String → UUID coercion for ``case_id`` / ``tenant_id`` (deterministic
  via :func:`_coerce_uuid`, accepted as canonical UUID strings too).
* ``run_id`` honoured when caller supplies one; minted otherwise.
* Original caller strings preserved on every yielded event so
  realtime / ledger consumers can correlate against the inputs they
  already hold.
* ``step`` events enriched with the ``kind`` / ``node`` / ``ts``
  envelope fields the investigator stream carries.
* Failure mode: a router that ends in ``status=FAILED`` produces an
  out-of-band ``{"type": "error"}`` event, and the original ``done``
  is suppressed.
* Alert text actually lands on the internal :class:`InvestigationState`
  (regression guard for the field-name mismatch that bit on first cut).

Sub-agent runners are monkeypatched to deterministic shims — same
pattern as :mod:`tests.test_orchestrator_router_stream`.
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

import inspect  # noqa: E402

from app.investigator.orchestrator import InvestigatorOrchestrator  # noqa: E402
from app.models.state import AgentStatus, InvestigationState  # noqa: E402
from app.orchestrator.router import (  # noqa: E402
    _AISOC_ROUTER_NAMESPACE,
    RouterOrchestrator,
    _coerce_uuid,
)

SUBAGENT_SLEEP_MS = 5


# ---------------------------------------------------------------------------
# Fixtures — mirror test_orchestrator_router_stream._patch_runners
# ---------------------------------------------------------------------------


def _patch_runners(monkeypatch: pytest.MonkeyPatch, *, auto_close: bool = False) -> dict[str, list[str]]:
    call_log: dict[str, list[str]] = {
        "auto_triage": [],
        "phishing": [],
        "identity": [],
        "cloud": [],
        "insider": [],
    }

    async def fake_auto_triage(state: InvestigationState) -> InvestigationState:
        await asyncio.sleep(SUBAGENT_SLEEP_MS / 1000.0)
        state.iteration_count += 1
        state.status = AgentStatus.COMPLETED if auto_close else AgentStatus.RUNNING
        state.verdict = "benign" if auto_close else "true_positive"
        state.confidence = 0.95 if auto_close else 0.6
        state.confidence_basis = ["fake auto-triage rationale"]
        state.add_finding(f"Auto-triage (fake): verdict={state.verdict}")
        call_log["auto_triage"].append(str(state.incident_id))
        return state

    def _make_runner(name: str, technique: str):
        async def _runner(state: InvestigationState) -> InvestigationState:
            await asyncio.sleep(SUBAGENT_SLEEP_MS / 1000.0)
            state.add_finding(f"{name} (fake): triggered")
            if technique not in state.mitre_mappings:
                state.mitre_mappings.append(technique)
            state.verdict = "true_positive"
            state.confidence = max(state.confidence, 0.7)
            call_log[name].append(str(state.incident_id))
            return state

        return _runner

    targets: list[tuple[str, object]] = [
        ("app.agents.run_auto_triage", fake_auto_triage),
        ("app.agents.auto_triage_agent.run_auto_triage", fake_auto_triage),
        ("app.agents.run_phishing", _make_runner("phishing", "T1566.001")),
        (
            "app.agents.phishing_agent.run_phishing",
            _make_runner("phishing", "T1566.001"),
        ),
        ("app.agents.run_identity", _make_runner("identity", "T1078")),
        ("app.agents.identity_agent.run_identity", _make_runner("identity", "T1078")),
        ("app.agents.run_cloud", _make_runner("cloud", "T1078.004")),
        ("app.agents.cloud_agent.run_cloud", _make_runner("cloud", "T1078.004")),
        ("app.agents.run_insider_threat", _make_runner("insider", "T1567.002")),
        (
            "app.agents.insider_threat_agent.run_insider_threat",
            _make_runner("insider", "T1567.002"),
        ),
    ]
    for path, fn in targets:
        monkeypatch.setattr(path, fn, raising=False)

    return call_log


def _stub_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    """No-op ledger so streaming runs end-to-end without persistence."""
    import app.investigator.ledger as ledger_module

    async def _none(**_: Any) -> None:
        return None

    monkeypatch.setattr(ledger_module, "start_run", _none, raising=True)
    monkeypatch.setattr(ledger_module, "record_event", _none, raising=True)
    monkeypatch.setattr(ledger_module, "record_artifact", _none, raising=True)
    monkeypatch.setattr(ledger_module, "complete_run", _none, raising=True)


async def _collect(stream) -> list[dict[str, Any]]:
    return [event async for event in stream]


def _raw_alert() -> dict[str, Any]:
    """Trigger all four signal classes so the parallel topology fans out fully."""
    return {
        "sender": "compliance@trusted-partner.example",
        "subject": "Action required: contract renewal",
        "urls": ["https://contract-renewal[.]example/login"],
        "username": "alice@corp.example",
        "user_email": "alice@corp.example",
        "source_ip": "203.0.113.42",
        "auth_method": "saml",
        "mfa_status": "challenged",
        "cloud_provider": "aws",
        "region": "eu-west-1",
        "account_id": "111122223333",
        "principal_arn": "arn:aws:iam::111122223333:role/DataAnalyst",
        "data_volume_mb": 4096,
        "file_count": 871,
        "destination_domain": "attacker[.]example",
        "is_off_hours": True,
    }


# ---------------------------------------------------------------------------
# Signature & helper parity
# ---------------------------------------------------------------------------


def test_stream_kwargs_signature_matches_investigator() -> None:
    """Adapter must accept every parameter ``InvestigatorOrchestrator.stream`` accepts.

    The endpoint calls ``await orch.stream(case_id=..., alert_summary=...,
    raw_alert=..., tenant_id=..., run_id=...)``. If the parameter names
    drift, the feature-flag swap silently breaks. Pin them here.
    """
    inv_params = set(inspect.signature(InvestigatorOrchestrator.stream).parameters)
    inv_params.discard("self")
    router_params = set(inspect.signature(RouterOrchestrator.stream_kwargs).parameters)
    router_params.discard("self")

    # Adapter must cover every investigator param. Extras (``topology``) are fine.
    assert inv_params.issubset(router_params), f"missing params: {inv_params - router_params}"


def test_coerce_uuid_is_deterministic_across_calls() -> None:
    """Same opaque string must always hash to the same UUID — required so the
    ledger row and the realtime stream agree on the case id across processes."""
    first = _coerce_uuid("case-42")
    second = _coerce_uuid("case-42")
    assert first == second
    assert first == uuid.uuid5(_AISOC_ROUTER_NAMESPACE, "case-42")


def test_coerce_uuid_passes_through_real_uuid() -> None:
    real = uuid.uuid4()
    assert _coerce_uuid(real) is real
    assert _coerce_uuid(str(real)) == real


def test_coerce_uuid_differs_by_input() -> None:
    """Two distinct opaque strings must not collide."""
    assert _coerce_uuid("case-1") != _coerce_uuid("case-2")
    assert _coerce_uuid("default") != _coerce_uuid("tenant-a")


# ---------------------------------------------------------------------------
# Event-shape parity with InvestigatorOrchestrator
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step_events_carry_investigator_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every ``step`` event must carry case_id / run_id / kind / node / ts."""
    _patch_runners(monkeypatch)
    _stub_ledger(monkeypatch)

    run_id = uuid.uuid4()
    events = await _collect(
        RouterOrchestrator().stream_kwargs(
            case_id="case-stream-1",
            alert_summary="Spear-phish → OAuth → cloud creds",
            raw_alert=_raw_alert(),
            tenant_id="tenant-a",
            run_id=run_id,
            topology="parallel",
        )
    )

    steps = [e for e in events if e["type"] == "step"]
    assert steps, "expected step events"

    for ev in steps:
        # Caller-supplied strings are surfaced as-is, not the internal UUID.
        assert ev["case_id"] == "case-stream-1"
        # run_id is the supplied UUID, serialized.
        assert ev["run_id"] == str(run_id)
        # Envelope fields the WebSocket layer reads.
        assert "kind" in ev, f"missing kind: {ev}"
        assert ev["node"], f"missing node: {ev}"
        assert ev["ts"], f"missing ts: {ev}"
        # ts is ISO-formattable.
        assert "T" in ev["ts"], ev["ts"]


@pytest.mark.asyncio
async def test_done_event_preserves_caller_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    """``done`` must reference the caller's strings, not the coerced UUIDs."""
    _patch_runners(monkeypatch)
    _stub_ledger(monkeypatch)

    run_id = uuid.uuid4()
    events = await _collect(
        RouterOrchestrator().stream_kwargs(
            case_id="case-done-1",
            alert_summary="Trigger all four signals",
            raw_alert=_raw_alert(),
            tenant_id="default",
            run_id=run_id,
            topology="parallel",
        )
    )

    done = events[-1]
    assert done["type"] == "done"
    assert done["case_id"] == "case-done-1"
    assert done["run_id"] == str(run_id)
    # State payload still survives the adapter — the endpoint reads
    # report_md / report_html off this.
    inner = done["state"]
    assert inner["status"] == "completed"
    assert inner["report_md"], "report_md must be non-empty"
    assert inner["report_html"], "report_html must be non-empty"


@pytest.mark.asyncio
async def test_run_id_minted_when_not_supplied(monkeypatch: pytest.MonkeyPatch) -> None:
    """Adapter mints a fresh UUID for run_id when the caller omits it."""
    _patch_runners(monkeypatch)
    _stub_ledger(monkeypatch)

    events = await _collect(
        RouterOrchestrator().stream_kwargs(
            case_id="case-fresh",
            alert_summary="Trigger all four signals",
            raw_alert=_raw_alert(),
            topology="parallel",
        )
    )

    run_ids = {e["run_id"] for e in events if "run_id" in e}
    assert len(run_ids) == 1, "all events must share one run_id"
    (only,) = run_ids
    # Parses as a UUID, and is not the namespace itself (defensive).
    parsed = UUID(only)
    assert parsed != _AISOC_ROUTER_NAMESPACE


@pytest.mark.asyncio
async def test_canonical_uuid_string_passes_through_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller that already has UUIDs as strings shouldn't get them rehashed."""
    _patch_runners(monkeypatch)
    _stub_ledger(monkeypatch)

    case_uuid = uuid.uuid4()
    events = await _collect(
        RouterOrchestrator().stream_kwargs(
            case_id=str(case_uuid),
            alert_summary="Trigger all four signals",
            raw_alert=_raw_alert(),
            tenant_id=str(uuid.uuid4()),
            topology="parallel",
        )
    )

    # Round-trip: the case_id surfaced on every event matches the string
    # the caller passed in, not a hash of it.
    case_ids = {e["case_id"] for e in events if "case_id" in e}
    assert case_ids == {str(case_uuid)}


# ---------------------------------------------------------------------------
# Error synthesis
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_failed_done_is_translated_to_error_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the router reports ``status=FAILED`` inside ``done``, the adapter
    must emit an explicit ``{"type": "error"}`` event and suppress the done."""
    _stub_ledger(monkeypatch)

    async def _fake_stream(
        self: RouterOrchestrator,
        state: InvestigationState,
        *,
        topology: str | None = None,
    ):
        yield {
            "type": "step",
            "agent": "auto_triage",
            "summary": "auto-triage probing",
            "seq": 1,
            "state": {"status": "running"},
        }
        yield {
            "type": "done",
            "case_id": state.incident_id,
            "run_id": str(state.run_id),
            "state": {
                "status": AgentStatus.FAILED.value,
                "error": "ledger blew up",
            },
            "info": {"topology": topology or "parallel"},
        }

    monkeypatch.setattr(RouterOrchestrator, "stream", _fake_stream, raising=True)

    run_id = uuid.uuid4()
    events = await _collect(
        RouterOrchestrator().stream_kwargs(
            case_id="case-fail-1",
            alert_summary="something exploded",
            tenant_id="default",
            run_id=run_id,
            topology="parallel",
        )
    )

    types = [e["type"] for e in events]
    # Step survives, done is suppressed in favour of error.
    assert types == ["step", "error"], types

    err = events[-1]
    assert err["case_id"] == "case-fail-1"
    assert err["run_id"] == str(run_id)
    assert "ledger blew up" in err["error"]


@pytest.mark.asyncio
async def test_failed_error_event_carries_partial_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Synthesised error event must include the partial ``report_md`` /
    ``report_html`` / ``state`` snapshot the router assembled before the
    failure, so the UI can still render the in-progress narrative instead
    of losing every finding the sub-agents already produced."""
    _stub_ledger(monkeypatch)

    partial_md = "# Partial report\n\nauto_triage finding: suspicious"
    partial_html = "<h1>Partial report</h1><p>auto_triage finding: suspicious</p>"
    partial_state = {
        "status": AgentStatus.FAILED.value,
        "error": "phishing sub-agent crashed mid-fanout",
        "findings": ["auto_triage finding: suspicious"],
    }

    async def _fake_stream(
        self: RouterOrchestrator,
        state: InvestigationState,
        *,
        topology: str | None = None,
    ):
        yield {
            "type": "done",
            "case_id": state.incident_id,
            "run_id": str(state.run_id),
            "state": partial_state,
            "report_md": partial_md,
            "report_html": partial_html,
            "info": {"topology": "parallel"},
        }

    monkeypatch.setattr(RouterOrchestrator, "stream", _fake_stream, raising=True)

    events = await _collect(
        RouterOrchestrator().stream_kwargs(
            case_id="case-partial-1",
            alert_summary="partial fanout",
        )
    )

    assert [e["type"] for e in events] == ["error"]
    err = events[0]
    assert err["report_md"] == partial_md
    assert err["report_html"] == partial_html
    assert err["state"] == partial_state
    assert "phishing sub-agent crashed" in err["error"]


@pytest.mark.asyncio
async def test_failed_done_without_error_message_still_emits_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If FAILED state has no ``error`` field, the adapter still produces an
    error event with a sensible default — the endpoint must never see a
    silently-failed done."""
    _stub_ledger(monkeypatch)

    async def _fake_stream(
        self: RouterOrchestrator,
        state: InvestigationState,
        *,
        topology: str | None = None,
    ):
        yield {
            "type": "done",
            "case_id": state.incident_id,
            "run_id": str(state.run_id),
            "state": {"status": AgentStatus.FAILED.value},
            "info": {"topology": "parallel"},
        }

    monkeypatch.setattr(RouterOrchestrator, "stream", _fake_stream, raising=True)

    events = await _collect(
        RouterOrchestrator().stream_kwargs(
            case_id="case-fail-default",
            alert_summary="boom",
        )
    )

    assert [e["type"] for e in events] == ["error"]
    assert events[0]["error"], "must include a non-empty error message"


# ---------------------------------------------------------------------------
# Field-name regression — alert_summary lands on the state
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alert_summary_lands_on_internal_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression guard: the field is ``alert_summary``, not ``alert_text``.

    Pydantic silently drops unknown fields, so a typo here would leave
    the agents running against an empty alert. Verify the runner sees
    the real text.
    """
    seen: dict[str, str] = {}

    async def fake_auto_triage(state: InvestigationState) -> InvestigationState:
        seen["alert_summary"] = state.alert_summary
        state.status = AgentStatus.COMPLETED  # short-circuit to keep the test tight
        state.verdict = "benign"
        state.confidence = 0.99
        state.add_finding("auto-closed")
        return state

    monkeypatch.setattr("app.agents.run_auto_triage", fake_auto_triage, raising=False)
    monkeypatch.setattr(
        "app.agents.auto_triage_agent.run_auto_triage",
        fake_auto_triage,
        raising=False,
    )
    _stub_ledger(monkeypatch)

    expected = "Spear-phish → OAuth consent → cloud creds; impossible travel."
    await _collect(
        RouterOrchestrator().stream_kwargs(
            case_id="case-alert",
            alert_summary=expected,
            raw_alert={"sender": "x@y.example"},
            tenant_id="default",
        )
    )

    assert seen.get("alert_summary") == expected
