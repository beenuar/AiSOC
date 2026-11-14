"""Shadow mode must not write anything, and must be the production path.

Gap-closure Phase 1.2.

Two claims, and they need different kinds of evidence.

**"It writes nothing"** is proved against the *real* modules, not against
mocks of them. Every write function in the triage path is monkeypatched to
raise, and then a replay is run. A mock that records calls would pass while
the worker called something nobody thought to mock; a module that raises
cannot.

**"It is the production path"** cannot be proved by a test that constructs the
thing it is testing, so this file does not try. It pins the two properties that
make the claim checkable instead: the worker's default sinks are the live ones
(so a deployment passing neither argument gets production behaviour), and the
service entrypoint constructs the worker without overriding them. The second is
read off the source with ``ast`` rather than by importing ``main``, which pulls
in Kafka.
"""

from __future__ import annotations

import ast
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from app.investigator import ledger as ledger_module
from app.investigator import siem_writeback
from app.memory import outcomes as outcomes_module
from app.replay.findings import HistoricalFinding
from app.replay.runner import ReplayRunner
from app.replay.shadow import ContextSnapshot, FrozenTriageContextReader, ShadowTriageWriter
from app.workers import fused_alert_consumer as worker_module
from app.workers.fused_alert_consumer import FusedAlertTriageWorker
from app.workers.triage_persistence import (
    LiveTriageContextReader,
    LiveTriageWriter,
    TriageContextReader,
    TriageWriter,
)

_BASE = datetime(2026, 4, 1, 9, 0, tzinfo=UTC)


class _PassthroughNormalizer:
    """Stands in for a connector. Named so a reader does not mistake it for one.

    Replay refuses to normalize its own way, so the runner needs *some*
    object with ``normalize``. Using a stand-in here keeps this file about
    writes; ``test_replay_runner.py`` drives the real Splunk connector
    mapping.
    """

    connector_id = "splunk"

    def normalize(self, raw: dict) -> dict:
        return {
            "source": "splunk",
            "title": raw.get("search_name") or "Splunk Notable Event",
            "severity": "high",
            "src_ip": raw.get("src"),
            "hostname": raw.get("host"),
            "raw_event": raw,
        }


def _findings(count: int = 10) -> list[HistoricalFinding]:
    return [
        HistoricalFinding(
            vendor="splunk",
            finding_id=f"ES-{index:03d}",
            title="Suspicious PowerShell",
            disposition="true_positive" if index % 3 == 0 else "false_positive",
            vendor_disposition="disposition:1",
            closed_at=_BASE + timedelta(hours=index),
            rule_id="rule-powershell",
            raw={"search_name": "Suspicious PowerShell", "src": "10.1.2.3", "host": f"WS-{index:03d}"},
        )
        for index in range(count)
    ]


@pytest.fixture
def _every_write_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every durable write in the triage path fatal.

    ``BaseException`` on purpose. The worker wraps most of its writes in
    ``contextlib.suppress(Exception)`` or a fail-soft ``except Exception``,
    which is correct production behaviour and is exactly what would let a
    leaked write pass this test silently.
    """

    class WroteSomething(BaseException):
        pass

    def _refuse(name: str):
        async def _fail(*args: object, **kwargs: object):
            raise WroteSomething(f"shadow replay called {name}")

        return _fail

    monkeypatch.setattr(ledger_module, "persist_auto_triage", _refuse("ledger.persist_auto_triage"))
    monkeypatch.setattr(ledger_module, "raise_approval", _refuse("ledger.raise_approval"))
    monkeypatch.setattr(ledger_module, "record_suppression", _refuse("ledger.record_suppression"))
    monkeypatch.setattr(outcomes_module, "record_outcome", _refuse("outcomes.record_outcome"))
    monkeypatch.setattr(siem_writeback, "write_back_disposition", _refuse("siem_writeback.write_back_disposition"))


@pytest.mark.asyncio
async def test_a_replay_touches_no_write_path(_every_write_raises: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_DETERMINISTIC", "1")
    findings = _findings()
    runner = ReplayRunner(normalizer=_PassthroughNormalizer(), tenant_id=str(uuid.uuid4()))

    run = await runner.run(findings)

    assert run.decisions, "the replay produced no decisions, so it proved nothing"
    assert all(d.error is None for d in run.decisions), [d.error for d in run.decisions if d.error]


@pytest.mark.asyncio
async def test_the_writes_production_would_have_made_are_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero has to be a number the run reports, not an absence a reader infers.

    A replay that never reached the persistence branch and a replay whose
    persistence was suppressed both write nothing. Only the counter tells them
    apart, and without it this suite could go green over a runner that silently
    stopped replaying anything.
    """
    monkeypatch.setenv("AISOC_DETERMINISTIC", "1")
    runner = ReplayRunner(normalizer=_PassthroughNormalizer(), tenant_id=str(uuid.uuid4()))

    run = await runner.run(_findings())

    writer_methods = {
        "persist_auto_triage",
        "record_outcome",
        "record_suppression",
        "raise_approval",
        "write_back_disposition",
        "cache_verdict",
    }
    attempted = {name for name, count in run.writes_attempted.items() if count}
    # persist_auto_triage fires once per decision: production would have
    # written a ledger row and an alerts row for each. That it was *attempted*
    # is the proof the production path ran; that it was not *performed* is the
    # previous test.
    assert "persist_auto_triage" in attempted
    assert run.writes_attempted["persist_auto_triage"] == len(run.decisions)
    assert attempted <= writer_methods


@pytest.mark.asyncio
async def test_shadow_writer_implements_every_method_of_the_port() -> None:
    """A sink missing a method is a write that falls through to production.

    ``runtime_checkable`` protocols only check method *presence*, which is
    precisely the property that matters here: a method added to
    ``TriageWriter`` and not to the shadow implementation would raise
    ``AttributeError`` mid-replay, or worse, be reached on the live module.
    """
    assert isinstance(ShadowTriageWriter(), TriageWriter)
    assert isinstance(LiveTriageWriter(), TriageWriter)
    assert isinstance(LiveTriageContextReader(), TriageContextReader)


@pytest.mark.asyncio
async def test_a_worker_built_without_sinks_is_the_production_one() -> None:
    worker = FusedAlertTriageWorker(bootstrap_servers="")

    assert isinstance(worker._writer, LiveTriageWriter)
    assert isinstance(worker._reader, LiveTriageContextReader)
    assert worker._writer.escalation_allowed is True
    assert worker._writer.persists_cost is True


def test_the_service_entrypoint_does_not_override_the_sinks() -> None:
    """The deployed worker must be the default-sink one.

    Read off the source rather than imported: ``app.main`` imports aiokafka
    and the service's whole startup graph, and a test that has to boot the
    service to check a constructor argument will be deleted the first time it
    is slow.
    """
    source = Path(__file__).resolve().parents[1] / "app" / "main.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))

    constructions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "FusedAlertTriageWorker"
    ]
    assert constructions, "app/main.py no longer constructs FusedAlertTriageWorker; this test is stale"
    for call in constructions:
        passed = {kw.arg for kw in call.keywords}
        assert "writer" not in passed, "the deployed worker must use the live writer"
        assert "context_reader" not in passed, "the deployed worker must use the live reader"


@pytest.mark.asyncio
async def test_escalation_cannot_change_the_graded_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shadow mode declines escalation, and that must not move the number.

    ``ShadowTriageWriter.escalation_allowed`` is ``False`` because every node
    of the investigation graph records itself to the ledger. That is only
    sound if the verdict ``triage()`` returns is fixed before escalation runs.
    This drives the real worker with escalation forced on and a graph runner
    that rewrites the verdict, and asserts the returned summary is unmoved.
    """
    monkeypatch.setenv("AISOC_DETERMINISTIC", "1")
    monkeypatch.setenv("AISOC_AGENT_ESCALATE_TO_GRAPH", "1")

    async def _hostile_escalation(state, **kwargs: object):
        state.verdict = "escalation_rewrote_this"
        state.confidence = 0.01
        return state

    async def _no_bundle(**kwargs: object) -> dict:
        return {}

    monkeypatch.setattr(worker_module, "run_escalation", _hostile_escalation)
    monkeypatch.setattr(worker_module, "prefetch_context_bundle_dict", _no_bundle)

    class _EscalatingWriter(ShadowTriageWriter):
        @property
        def escalation_allowed(self) -> bool:
            return True

    worker = FusedAlertTriageWorker(
        bootstrap_servers="",
        writer=_EscalatingWriter(),
        context_reader=FrozenTriageContextReader(ContextSnapshot(split_at=_BASE)),
    )
    envelope = {
        "id": "ES-001",
        "alert_row_id": "ES-001",
        "tenant_id": str(uuid.uuid4()),
        "alert": {"id": "ES-001", "title": "Ransomware detected", "severity": "critical", "hostname": "WS-001"},
    }

    summary = await worker.triage(envelope)

    assert summary is not None
    assert summary["verdict"] != "escalation_rewrote_this"


def _frozen_reader():
    from app.replay.shadow import FrozenTriageContextReader

    return FrozenTriageContextReader(ContextSnapshot(split_at=_BASE))
