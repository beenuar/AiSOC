"""A manual investigation must reach a terminal status (issue #1242).

The auto-triage path has had a wall-clock budget since issue #569:
``app.graph.runner._run`` wraps the graph in ``asyncio.timeout(budget.max_seconds)``
and logs ``investigation.budget_timeout``. The console's path is a different
one — ``POST /api/v1/cases/{id}/investigate`` reaches
:func:`app.api.investigate.launch_investigation`, which writes
``status: "running"`` and hands :func:`app.api.investigate._run_and_store` to
``BackgroundTasks`` — and it had no deadline at all. ``_run_and_store`` wrote a
terminal status only on a ``done`` event, an ``error`` event, or a raised
exception, so a model that merely answers slowly (``ChatOpenAI`` is built with
no timeout) left both the in-memory run entry and the ``investigation_runs``
row at ``running`` forever.

Three properties are pinned here, because the fix is wrong if any one is
missing:

**The deadline exists.** A stream that never completes must still end in a
terminal status, not hang until the process dies.

**It is the same budget, not a second one.** Two constants describing one
deadline is a shape this repository has already been bitten by, so the value
comes from ``app.graph.runner.default_budget()`` — i.e. the single
``AISOC_INVESTIGATION_MAX_SECONDS`` knob the auto-triage path reads.

**It reaches the database.** The console polls the API for the run entry but
the Investigation Ledger renders ``investigation_runs``. A timeout that only
updates the process dict leaves the ledger showing a run that never ends.
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.api import investigate as investigate_mod  # noqa: E402

#: The budget the tests drive the code with. Short enough that a wall-clock
#: assertion is cheap, long enough that it is clearly a deadline firing rather
#: than the coroutine never having started.
_TEST_BUDGET_SECONDS = 0.25

#: How long the test itself is willing to wait. Comfortably above the budget,
#: so a failure here means "no deadline fired", never "the runner was slow".
_TEST_PATIENCE_SECONDS = 15.0

#: Terminal statuses the console already renders. ``CaseWorkspace.tsx`` branches
#: on ``idle``/``starting``/``running``/``failed``/``completed`` and the
#: WebSocket tail in ``investigate.py`` breaks on ``completed``/``failed``, so a
#: new vocabulary word here would be a run that no surface can finish.
_TERMINAL = {"completed", "failed"}


class _HungStream:
    """A stream that starts, emits one step, and then never completes.

    This is the shape of the defect: not an exception and not an empty
    generator, but a model call that is still outstanding. ``_run_and_store``
    treats everything short of ``done``/``error`` as progress.
    """

    def __init__(self) -> None:
        self.cancelled = False

    async def __call__(self, **_kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        yield {"type": "step", "kind": "llm_request", "agent": "recon", "summary": "asking the model"}
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        yield {"type": "done", "state": {}}  # pragma: no cover — unreachable


@pytest.fixture
def hung_stream(monkeypatch: pytest.MonkeyPatch) -> _HungStream:
    """Replace the orchestrator stream with one that never finishes."""
    stream = _HungStream()
    monkeypatch.setattr(investigate_mod, "_investigate_stream", stream, raising=True)
    # The realtime fan-out is a best-effort HTTP POST; keep the test off the
    # network so a 2s connect timeout per step cannot be mistaken for the
    # deadline under test.
    monkeypatch.setattr(investigate_mod, "_emit_event", _noop_emit, raising=True)
    return stream


async def _noop_emit(*_args: Any, **_kwargs: Any) -> None:
    return None


@pytest.fixture
def budget(monkeypatch: pytest.MonkeyPatch) -> float:
    monkeypatch.setenv("AISOC_INVESTIGATION_MAX_SECONDS", str(_TEST_BUDGET_SECONDS))
    return _TEST_BUDGET_SECONDS


@pytest.fixture
def run_entry(monkeypatch: pytest.MonkeyPatch) -> tuple[str, dict[str, Any]]:
    """Seed ``_runs`` exactly as ``launch_investigation`` does, isolated."""
    runs: dict[str, dict[str, Any]] = {}
    monkeypatch.setattr(investigate_mod, "_runs", runs, raising=True)
    run_id = str(uuid4())
    runs[run_id] = {"run_id": run_id, "case_id": "case-1242", "status": "running"}
    return run_id, runs[run_id]


async def _drive(run_id: str) -> None:
    """Run the background task the endpoint schedules, under the test's patience."""
    req = investigate_mod.InvestigateRequest(
        alert_summary="Impossible travel on a privileged account",
        raw_alert={"user": "svc-deploy"},
        tenant_id="default",
    )
    try:
        await asyncio.wait_for(
            investigate_mod._run_and_store(run_id, "case-1242", req),
            timeout=_TEST_PATIENCE_SECONDS,
        )
    except TimeoutError:
        pytest.fail(
            f"_run_and_store did not return within {_TEST_PATIENCE_SECONDS}s against a stream that "
            f"never completes, with AISOC_INVESTIGATION_MAX_SECONDS={_TEST_BUDGET_SECONDS}. "
            "The manual investigation path has no wall-clock deadline, so the run stays 'running' "
            "forever and the console shows a spinner that never resolves (issue #1242)."
        )


@pytest.mark.asyncio
async def test_hung_stream_still_reaches_a_terminal_status(
    budget: float,
    hung_stream: _HungStream,
    run_entry: tuple[str, dict[str, Any]],
) -> None:
    run_id, entry = run_entry

    await _drive(run_id)

    assert entry["status"] in _TERMINAL, (
        f"run ended at status {entry['status']!r}; the console only renders {sorted(_TERMINAL)} as finished states"
    )
    assert entry.get("error"), "a run that timed out must say so, not finish silently"
    assert hung_stream.cancelled, "the outstanding model call must be cancelled, not left running"


@pytest.mark.asyncio
async def test_deadline_is_the_shared_budget_not_a_second_constant(
    budget: float,
    hung_stream: _HungStream,
    run_entry: tuple[str, dict[str, Any]],
) -> None:
    """``AISOC_INVESTIGATION_MAX_SECONDS`` is the only knob, on both paths.

    Asserted through the env var rather than by reading a module attribute:
    a second hardcoded number would satisfy an attribute check and still
    ignore the operator's setting.
    """
    run_id, entry = run_entry

    loop = asyncio.get_running_loop()
    started = loop.time()
    await _drive(run_id)
    elapsed = loop.time() - started

    assert elapsed < _TEST_PATIENCE_SECONDS / 2, (
        f"run took {elapsed:.1f}s against a {budget}s budget — the deadline is not reading AISOC_INVESTIGATION_MAX_SECONDS"
    )
    assert str(budget) in str(entry.get("error", "")), (
        f"the failure message {entry.get('error')!r} does not quote the configured budget "
        f"({budget}s), so an operator cannot tell which deadline fired"
    )


@pytest.mark.asyncio
async def test_timeout_writes_the_terminal_status_to_the_ledger_row(
    budget: float,
    hung_stream: _HungStream,
    run_entry: tuple[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ``investigation_runs`` row must finish too, not just the process dict.

    ``InvestigationLedger.tsx`` renders that row. ``complete_run`` fires from
    the orchestrator's ``done`` and ``except`` arms only, and neither runs when
    the task is cancelled from outside — ``CancelledError`` is a
    ``BaseException``, so the orchestrator's ``except Exception`` does not see
    it.
    """
    run_id, _entry = run_entry
    completions: list[dict[str, Any]] = []
    tenant_uuid = uuid4()

    async def _fake_resolve_tenant(tenant_ref: str) -> UUID:
        assert tenant_ref == "default"
        return tenant_uuid

    async def _fake_complete_run(**kwargs: Any) -> None:
        completions.append(kwargs)

    monkeypatch.setattr(investigate_mod.ledger, "resolve_tenant", _fake_resolve_tenant, raising=True)
    monkeypatch.setattr(investigate_mod.ledger, "complete_run", _fake_complete_run, raising=True)

    await _drive(run_id)

    assert completions, (
        "no ledger write on timeout — investigation_runs.status stays 'running' and the Investigation Ledger shows a run that never ends"
    )
    (call,) = completions
    assert call["status"] == "failed", f"ledger row closed as {call['status']!r}"
    assert call["tenant_id"] == tenant_uuid
    assert str(call["run_id"]) == run_id, "the ledger row closed must be the one the endpoint opened"
    assert call.get("error"), "the ledger row must carry the reason"
