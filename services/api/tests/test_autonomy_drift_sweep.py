"""The drift sweep exists, is started, and is on by default.

Fix pass item 3.7. See ``plans/aisoc_fix_pass_plan.plan.md``.

``reconcile_grants`` shipped with one production caller, the handler behind
``GET /api/v1/autonomy-policy/grants``, so a grant whose evidence had
collapsed stayed ``granted`` until somebody opened that page. The sweep is the
caller that needs no human.

What it demotes, and what it leaves alone, is proven against a real Postgres
in ``tests/isolation/test_autonomy_promotion_live.py``: the aggregate and the
evaluator agree by convention and a convention is what drifts, so only real
rows settle it. What is here is the half a database cannot answer — whether
anything starts the sweep. A worker nobody calls is this repository's most
frequently rediscovered defect, and it is the defect the sweep itself exists
to repair one layer down.
"""

from __future__ import annotations

import ast
from pathlib import Path

_MAIN = Path(__file__).resolve().parents[1] / "app" / "main.py"


def test_the_lifespan_starts_the_sweep() -> None:
    """Read with ``ast`` rather than imported.

    Importing ``app.main`` pulls in the service's whole startup graph, and a
    registration test that has to boot the service gets deleted the first time
    it is slow. Same approach, and the same three checks, as the shadow
    reconciliation sweep's: the module is imported, a task is created for it,
    and the task's ``worker=`` is this sweep rather than something that merely
    mentions it.
    """
    tree = ast.parse(_MAIN.read_text(encoding="utf-8"))

    imported = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "app.workers.autonomy_drift"
        for alias in node.names
    }
    assert imported, "app/main.py no longer imports the autonomy drift sweep"

    guarded = [
        call
        for call in ast.walk(tree)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "_run_guarded_scheduler_worker"
    ]
    assert guarded, "app/main.py no longer registers guarded scheduler workers; this test is stale"

    registered = [
        call
        for call in guarded
        for kw in call.keywords
        if kw.arg == "worker" and isinstance(kw.value, ast.Name) and kw.value.id in imported
    ]
    assert registered, (
        "the drift sweep is imported by app/main.py but never passed to _run_guarded_scheduler_worker, "
        "so nothing would call it on a schedule — which is the defect it was written to repair"
    )

    job_names = {
        kw.value.value for call in registered for kw in call.keywords if kw.arg == "job_name" and isinstance(kw.value, ast.Constant)
    }
    assert "autonomy_drift" in job_names, (
        f"the sweep is registered under {job_names or 'no job name'}; the Redis scheduler lease is keyed on the "
        f"job name, so two names means two replicas can demote the same tenant at once"
    )


def test_the_shutdown_path_cancels_it() -> None:
    """A worker the lifespan starts and never cancels leaks a task per reload."""
    assert "autonomy_drift_task.cancel()" in _MAIN.read_text(encoding="utf-8")


def test_the_sweep_is_on_by_default_and_the_disabled_case_is_announced() -> None:
    """Unlike the shadow sweep, and the difference is what each one reaches.

    That one polls a customer's SIEM on a timer, so the plan's rule applies
    and it ships off. This one aggregates rows the deployment already wrote
    and makes no outbound call; the condition it catches is a grant that has
    stopped being earned, which by definition nobody is watching for, so
    shipping it off would leave it off exactly where it matters.
    """
    from app.core.config import Settings  # noqa: PLC0415

    assert Settings.model_fields["AUTONOMY_DRIFT_ENABLED"].default is True

    # Still announced when switched off, because "no demotions" and "no sweep"
    # look identical from outside.
    assert "autonomy_drift worker disabled" in _MAIN.read_text(encoding="utf-8")


def test_the_tick_cadence_has_a_floor() -> None:
    """A misconfigured interval must not become a scan storm over every tenant."""
    from app.workers import autonomy_drift  # noqa: PLC0415

    class _Settings:
        AUTONOMY_DRIFT_INTERVAL_SECONDS = 0
        AUTONOMY_DRIFT_MAX_TENANTS_PER_TICK = 0

    original = autonomy_drift.settings
    autonomy_drift.settings = _Settings()  # type: ignore[assignment]
    try:
        assert autonomy_drift._interval() >= 60
        assert autonomy_drift._max_tenants() >= 1
    finally:
        autonomy_drift.settings = original


def test_the_sweep_cannot_promote() -> None:
    """It can only take autonomy away.

    A grant that reappeared on its own would have nobody's name on it. A
    tenant whose numbers recover asks again through the gate, with an actor
    and an audit row.
    """
    source = (Path(__file__).resolve().parents[1] / "app" / "workers" / "autonomy_drift.py").read_text(encoding="utf-8")

    assert "request_promotion" not in source
    assert "reconcile_grants" in source
