"""The closure chokepoint: default-deny, fail-closed, and nothing routes around it.

Phase 1 of the closure remediation. See
`docs/remediation/phase-1-closure-authorization.md`.

The live half of this is `tests/isolation/test_closure_authorization_live.py`,
which drives real Postgres. What is here is the part a database cannot answer:
what the module does when there is no database, and whether every production
path that can close an alert actually goes through the gate.

The second half deserves a note. `test_closure_policy.py` already carried a
wiring test, and it asserted `"closure_policy.decide(" in source` against one
function. That is the weak shape this repository keeps rediscovering: it
confirms the path somebody remembered to check, and says nothing about the
path they forgot — which is precisely how the outcome-memory closure went
unnoticed for as long as it did. The replacement below enumerates every site
in the service that can set `alerts.status = 'resolved'` and requires each one
to be governed, so a new path fails the test by existing.
"""

from __future__ import annotations

import subprocess
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from app.closure import policy as closure


def _repo_root() -> Path:
    """The repository per git, not per this file's position in it.

    Counting directories above `__file__` is the thing
    `scripts/gate_toolkit.repo_root` exists to stop: four levels up is
    whatever happens to be there, and the repo's own meta-gate rejects it.
    """
    out = subprocess.run(  # noqa: S603
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
        cwd=Path(__file__).resolve().parent,
    )
    if out.returncode == 0 and out.stdout.strip():
        return Path(out.stdout.strip()).resolve()
    return Path(__file__).resolve().parents[3]


class _Conn:
    def __init__(self, *, policy_row=None, grant=None, switches=()):  # noqa: ANN001
        self.policy_row = policy_row
        self.grant = grant
        self.switches = list(switches)

    async def fetchrow(self, sql: str, *args):  # noqa: ANN001, ARG002
        if "autonomy_grants" in sql:
            return self.grant
        return self.policy_row

    async def fetch(self, sql: str, *args):  # noqa: ANN001, ARG002
        return self.switches


class _Pool:
    def __init__(self, conn: _Conn) -> None:
        self._conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self._conn


@pytest.fixture(autouse=True)
def _clear_cache():
    closure.reset_cache()
    yield
    closure.reset_cache()


@pytest.mark.asyncio
class TestTheDefaultIsRefusal:
    """Finding 14. The absence of a policy row was read as permission."""

    async def test_a_tenant_with_no_policy_row_is_not_authorized(self) -> None:
        decision = await closure.resolve_closure_policy(
            _Pool(_Conn(policy_row=None)),
            tenant_id="t1",
            alert_class="identity",
            confidence=0.99,
            default_threshold=0.85,
        )
        assert decision.allowed is False, (
            "a tenant that has configured nothing auto-closed, so automatic closure did not require explicit authorization"
        )
        assert decision.source == "default_deny"

    async def test_an_explicit_policy_still_decides(self) -> None:
        """The positive control. Default-deny must not mean deny-everything."""
        decision = await closure.resolve_closure_policy(
            _Pool(_Conn(policy_row={"enabled": True, "threshold": 0.80, "require_grant": False, "alert_class": "identity"})),
            tenant_id="t1",
            alert_class="identity",
            confidence=0.99,
            default_threshold=0.85,
        )
        assert decision.allowed is True
        assert decision.source == "policy"

    async def test_a_missing_tenant_is_not_authorized(self) -> None:
        """A closure that cannot be attributed to a tenant cannot be authorized."""
        decision = await closure.resolve_closure_policy(
            _Pool(_Conn(policy_row=None)),
            tenant_id=None,
            alert_class=None,
            confidence=1.0,
            default_threshold=0.85,
        )
        assert decision.allowed is False


@pytest.mark.asyncio
class TestAnUnavailableDatabaseRefuses:
    """Finding 10. `pool is None` was permissive, and it is far more reachable
    than "no database configured": `institutional._get_pool` returns None on
    any exception from `create_pool` *and* when the bootstrap probe on an
    unrelated table fails. A missing migration therefore disabled the closure
    policy and the kill switch together, logged at `debug`."""

    async def test_a_pool_that_failed_to_open_refuses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _unavailable():
            return None, closure.POOL_UNAVAILABLE

        monkeypatch.setattr(closure, "resolve_pool", _unavailable)

        decision = await closure.decide(
            tenant_id="t1",
            alert_class="identity",
            confidence=1.0,
            default_threshold=0.85,
        )
        assert decision.allowed is False, "a database that is configured but unreachable was read as permission to close"
        assert decision.source == "error"

    async def test_an_unconfigured_database_refuses_too(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No database means no recorded authorization, which is not a yes."""

        async def _unconfigured():
            return None, closure.POOL_UNCONFIGURED

        monkeypatch.setattr(closure, "resolve_pool", _unconfigured)

        decision = await closure.decide(
            tenant_id="t1",
            alert_class="identity",
            confidence=1.0,
            default_threshold=0.85,
        )
        assert decision.allowed is False

    async def test_the_kill_switch_refuses_when_the_pool_is_unavailable(self) -> None:
        engaged, reason = await closure.kill_switch_engaged(None, "t1", pool_state=closure.POOL_UNAVAILABLE)
        assert engaged is True, "an unreadable stop control was reported as not engaged"
        assert "unreadable" in reason


@pytest.mark.asyncio
class TestTheMemoryTableDoesNotGateTheClosurePolicy:
    """The institutional-memory bootstrap must not be able to switch closure off.

    `_get_pool` probed `aisoc_institutional_memory` and, when the probe
    failed, closed the pool and returned None — so an ACL problem or a missing
    migration on a table the closure policy never reads took the policy and
    the kill switch down with it.
    """

    async def test_a_failed_memory_bootstrap_still_yields_a_pool(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.memory import institutional

        sentinel = object()

        async def _connect():
            return sentinel, institutional.POOL_READY

        async def _probe_fails(*args, **kwargs):  # noqa: ANN002, ANN003, ARG001
            return False

        monkeypatch.setattr(institutional, "_connect", _connect)
        monkeypatch.setattr(institutional, "ensure_table", _probe_fails)
        monkeypatch.setattr(institutional, "_POOL", None, raising=False)
        monkeypatch.setattr(institutional, "_MEMORY_TABLE_READY", None, raising=False)

        pool, state = await institutional.connection_pool()

        assert pool is sentinel, "a failed memory-table probe removed the pool the closure policy reads"
        assert state == institutional.POOL_READY
        assert await institutional._get_pool() is None, "the memory store itself must still decline its unusable table"


@pytest.mark.asyncio
class TestTheChokepointItself:
    async def test_a_verdict_that_is_not_auto_closeable_is_refused(self) -> None:
        from app.closure import authorization

        decision = await authorization.authorize_auto_closure(
            tenant_ref="t1",
            raw_alert={"category": "identity"},
            verdict="true_positive",
            confidence=1.0,
            shadow=False,
            ungrounded=False,
            tier="llm",
        )
        assert decision.allowed is False
        assert decision.source == "verdict"

    async def test_a_shadow_run_is_refused(self) -> None:
        from app.closure import authorization

        decision = await authorization.authorize_auto_closure(
            tenant_ref="t1",
            raw_alert={},
            verdict="benign",
            confidence=1.0,
            shadow=True,
            ungrounded=False,
            tier="llm",
        )
        assert decision.allowed is False
        assert decision.source == "shadow"

    async def test_an_ungrounded_verdict_is_refused(self) -> None:
        """Evidence quality is a precondition of closure, not a label on it."""
        from app.closure import authorization

        decision = await authorization.authorize_auto_closure(
            tenant_ref="t1",
            raw_alert={},
            verdict="benign",
            confidence=1.0,
            shadow=False,
            ungrounded=True,
            tier="llm",
        )
        assert decision.allowed is False
        assert decision.source == "groundedness"

    async def test_the_reason_is_always_populated(self) -> None:
        """An alert that silently stays open is a support ticket."""
        from app.closure import authorization

        decision = await authorization.authorize_auto_closure(
            tenant_ref="t1",
            raw_alert={},
            verdict="benign",
            confidence=1.0,
            shadow=True,
            ungrounded=False,
            tier="memory",
        )
        assert decision.reason.strip()

    async def test_the_alert_class_matches_what_the_agent_resolves(self) -> None:
        """Both sides must mean the same thing by "this class".

        The agent pre-checks the policy for one class and the chokepoint
        re-checks it at the write. If they derived the class differently, a
        policy row could pass one and fail the other, and the disagreement
        would read as a flapping gate rather than as two readers.
        """
        import uuid as _uuid

        from app.agents import auto_triage_agent
        from app.closure import authorization
        from app.models.state import InvestigationState

        raw = {"id": "a", "category": "identity"}
        state = InvestigationState(incident_id=_uuid.uuid4(), tenant_id=_uuid.uuid4(), raw_alert=raw)

        assert auto_triage_agent._alert_class_of(state) == authorization.alert_class_of(raw)


class TestNothingRoutesAroundTheChokepoint:
    """Enumerates the closure paths instead of spot-checking one of them."""

    def test_the_chokepoint_gate_passes(self) -> None:
        """Runs `scripts/check_closure_authorization.py` rather than restating it.

        The gate asserts that only the ledger carries SQL which can set an
        alert to `'resolved'`, and that the function holding it calls the
        chokepoint. Shelling out keeps one implementation: a copy of the
        detector here is the copy that drifts, and this repository has shipped
        that exact shape more than once.
        """
        import subprocess
        import sys

        root = _repo_root()
        gate = root / "scripts" / "check_closure_authorization.py"
        assert gate.is_file(), f"the closure chokepoint gate is missing at {gate}"

        result = subprocess.run(  # noqa: S603
            [sys.executable, str(gate), "--root", str(root)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, f"closure chokepoint gate failed:\n{result.stdout}\n{result.stderr}"

    def test_the_gate_itself_detects_both_ways(self) -> None:
        """A gate nobody proved is a gate nobody should believe."""
        import subprocess
        import sys

        result = subprocess.run(  # noqa: S603
            [sys.executable, str(_repo_root() / "scripts" / "check_closure_authorization.py"), "--self-test"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, f"closure chokepoint gate self-test failed:\n{result.stdout}\n{result.stderr}"

    def test_the_ledger_consults_the_chokepoint_before_closing(self) -> None:
        import inspect

        from app.investigator import ledger as ledger_module

        source = inspect.getsource(ledger_module.persist_auto_triage)
        assert "authorize_auto_closure(" in source, (
            "persist_auto_triage can set alerts.status='resolved' without consulting the closure authorization"
        )

    def test_every_caller_of_persist_auto_triage_is_covered(self) -> None:
        """The reason this is an enumeration and not a spot check.

        Each of these reaches the one durable write with a caller-supplied
        `auto_closed`. Listing them makes a new one a test failure rather
        than a silent fourth path.
        """
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[1] / "app"
        callers = {
            path.relative_to(root).as_posix() for path in root.rglob("*.py") if "persist_auto_triage(" in path.read_text(encoding="utf-8")
        }
        assert callers == {
            "investigator/ledger.py",
            "workers/fused_alert_consumer.py",
            "workers/shadow_mode.py",
            "workers/triage_persistence.py",
            "replay/shadow.py",
        }, f"the set of modules reaching the durable closure write changed: {sorted(callers)}"
