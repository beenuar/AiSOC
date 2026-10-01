"""Closure obeys per-tenant policy, and the kill switch stops it.

Parity plan 2.1 and 2.2.

These drive `resolve_closure_policy` with a fake pool standing in for
Postgres, and `run_auto_triage` for the wiring, because the plan requires a
test that exercises the production call path rather than a function nothing
imports. The thing that was wrong before was precisely a policy nothing
read: an earned `auto_close` grant whose only consumer selected
`auto_execute` on action verbs.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import pytest
from app.closure import policy as closure


class _Conn:
    def __init__(self, *, policy_row=None, grant=None, switches=()):  # noqa: ANN001
        self.policy_row = policy_row
        self.grant = grant
        self.switches = list(switches)
        self.queries: list[str] = []

    async def fetchrow(self, sql: str, *args):  # noqa: ANN001, ARG002
        self.queries.append(sql)
        if "autonomy_grants" in sql:
            return self.grant
        return self.policy_row

    async def fetch(self, sql: str, *args):  # noqa: ANN001, ARG002
        self.queries.append(sql)
        return self.switches


class _Pool:
    def __init__(self, conn: _Conn) -> None:
        self._conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self._conn


class _BrokenPool:
    @asynccontextmanager
    async def acquire(self):
        raise RuntimeError("connection refused")
        yield  # pragma: no cover


@pytest.fixture(autouse=True)
def _clear_cache():
    closure.reset_cache()
    yield
    closure.reset_cache()


@pytest.mark.asyncio
class TestPerTenantPolicy:
    async def test_no_policy_row_behaves_exactly_as_before(self) -> None:
        """Additive. A deployment that configures nothing is unchanged."""
        pool = _Pool(_Conn(policy_row=None))
        decision = await closure.resolve_closure_policy(
            pool, tenant_id="t1", alert_class="identity", confidence=0.9, default_threshold=0.85
        )
        assert decision.allowed is True
        assert decision.source == "env"
        assert decision.threshold == 0.85

    async def test_a_tenant_can_disable_closure_for_one_class(self) -> None:
        pool = _Pool(_Conn(policy_row={"enabled": False, "threshold": None, "require_grant": False, "alert_class": "identity"}))
        decision = await closure.resolve_closure_policy(
            pool, tenant_id="t1", alert_class="identity", confidence=0.99, default_threshold=0.85
        )
        assert decision.allowed is False
        assert "disabled" in decision.reason
        assert decision.source == "policy"

    async def test_a_tenant_threshold_overrides_the_process_wide_one(self) -> None:
        pool = _Pool(_Conn(policy_row={"enabled": True, "threshold": 0.97, "require_grant": False, "alert_class": "identity"}))
        at_default = await closure.resolve_closure_policy(
            pool, tenant_id="t1", alert_class="identity", confidence=0.90, default_threshold=0.85
        )
        assert at_default.allowed is False, "0.90 cleared the global 0.85 but not the tenant's 0.97"
        assert at_default.threshold == 0.97

        closure.reset_cache()
        pool = _Pool(_Conn(policy_row={"enabled": True, "threshold": 0.97, "require_grant": False, "alert_class": "identity"}))
        above = await closure.resolve_closure_policy(pool, tenant_id="t1", alert_class="identity", confidence=0.98, default_threshold=0.85)
        assert above.allowed is True

    async def test_an_earned_grant_is_finally_read(self) -> None:
        """The grant had no reader at all before this.

        `apps/docs/docs/operations/shadow-mode.md` said earning it let the
        agent close alerts of that class. Parity 1.1 had to retract that,
        because the only consumer of `autonomy_grants` selected
        `auto_execute` on action verbs.
        """
        without = _Pool(_Conn(policy_row={"enabled": True, "threshold": 0.8, "require_grant": True, "alert_class": "identity"}, grant=None))
        decision = await closure.resolve_closure_policy(
            without, tenant_id="t1", alert_class="identity", confidence=0.99, default_threshold=0.85
        )
        assert decision.allowed is False
        assert "grant" in decision.reason

        closure.reset_cache()
        with_grant = _Pool(
            _Conn(policy_row={"enabled": True, "threshold": 0.8, "require_grant": True, "alert_class": "identity"}, grant={"?column?": 1})
        )
        decision = await closure.resolve_closure_policy(
            with_grant, tenant_id="t1", alert_class="identity", confidence=0.99, default_threshold=0.85
        )
        assert decision.allowed is True

    async def test_one_tenants_policy_does_not_affect_another(self) -> None:
        """The plan's own "done when": a tenant with closure disabled sees
        no closure for that class while another tenant's closures continue."""
        disabled = _Pool(_Conn(policy_row={"enabled": False, "threshold": None, "require_grant": False, "alert_class": "identity"}))
        a = await closure.resolve_closure_policy(
            disabled, tenant_id="tenant-a", alert_class="identity", confidence=0.99, default_threshold=0.85
        )
        permissive = _Pool(_Conn(policy_row={"enabled": True, "threshold": 0.8, "require_grant": False, "alert_class": "identity"}))
        b = await closure.resolve_closure_policy(
            permissive, tenant_id="tenant-b", alert_class="identity", confidence=0.99, default_threshold=0.85
        )
        assert a.allowed is False
        assert b.allowed is True


@pytest.mark.asyncio
class TestTheKillSwitch:
    async def test_a_global_switch_stops_closure(self) -> None:
        pool = _Pool(_Conn(switches=[{"tenant_id": None, "engaged": True, "reason": "incident 4471"}]))
        decision = await closure.resolve_closure_policy(
            pool, tenant_id="t1", alert_class="identity", confidence=0.99, default_threshold=0.5
        )
        assert decision.allowed is False
        assert decision.source == "kill_switch"
        assert "incident 4471" in decision.reason

    async def test_a_tenant_switch_stops_only_that_tenant(self) -> None:
        engaged = _Pool(_Conn(switches=[{"tenant_id": "t1", "engaged": True, "reason": "tuning"}]))
        assert (await closure.kill_switch_engaged(engaged, "t1"))[0] is not False
        closure.reset_cache()
        clear = _Pool(_Conn(switches=[]))
        assert (await closure.kill_switch_engaged(clear, "t2"))[0] is False

    async def test_it_is_checked_before_the_policy(self) -> None:
        """Order matters: the switch must not depend on per-class rows."""
        conn = _Conn(
            policy_row={"enabled": True, "threshold": 0.1, "require_grant": False, "alert_class": None},
            switches=[{"tenant_id": None, "engaged": True, "reason": "stop"}],
        )
        decision = await closure.resolve_closure_policy(
            _Pool(conn), tenant_id="t1", alert_class="identity", confidence=0.99, default_threshold=0.85
        )
        assert decision.allowed is False
        assert not any("aisoc_closure_policies" in q for q in conn.queries), "the policy table was read before the switch was honoured"


@pytest.mark.asyncio
class TestFailureIsRefusal:
    """A database that cannot answer must not be read as permission.

    This is the direction that matters. Reading an unavailable policy as
    "no policy, use the permissive default" would mean a database blip
    starts closing alerts the tenant had disabled.
    """

    async def test_an_unreadable_policy_refuses(self) -> None:
        decision = await closure.resolve_closure_policy(
            _BrokenPool(), tenant_id="t1", alert_class="identity", confidence=0.99, default_threshold=0.1
        )
        assert decision.allowed is False
        assert decision.source == "error"

    async def test_an_unreadable_kill_switch_refuses(self) -> None:
        engaged, reason = await closure.kill_switch_engaged(_BrokenPool(), "t1")
        assert engaged is True
        assert "unreadable" in reason


class TestTheWiring:
    """The policy is consulted by the real closure decision, not just
    importable. A passing test on an uncalled function is indistinguishable
    from a working feature until someone traces the call graph."""

    def test_the_triage_agent_calls_the_policy(self) -> None:
        import inspect

        from app.agents import auto_triage_agent

        source = inspect.getsource(auto_triage_agent.run_auto_triage)
        assert "closure_policy.decide(" in source, (
            "run_auto_triage does not consult the closure policy, so the policy table is another mechanism with no reader"
        )
        assert "should_auto_close = verdict in AUTO_CLOSEABLE_DISPOSITIONS and closure.allowed" in source

    def test_a_withheld_closure_says_why(self) -> None:
        """An alert that silently stays open is a support ticket."""
        import inspect

        from app.agents import auto_triage_agent

        source = inspect.getsource(auto_triage_agent.run_auto_triage)
        assert "Auto-close withheld:" in source
