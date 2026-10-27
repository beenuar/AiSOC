"""An engaged kill switch stops the actions dispatcher.

The switch was documented as the platform-wide stop and reached one caller.
``services/api/app/api/v1/endpoints/kill_switch.py`` said it was "checked
first and separately by everything that acts: closure in the triage worker,
the actions dispatcher, playbook dispatch and the MCP write tools", and
``git grep -i kill.switch -- services/actions`` returned nothing at all. An
operator who pressed it believed vendor actions had stopped; isolations and
account disables carried on.

Why the vendor is the only thing replaced
-----------------------------------------
``dispatch()`` is the real dispatcher, the switch reader runs its real query
against a real Postgres, and the executor is a recorder that counts calls. A
fake dispatcher or a fake reader would answer whatever it was asked, and the
whole defect was that nothing asked.

Why ``search_siem`` and not ``isolate_host`` for the blocking cases
------------------------------------------------------------------
``isolate_host`` is HIGH blast and the autonomy gate refuses it at every
tier, so a test that watched it stop would have passed on the unfixed tree
for a reason that had nothing to do with the switch. ``search_siem`` is
contracted AUTOMATIC and really does execute, so "it stopped" can only mean
the switch stopped it. ``isolate_host`` still appears below, asserting the
*reason* names the switch: two controls that both refuse are one control an
operator cannot release, so the switch has to be legible as the cause.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio
from app.live_actions import dispatcher as dispatcher_mod
from app.live_actions import registry
from app.live_actions.dispatcher import dispatch
from app.live_actions.models import LiveActionRequest, LiveActionResult, LiveActionStatus
from app.models.action import ActionType
from app.services.maturity import MaturityTier
from app.services.tenant_policy import TenantPolicy

pytestmark = pytest.mark.asyncio

#: Set by `action-durability-live.yml`, which already stands up Postgres as
#: the `aisoc_app` runtime role with every migration applied. Gated on an
#: explicit variable rather than on whether a connection happens to succeed:
#: a live case that silently degrades to a skip is a green run that measured
#: nothing.
_LIVE_DSN = os.environ.get("AISOC_KILL_SWITCH_TEST_DSN", "")

#: Privileged connection used only to seed rows. See :class:`_Switch`.
#: Falls back to the runtime DSN so that once the global row is writable by
#: the runtime role, one variable is enough.
_SEED_DSN = os.environ.get("AISOC_KILL_SWITCH_TEST_SEED_DSN", "") or _LIVE_DSN

live_only = pytest.mark.skipif(
    not _LIVE_DSN,
    reason="needs a real Postgres with migration 078 applied; set AISOC_KILL_SWITCH_TEST_DSN",
)


class _RecordingExecutor:
    """Counts what reached the vendor. Nothing else about it is interesting.

    `calls` is the assertion that matters: a dispatcher that returns BLOCKED
    *after* contacting the vendor has not stopped anything, and a status
    string alone cannot tell the two apart.
    """

    def __init__(self, action_type: ActionType = ActionType.SEARCH_SIEM) -> None:
        self._legacy_action_type = action_type
        self.calls: list[LiveActionRequest] = []

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        self.calls.append(request)
        return LiveActionResult(
            request_id=request.request_id,
            status=LiveActionStatus.SUCCEEDED,
            capability=request.capability,
            vendor_id=request.vendor_id,
            summary="vendor was contacted",
        )


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _RecordingExecutor:
    executor = _RecordingExecutor()
    monkeypatch.setattr(registry, "get_executor", lambda vendor, cap: executor)
    return executor


class _Switch:
    """Seeds the real table so the real reader can be measured against it.

    Writes SQL rather than calling the API handlers because the two services
    cannot share an interpreter — both name their top-level package ``app``,
    so importing one shadows the other.

    Two DSNs, and the distinction is load-bearing. ``dsn`` is the runtime
    role the dispatcher reads with and is the thing under test. ``seed_dsn``
    is a privileged connection used only to put rows in place, because on
    ``main`` the global row cannot be written by the runtime role at all:
    ``aisoc_kill_switch`` carries ``WITH CHECK (tenant_id =
    current_tenant_id())`` and a NULL ``tenant_id`` satisfies it for no
    session, bound or unbound. That writability defect is reproduced here
    and owned by the PR that makes the global switch engageable; what these
    cases measure is whether dispatch *reads* an engaged switch, which is a
    separate question and was separately false.
    """

    def __init__(self, dsn: str, seed_dsn: str) -> None:
        self.dsn = dsn
        self.seed_dsn = seed_dsn

    async def _run(self, sql: str, *args: object) -> None:
        import asyncpg

        conn = await asyncpg.connect(self.seed_dsn, timeout=10.0)
        try:
            await conn.execute(sql, *args)
        finally:
            await conn.close()

    async def new_tenant(self) -> uuid.UUID:
        tenant = uuid.uuid4()
        await self._run(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)",
            tenant,
            f"kill-switch-{tenant}",
            f"ks-{tenant}",
        )
        return tenant

    async def engage(self, tenant: uuid.UUID | None, reason: str) -> None:
        await self._run(
            """
            INSERT INTO aisoc_kill_switch (id, tenant_id, engaged, reason, engaged_by)
            VALUES ($1, $2, TRUE, $3, 'operator@example.com')
            """,
            uuid.uuid4(),
            tenant,
            reason,
        )

    async def release(self, tenant: uuid.UUID | None) -> None:
        await self._run(
            "UPDATE aisoc_kill_switch SET engaged = FALSE WHERE tenant_id IS NOT DISTINCT FROM $1",
            tenant,
        )


@pytest_asyncio.fixture
async def switch(monkeypatch: pytest.MonkeyPatch) -> _Switch:
    """A clean switch table per test, and no caching.

    The reader caches a resolved state for a few seconds so the hot path does
    not pay a round trip per action. Left alone between tests that caches one
    test's verdict into the next, which would make a stop look like it worked
    when it was a leftover. Turning the TTL off is the honest way to get a
    cold read: a test that reaches into the module's cache would also be a
    test that passes when the cache is the only thing working.
    """
    import asyncpg

    monkeypatch.setenv("AISOC_KILL_SWITCH_TTL_SECONDS", "0")
    conn = await asyncpg.connect(_SEED_DSN, timeout=10.0)
    try:
        await conn.execute("DELETE FROM aisoc_kill_switch")
    finally:
        await conn.close()
    return _Switch(_LIVE_DSN, _SEED_DSN)


@pytest.fixture(autouse=True)
def _permissive_tenant_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every *other* reason to refuse.

    The tenant policy is stubbed and the switch reader is not. That is the
    point: if anything but the switch can explain a refusal, the test proves
    nothing about the switch.
    """

    async def _resolve(tenant_id):  # noqa: ANN001, ANN202
        return TenantPolicy(tier=MaturityTier.L4_AUTOMATE, from_store=True)

    monkeypatch.setattr(dispatcher_mod, "resolve_tenant_policy", _resolve)


def _request(**overrides) -> LiveActionRequest:
    payload = {
        "request_id": uuid.uuid4(),
        "capability": "search_siem",
        "vendor_id": "splunk",
        "target": "index=main",
        "dry_run": False,
        "requested_by": "analyst@example.com",
    }
    payload.update(overrides)
    return LiveActionRequest(**payload)


# ── live: a real switch, a real reader, a real database ──────────────────


@live_only
class TestAnEngagedSwitchStopsTheVendor:
    async def test_a_global_switch_stops_dispatch(self, switch, recorder: _RecordingExecutor, monkeypatch: pytest.MonkeyPatch) -> None:
        tenant = await switch.new_tenant()
        monkeypatch.setenv("DATABASE_DSN", switch.dsn)
        await switch.engage(None, "platform-wide freeze: investigating runaway containment")

        result = await dispatch(_request(tenant_id=tenant))

        assert recorder.calls == [], "the vendor was contacted while the platform-wide stop was engaged"
        assert result.status is LiveActionStatus.BLOCKED
        assert result.details.get("blocked_by") == "kill_switch"
        assert result.details.get("kill_switch_scope") == "global"

    async def test_a_tenant_switch_stops_that_tenants_dispatch(
        self, switch, recorder: _RecordingExecutor, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant = await switch.new_tenant()
        monkeypatch.setenv("DATABASE_DSN", switch.dsn)
        await switch.engage(tenant, "tenant freeze while we work out what the agent did")

        result = await dispatch(_request(tenant_id=tenant))

        assert recorder.calls == []
        assert result.status is LiveActionStatus.BLOCKED
        assert result.details.get("kill_switch_scope") == "tenant"

    async def test_one_tenants_switch_does_not_stop_another(
        self, switch, recorder: _RecordingExecutor, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stop control that over-blocks is as broken as one that under-blocks."""
        frozen = await switch.new_tenant()
        working = await switch.new_tenant()
        monkeypatch.setenv("DATABASE_DSN", switch.dsn)
        await switch.engage(frozen, "this tenant only, please")

        result = await dispatch(_request(tenant_id=working))

        assert len(recorder.calls) == 1, "an unrelated tenant's switch stopped this tenant's action"
        assert result.status is LiveActionStatus.SUCCEEDED

    async def test_the_reason_names_the_switch_even_when_policy_would_also_refuse(self, switch, monkeypatch: pytest.MonkeyPatch) -> None:
        """`isolate_host` is refused by the tier ladder too. Say which one.

        Two controls that both refuse are one control an operator cannot
        release: they lift the switch, the action still refuses, and they go
        looking for a second switch that does not exist.
        """
        tenant = await switch.new_tenant()
        isolator = _RecordingExecutor(ActionType.ISOLATE_HOST)
        monkeypatch.setattr(registry, "get_executor", lambda vendor, cap: isolator)
        monkeypatch.setenv("DATABASE_DSN", switch.dsn)
        await switch.engage(None, "platform-wide freeze while containment is reviewed")

        result = await dispatch(_request(capability="isolate_host", vendor_id="crowdstrike", target="WIN-DC01", tenant_id=tenant))

        assert isolator.calls == []
        assert result.details.get("blocked_by") == "kill_switch"
        assert "kill switch" in result.summary.lower()

    async def test_a_dry_run_is_stopped_too(self, switch, recorder: _RecordingExecutor, monkeypatch: pytest.MonkeyPatch) -> None:
        """A preview is only credentials-free if the strip list is right.

        `services/actions/app/executors/siem.py` records what happens when it
        is not: "a 'dry run' calls the customer's production SIEM. That is
        exactly what happened". During a declared freeze that is the one risk
        not worth carrying for the convenience of a preview.
        """
        tenant = await switch.new_tenant()
        monkeypatch.setenv("DATABASE_DSN", switch.dsn)
        await switch.engage(None, "freeze everything, including previews")

        result = await dispatch(_request(tenant_id=tenant, dry_run=True))

        assert recorder.calls == []
        assert result.status is LiveActionStatus.BLOCKED

    async def test_blocked_is_not_reported_as_failed(self, switch, recorder: _RecordingExecutor, monkeypatch: pytest.MonkeyPatch) -> None:
        """FAILED invites a retry. A deliberate stop is not a failure."""
        tenant = await switch.new_tenant()
        monkeypatch.setenv("DATABASE_DSN", switch.dsn)
        await switch.engage(None, "a deliberate freeze, not an outage")

        result = await dispatch(_request(tenant_id=tenant))

        assert result.status is not LiveActionStatus.FAILED
        assert result.status is not LiveActionStatus.SUCCEEDED
        assert result.error is None, "a blocked action has nothing to retry and no error to report"


@live_only
class TestTheSwitchReleasedLetsWorkThrough:
    """The positive control. A stop control stuck on is a product that stopped."""

    async def test_a_released_switch_does_not_block(self, switch, recorder: _RecordingExecutor, monkeypatch: pytest.MonkeyPatch) -> None:
        tenant = await switch.new_tenant()
        monkeypatch.setenv("DATABASE_DSN", switch.dsn)
        await switch.engage(tenant, "freeze for a moment")
        await switch.release(tenant)

        result = await dispatch(_request(tenant_id=tenant))

        assert len(recorder.calls) == 1, "the switch was released and the action still did not run"
        assert result.status is LiveActionStatus.SUCCEEDED

    async def test_a_deployment_with_no_switch_row_dispatches_normally(
        self, switch, recorder: _RecordingExecutor, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The overwhelmingly common case: nobody has ever pressed it."""
        tenant = await switch.new_tenant()
        monkeypatch.setenv("DATABASE_DSN", switch.dsn)

        result = await dispatch(_request(tenant_id=tenant))

        assert len(recorder.calls) == 1
        assert result.status is LiveActionStatus.SUCCEEDED

    async def test_the_route_every_caller_reaches_is_governed_too(
        self, switch, recorder: _RecordingExecutor, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Playbook dispatch terminates here, so this is where it is stopped.

        `action_bridge.py` posts to the API's `/playbook-steps/dispatch`,
        which resolves credentials and calls `actions_client`, which posts to
        `POST /api/v1/live-actions/dispatch` — this route. Gating the shared
        chokepoint rather than adding a second check in the playbook service
        is the same reasoning `playbook_step_dispatch.py` already records: a
        policy mirrored in two services is off in whichever is more generous.
        """
        from app.core.config import get_settings
        from app.main import app
        from fastapi.testclient import TestClient

        tenant = await switch.new_tenant()
        monkeypatch.setenv("DATABASE_DSN", switch.dsn)
        monkeypatch.setenv("AISOC_ACTIONS_SERVICE_TOKEN", "test-actions-service-token")
        get_settings.cache_clear()
        await switch.engage(None, "platform-wide freeze reaches the HTTP surface too")

        with TestClient(
            app,
            headers={"Authorization": "Bearer test-actions-service-token"},
            raise_server_exceptions=False,
        ) as client:
            response = client.post(
                "/api/v1/live-actions/dispatch",
                json={
                    "capability": "search_siem",
                    "vendor_id": "splunk",
                    "target": "index=main",
                    "tenant_id": str(tenant),
                    "dry_run": False,
                },
            )

        assert recorder.calls == []
        assert response.status_code == 200, response.text
        assert response.json()["result"]["status"] == "blocked"


# ── no database needed: the read path's own failure modes ────────────────


class TestWhatHappensWhenTheSwitchCannotBeRead:
    async def test_an_unreadable_switch_blocks_rather_than_permits(
        self, recorder: _RecordingExecutor, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A database that cannot answer "is the stop pressed" must not be read as "no".

        Points at a closed port, so this is the real reader failing for real.
        """
        monkeypatch.setenv("DATABASE_DSN", "postgresql://nobody@127.0.0.1:1/aisoc")

        result = await dispatch(_request(tenant_id=uuid.uuid4()))

        assert recorder.calls == []
        assert result.status is LiveActionStatus.BLOCKED
        assert result.details.get("blocked_by") == "kill_switch_unreadable"

    async def test_unreadable_does_not_claim_somebody_pressed_it(
        self, recorder: _RecordingExecutor, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Naming the wrong subsystem sends an operator to debug a switch nobody touched."""
        monkeypatch.setenv("DATABASE_DSN", "postgresql://nobody@127.0.0.1:1/aisoc")

        result = await dispatch(_request(tenant_id=uuid.uuid4()))

        assert result.details.get("blocked_by") != "kill_switch"
        assert "unreadable" in result.summary.lower()

    async def test_no_database_configured_does_not_block(self, recorder: _RecordingExecutor, monkeypatch: pytest.MonkeyPatch) -> None:
        """A deployment with no database has no switch, and must still work.

        The same line `resolve_tenant_policy` already draws: no DSN is an
        operator's documented single-tenant configuration, not a read
        failure. Failing closed here would brick every such install to guard
        a table that cannot exist on it.
        """
        monkeypatch.delenv("DATABASE_DSN", raising=False)
        monkeypatch.delenv("DATABASE_URL", raising=False)

        result = await dispatch(_request(tenant_id=uuid.uuid4()))

        assert len(recorder.calls) == 1
        assert result.status is LiveActionStatus.SUCCEEDED
