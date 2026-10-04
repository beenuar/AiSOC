"""A hunt that found rows says so, for the right tenant, with a ledger.

Fix pass item 1.5. See `plans/aisoc_fix_pass_plan.plan.md`.

Three defects in one route
--------------------------
`POST /hunt` on the agents service built its response as

    matches=list(getattr(result, "matches", []) or [])

and `HuntAgentResult` has no `matches` attribute. It has `findings`. The
`getattr` default made the mistake silent, so **every hunt that found rows
answered `checked: true, matches: []`** -- which reads to an analyst, and to a
model, as a clean result rather than as a hunt whose answer was dropped on the
way out.

`run_hunt` was called with no `ledger`, so `_record` returned at its first line
and **no hunt has ever written a ledger row**. Underneath that, `_record`
called `ledger.record_event(run_id=..., kind=..., payload=...)` while the real
`record_event` additionally requires `tenant_id`, `seq`, `agent` and `summary`,
so the first call that did reach a real ledger would have raised `TypeError`
into the `except` and logged a warning.

The tenant the route resolves was not passed on either; item 1.1 threads it.

Why the existing tests did not catch any of it
----------------------------------------------
They drive `run_hunt` directly and assert on `result.findings`, which is
correct and which the route then fails to read. And they pass a fake ledger
that accepts any keyword arguments, so a call the real ledger would reject
looks fine.

This file drives the route handler itself and uses the real `record_event`
signature as the contract, which is the pair of boundaries the defects live at.
"""

from __future__ import annotations

import inspect
import uuid
from typing import Any

import pytest

pytestmark = pytest.mark.anyio

TENANT = uuid.UUID("33333333-3333-3333-3333-333333333333")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Principal:
    """A console principal scoped to one tenant, as the dependency returns."""

    tenant_ids = frozenset({TENANT})
    subject = "console:hunter"
    delegated = False

    @property
    def is_empty(self) -> bool:
        return False

    def covers(self, tenant_id: uuid.UUID) -> bool:
        return tenant_id in self.tenant_ids

    def ordered_ids(self) -> list[uuid.UUID]:
        return sorted(self.tenant_ids)


class TestTheRouteReturnsWhatTheHuntFound:
    async def test_rows_the_hunt_found_reach_the_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The defect, exactly: findings in, nothing out."""
        from app.api import router as router_mod
        from app.hunt.agent import HuntAgentResult

        found = [{"host": "WS-42", "process": "powershell.exe"}]

        async def _fake_run_hunt(hypothesis: str, **kwargs: Any) -> HuntAgentResult:
            return HuntAgentResult(hypothesis=hypothesis, checked=True, findings=found, rows_scanned=17)

        monkeypatch.setattr(router_mod, "run_hunt", _fake_run_hunt)
        monkeypatch.setattr(router_mod, "make_chat_model", lambda *a, **k: object())

        response = await router_mod.run_nl_hunt(
            request=router_mod.HuntRequest(tenant_id=str(TENANT), hypothesis="powershell spawning from office"),
            principal=_Principal(),
        )

        assert response.checked is True
        assert response.matches == found, "the hunt found rows and the route reported none, which reads as a clean result"

    async def test_a_hunt_that_found_nothing_still_reports_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The negative control.

        Without it, a route that echoed its input would satisfy the assertion
        above. An empty hunt must stay empty.
        """
        from app.api import router as router_mod
        from app.hunt.agent import HuntAgentResult

        async def _fake_run_hunt(hypothesis: str, **kwargs: Any) -> HuntAgentResult:
            return HuntAgentResult(hypothesis=hypothesis, checked=True, findings=[], rows_scanned=4)

        monkeypatch.setattr(router_mod, "run_hunt", _fake_run_hunt)
        monkeypatch.setattr(router_mod, "make_chat_model", lambda *a, **k: object())

        response = await router_mod.run_nl_hunt(
            request=router_mod.HuntRequest(tenant_id=str(TENANT), hypothesis="anything"),
            principal=_Principal(),
        )

        assert response.checked is True
        assert response.matches == []

    async def test_the_route_passes_the_tenant_it_resolved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The tenant comes from the credential, and must reach the hunt.

        Without this the hunt runs against whatever tenant the API resolves
        from a shared credential, which is the defect item 1.1 closed one
        layer down.
        """
        from app.api import router as router_mod
        from app.hunt.agent import HuntAgentResult

        seen: dict[str, Any] = {}

        async def _fake_run_hunt(hypothesis: str, **kwargs: Any) -> HuntAgentResult:
            seen.update(kwargs)
            return HuntAgentResult(hypothesis=hypothesis, checked=True, findings=[])

        monkeypatch.setattr(router_mod, "run_hunt", _fake_run_hunt)
        monkeypatch.setattr(router_mod, "make_chat_model", lambda *a, **k: object())

        await router_mod.run_nl_hunt(
            request=router_mod.HuntRequest(tenant_id=str(TENANT), hypothesis="anything"),
            principal=_Principal(),
        )

        assert seen.get("tenant_id") == str(TENANT), f"the route resolved a tenant and did not pass it on: {seen.get('tenant_id')!r}"


class TestTheLedgerCallWouldBeAccepted:
    """`_record`'s call must satisfy the real `record_event`, not a fake one.

    The existing suite passes a double that accepts any keyword arguments, so
    a call the real ledger rejects looks identical to one it accepts. This
    compares against the real signature instead.
    """

    def test_the_hunt_ledger_call_matches_the_real_record_event(self) -> None:
        from app.investigator.ledger import record_event

        signature = inspect.signature(record_event)
        required = {
            name
            for name, param in signature.parameters.items()
            if param.default is inspect.Parameter.empty and param.kind is inspect.Parameter.KEYWORD_ONLY
        }

        from app.hunt.agent import _record

        source = inspect.getsource(_record)
        missing = sorted(name for name in required if f"{name}=" not in source)

        assert not missing, (
            f"_record does not supply {missing}, which record_event requires. "
            "Every call would raise TypeError into its own except and log a warning."
        )
