"""The route that gives ``shadow_reconcile`` a caller.

Gap-closure Phase 2.1, closing D15.

The module under test existed with eleven tests and no caller. These cover the
route that changes that, and the four answers it has to be able to give: a
window it read and graded, credentials that will never work, a vendor asking us
to slow down, and a vendor that was merely unhappy. Telling the second apart
from the fourth is the whole point, because one of them is worth retrying on a
timer and the other turns into churn nobody reads.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from app.api import shadow_reconcile_router as route_mod
from app.security.tenant_scope import TenantPrincipal, require_console_or_service_auth
from app.services.alert_history import ClosedFinding
from app.services.shadow_reconcile import ReconcileResult
from fastapi import FastAPI
from fastapi.testclient import TestClient

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = uuid.UUID("22222222-2222-2222-2222-222222222222")

_NOW = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)


def _finding(
    finding_id: str = "notable-1",
    disposition: str = "true_positive",
    *,
    closed_at: datetime | None = None,
) -> ClosedFinding:
    return ClosedFinding(
        vendor="splunk",
        finding_id=finding_id,
        title="Suspicious PowerShell on FIN-WS-04",
        disposition=disposition,
        vendor_disposition="disposition:1",
        closed_at=closed_at or _NOW,
        closed_by="analyst@example.com",
    )


def _body(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "vendor": "splunk",
        "credentials": {"splunk_url": "https://splunk.example.com:8089", "splunk_token": "t"},
        "since": (_NOW - timedelta(hours=1)).isoformat(),
        "until": _NOW.isoformat(),
        "limit": 500,
    }
    payload.update(overrides)
    return payload


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """The route mounted with a resolved principal and a configured database.

    The principal is overridden rather than a token minted, because what these
    tests are about is the route's behaviour once a tenant is resolved; the
    resolution itself is covered by the vendored ``test_tenant_scope.py`` that
    travels with the module in all ten services.
    """
    monkeypatch.setattr(route_mod, "database_configured", lambda: True)
    app = FastAPI()
    app.include_router(route_mod.router, prefix="/api/v1")
    app.dependency_overrides[require_console_or_service_auth] = lambda: TenantPrincipal(
        tenant_ids=frozenset({TENANT}), subject="service", delegated=True
    )
    return TestClient(app)


def _patch_reader(monkeypatch: pytest.MonkeyPatch, result: Any) -> list[Any]:
    """Replace the splunk arm. ``result`` is a list to return or an exception to raise."""
    seen: list[Any] = []

    async def _reader(body: Any) -> list[ClosedFinding]:
        seen.append(body)
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setitem(route_mod.READERS, "splunk", _reader)
    return seen


def _patch_reconcile(monkeypatch: pytest.MonkeyPatch, **counts: int) -> list[tuple[Any, list[ClosedFinding]]]:
    calls: list[tuple[Any, list[ClosedFinding]]] = []

    async def _reconcile(tenant_id: Any, findings: Any, **_kw: Any) -> ReconcileResult:
        rows = list(findings)
        calls.append((tenant_id, rows))
        return ReconcileResult(considered=len(rows), **counts)

    monkeypatch.setattr(route_mod, "reconcile_findings", _reconcile)
    return calls


def _status_error(code: int, headers: dict[str, str] | None = None) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://splunk.example.com:8089/services/search/jobs")
    response = httpx.Response(code, headers=headers or {}, request=request)
    return httpx.HTTPStatusError("vendor said no", request=request, response=response)


class TestAWindowItRead:
    def test_it_reconciles_and_reports_both_halves(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_reader(monkeypatch, [_finding("a"), _finding("b", "benign")])
        calls = _patch_reconcile(monkeypatch, matched=2)

        response = client.post("/api/v1/shadow/reconcile", json=_body())

        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2
        assert body["matched"] == 2
        assert body["labelled"] == 2
        # The tenant reached the matcher from the credential, not the body.
        assert calls and str(calls[0][0]) == str(TENANT)

    def test_the_watermark_comes_from_the_latest_closure_not_the_clock(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """A vendor that indexes late must not have its findings stepped over.

        The caller advances its watermark from this field, so it has to be the
        latest close time actually seen rather than the end of the window the
        caller asked for.
        """
        latest = _finding("a")
        earlier = _finding("b", "benign", closed_at=_NOW - timedelta(minutes=5))
        _patch_reader(monkeypatch, [earlier, latest])
        _patch_reconcile(monkeypatch, matched=2)

        body = client.post("/api/v1/shadow/reconcile", json=_body()).json()

        assert body["latest_closed_at"] == _NOW.isoformat()

    def test_an_empty_window_is_a_success_with_no_watermark(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_reader(monkeypatch, [])
        _patch_reconcile(monkeypatch)

        body = client.post("/api/v1/shadow/reconcile", json=_body()).json()

        assert body["count"] == 0
        assert body["latest_closed_at"] is None


class TestPermanentIsNotTransient:
    """The distinction the sweep depends on, asserted from both sides."""

    @pytest.mark.parametrize("code", sorted(route_mod.PERMANENT_VENDOR_STATUSES))
    def test_a_refused_credential_is_permanent_and_names_the_action(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch, code: int
    ) -> None:
        _patch_reader(monkeypatch, _status_error(code))

        response = client.post("/api/v1/shadow/reconcile", json=_body())

        assert response.status_code == 422
        detail = response.json()["detail"]
        assert "Re-authorise this connector" in detail
        assert "will not recover on its own" in detail

    @pytest.mark.parametrize("code", [500, 502, 503, 504])
    def test_an_unhappy_vendor_is_transient(self, client: TestClient, monkeypatch: pytest.MonkeyPatch, code: int) -> None:
        _patch_reader(monkeypatch, _status_error(code))

        response = client.post("/api/v1/shadow/reconcile", json=_body())

        assert response.status_code == 502
        assert "Re-authorise" not in response.json()["detail"]

    def test_a_timeout_is_transient(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_reader(monkeypatch, httpx.ReadTimeout("too slow"))

        response = client.post("/api/v1/shadow/reconcile", json=_body())

        assert response.status_code == 502

    def test_rate_limiting_forwards_the_vendors_own_retry_after(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """Obeyed rather than estimated. A guess is either rude or slow."""
        _patch_reader(monkeypatch, _status_error(429, {"Retry-After": "120"}))

        response = client.post("/api/v1/shadow/reconcile", json=_body())

        assert response.status_code == 429
        assert response.headers["Retry-After"] == "120"

    def test_unbuildable_credentials_are_permanent_rather_than_an_empty_window(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The reader's own 422 must not become a quiet zero-closure pass.

        An empty window reads as "these analysts closed nothing", which is a
        statement about the customer's week rather than about their config.
        """
        calls = _patch_reconcile(monkeypatch)

        response = client.post("/api/v1/shadow/reconcile", json=_body(credentials={}))

        assert response.status_code == 422
        assert "client factory reads" in response.json()["detail"]
        assert calls == [], "a refused read must not reach the matcher at all"


class TestRefusalsBeforeTheVendorIsCalled:
    def test_no_database_refuses_instead_of_spending_vendor_quota(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without a DSN the matcher returns zero matches and raises nothing.

        Reported as a success that number is indistinguishable from a broken
        join key, and the two send an operator to different places. So it is
        refused up front, before a customer's search quota is spent on a
        window nothing can be written from.
        """
        monkeypatch.setattr(route_mod, "database_configured", lambda: False)
        seen = _patch_reader(monkeypatch, [_finding()])

        response = client.post("/api/v1/shadow/reconcile", json=_body())

        assert response.status_code == 503
        assert "DATABASE_URL" in response.json()["detail"]
        assert seen == [], "the vendor must not be called when nothing could be recorded"

    def test_an_inverted_window_is_refused(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        seen = _patch_reader(monkeypatch, [_finding()])

        response = client.post(
            "/api/v1/shadow/reconcile",
            json=_body(since=_NOW.isoformat(), until=(_NOW - timedelta(hours=1)).isoformat()),
        )

        assert response.status_code == 422
        assert seen == []


class TestTheTenantIsNotARequestField:
    def test_the_request_model_carries_no_tenant(self) -> None:
        """A tenant the caller typed is a tenant nothing checked.

        Asserted against the model rather than by sending one, because a field
        Pydantic ignores and a field Pydantic honours both produce a 200 on the
        happy path and only one of them is safe.
        """
        fields = set(route_mod.ReconcileRequest.model_fields)
        assert not {f for f in fields if "tenant" in f}, f"ReconcileRequest grew a tenant field: {sorted(fields)}"

    def test_an_empty_scope_refuses_rather_than_widening(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A service token with no tenant header must reach nothing, not everything."""
        monkeypatch.setattr(route_mod, "database_configured", lambda: True)
        app = FastAPI()
        app.include_router(route_mod.router, prefix="/api/v1")
        app.dependency_overrides[require_console_or_service_auth] = lambda: TenantPrincipal()
        seen = _patch_reader(monkeypatch, [_finding()])

        response = TestClient(app).post("/api/v1/shadow/reconcile", json=_body())

        assert response.status_code == 403
        assert seen == []

    def test_the_resolved_tenant_is_the_one_written(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """Not the one in any header the handler could have read for itself."""
        _patch_reader(monkeypatch, [_finding()])
        calls = _patch_reconcile(monkeypatch, matched=1)

        client.post(
            "/api/v1/shadow/reconcile",
            json=_body(),
            headers={"X-AiSOC-Tenant-ID": str(OTHER_TENANT)},
        )

        assert str(calls[0][0]) == str(TENANT)


def test_the_route_is_reachable_on_the_deployed_app() -> None:
    """The failure being closed is "exists and nothing calls it".

    A router that is written and never included is the same defect one layer
    up, so the assertion is against the service's own ``app`` rather than
    against a FastAPI instance this test built.
    """
    from app.main import app as deployed  # noqa: PLC0415 - importing the service graph is the point

    paths = {route.path for route in deployed.routes if hasattr(route, "path")}
    assert "/api/v1/shadow/reconcile" in paths
