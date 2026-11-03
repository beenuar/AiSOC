"""Which credential name the API accepts from a peer service.

The other half of the contract measured in
``services/agents/tests/test_peer_service_token_wiring.py``. That file drives
the real agents caller and asserts it *presents* a particular name; this one
drives the real API ``get_current_user`` and asserts it *accepts* that name.
Neither can see the other — both services call their top-level package ``app``,
so importing one shadows the other in the same process — which is why the
agents resolver is loaded here **by file path** rather than restated, and why
``scripts/check_peer_service_token_names.py`` exists to compare the two.

The defect this pins: the agents service presented ``AISOC_AGENTS_SERVICE_TOKEN``
(the token it accepts) while the API validates ``AISOC_API_SERVICE_TOKEN``, and
``scripts/ensure_env.py`` generates the two as independent secrets. A test that
hard-codes one secret into both sides of the call cannot see that, so every
assertion here sets *three* distinct values and lets the two implementations
choose between them.
"""

from __future__ import annotations

import importlib.util
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest
from app.api.v1.deps import CurrentUser, get_current_user, get_db
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-0000000000de")

API_SECRET = "api-accepts-this-one-0000000000000000000000"
AGENTS_SECRET = "agents-accepts-this-one-00000000000000000000"
SHARED_SECRET = "the-shared-platform-token-000000000000000000"

_REPO_ROOT = Path(__file__).resolve().parents[3]
_AGENTS_PEER_TOKENS = _REPO_ROOT / "services" / "agents" / "app" / "security" / "peer_tokens.py"


def _agents_peer_tokens() -> Any:
    """The agents service's real resolver, loaded without importing its package.

    ``peer_tokens`` is deliberately stdlib-only so this works; if it ever grows
    an ``app.`` import this load fails loudly rather than silently measuring a
    copy.
    """
    assert _AGENTS_PEER_TOKENS.is_file(), f"agents peer-token resolver missing at {_AGENTS_PEER_TOKENS}"
    spec = importlib.util.spec_from_file_location("agents_peer_tokens_under_test", _AGENTS_PEER_TOKENS)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _TenantRow:
    """Answers the one query the service branch makes before it trusts a tenant."""

    def __init__(self, known: uuid.UUID) -> None:
        self.known = known

    def scalar_one_or_none(self) -> uuid.UUID | None:
        return self.known


class _Session:
    def __init__(self, known: uuid.UUID) -> None:
        self.known = known

    async def execute(self, _statement: Any) -> _TenantRow:
        return _TenantRow(self.known)


def _app() -> FastAPI:
    """One route behind the **real** ``get_current_user``.

    Only ``get_db`` is overridden. The token branch under test runs entirely
    before any query, so a stub session cannot mask a refusal — it exists so an
    *accepted* token can finish resolving its tenant.
    """
    router = APIRouter()

    @router.get("/whoami")
    async def whoami(user: CurrentUser = Depends(get_current_user)) -> dict[str, str]:
        return {"tenant_id": str(user.tenant_id), "role": str(user.role)}

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def _db() -> Any:
        yield _Session(TENANT)

    app.dependency_overrides[get_db] = _db
    return app


@pytest.fixture(autouse=True)
def _three_distinct_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("AISOC_API_SERVICE_TOKEN", API_SECRET)
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", AGENTS_SECRET)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", SHARED_SECRET)


def _get(token: str, *, tenant: str | None = str(TENANT), header: str = "X-AiSOC-Tenant-ID") -> Any:
    headers = {"Authorization": f"Bearer {token}"}
    if tenant is not None:
        headers[header] = tenant
    with TestClient(_app(), raise_server_exceptions=False) as client:
        return client.get("/api/v1/whoami", headers=headers)


def test_the_token_the_agents_service_presents_is_accepted() -> None:
    """The contract itself, with both sides choosing from the same three secrets."""
    presented = _agents_peer_tokens().api_token()
    response = _get(presented)

    assert response.status_code == 200, (
        f"the API refused the credential the agents service presents ({response.status_code}); "
        "the two sides name different environment variables"
    )
    assert response.json()["tenant_id"] == str(TENANT)


def test_the_api_accepts_its_own_name() -> None:
    """Positive control for the harness.

    If this fails the rig is broken, not the contract — so it is asserted
    before any conclusion is drawn from the test above.
    """
    assert _get(API_SECRET).status_code == 200


def test_the_shared_platform_token_is_accepted_as_the_fallback() -> None:
    """``AISOC_SERVICE_TOKEN`` is the documented second choice on both sides."""
    import os

    os.environ.pop("AISOC_API_SERVICE_TOKEN", None)
    assert _get(SHARED_SECRET).status_code == 200


def test_the_agents_services_own_token_is_not_accepted() -> None:
    """Negative control, and the measured symptom.

    ``AISOC_AGENTS_SERVICE_TOKEN`` is the token the *agents* service accepts.
    The API has never validated it on this path, so a caller presenting it is
    refused — which is what made the graph dimension silently unavailable.
    """
    assert _get(AGENTS_SECRET).status_code == 401


def test_a_service_caller_that_names_no_tenant_is_refused() -> None:
    """An absent scope narrows to nothing rather than widening to everything."""
    assert _get(API_SECRET, tenant=None).status_code == 403


def test_the_wrong_tenant_header_is_not_read() -> None:
    """``X-Tenant-ID`` is a different header, and the API's auth never reads it."""
    assert _get(API_SECRET, header="X-Tenant-ID").status_code == 403
