"""The audit middleware must derive its actor from a verified principal only.

GHSA-w4r8-969c-67p2 (CWE-347). ``AuditMiddleware`` used to decode the
Authorization Bearer token with ``jwt.decode(options={"verify_signature":
False})`` and write the extracted ``sub`` / ``tenant_id`` / ``email`` into the
tenant's tamper-evident audit hash chain — for every mutating request,
*before and regardless of authentication*. An unauthenticated caller who sent
a structurally valid JWT signed with any key therefore forged audit entries
attributed to any user, into any tenant whose id they knew (the Default tenant
exists in every deployment).

These tests mount the **real** ``AuditMiddleware`` through a real Starlette app
and ``TestClient``, so the ``BaseHTTPMiddleware`` task boundary and the
``request.state`` propagation are the real ones — a hand-built call of
``dispatch`` would fake exactly the behaviour under test. The database write is
intercepted at ``AsyncSessionLocal`` / ``_append_to_chain`` so the assertion is
about *which identity the middleware decides to write*, not about a row; the
live suite (``tests/isolation/test_audit_forgery_live.py``) proves the same
property end to end against real Postgres.

The identity now comes from ``request.state.aisoc_authenticated_principal``,
set by ``get_current_user`` only after a credential verifies. A request that
sends a forged token but never authenticates leaves no principal there, so the
middleware writes nothing.
"""

from __future__ import annotations

import types

import jwt
import pytest
from app.middleware import audit_middleware
from app.middleware.audit_middleware import AuditMiddleware
from fastapi import FastAPI, Request
from starlette.testclient import TestClient

# A forged token: a structurally valid JWT whose claims an attacker chose,
# signed with a key the attacker owns. The server signs with its own
# SECRET_KEY, so this signature is invalid by construction — exactly the PoC
# token from the advisory.
FORGED_TOKEN = jwt.encode(
    {
        "sub": "66666666-6666-6666-6666-666666666666",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "email": "framed-operator@victim.test",
        "exp": 9999999999,
    },
    "attacker-owned-key-not-the-server-key",
    algorithm="HS256",
)


class _FakeSession:
    """Stands in for ``AsyncSessionLocal()`` — records the row the middleware
    tries to write without needing a database.

    The security decision happens *before* the write (which identity, or
    none), so intercepting here observes it faithfully. ``_append_to_chain`` is
    separately patched to a no-op because it would otherwise issue SQL.
    """

    def __init__(self, sink: list) -> None:
        self._sink = sink

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    def add(self, event: object) -> None:
        self._sink.append(event)

    async def commit(self) -> None:
        return None


@pytest.fixture
def written(monkeypatch: pytest.MonkeyPatch) -> list:
    """Intercept the middleware's DB write; yield the list of written rows."""
    sink: list = []
    monkeypatch.setattr(audit_middleware, "AsyncSessionLocal", lambda: _FakeSession(sink))

    async def _noop_chain(_db: object, _event: object) -> None:
        return None

    monkeypatch.setattr(audit_middleware, "_append_to_chain", _noop_chain)
    return sink


def _app(*, stash_principal: object | None = None) -> FastAPI:
    """A minimal app behind the real ``AuditMiddleware``.

    ``stash_principal`` simulates ``get_current_user`` recording a *verified*
    principal on ``request.state`` — the only identity source the middleware
    is now allowed to trust.
    """
    app = FastAPI()

    @app.post("/mutate")
    async def mutate(request: Request):  # noqa: ANN202
        if stash_principal is not None:
            request.state.aisoc_authenticated_principal = stash_principal
        return {"ok": True}

    app.add_middleware(AuditMiddleware)
    return app


class TestForgedTokensAreNeverAudited:
    def test_a_forged_bearer_jwt_writes_no_audit_row(self, written: list) -> None:
        """The advisory's attack. A forged token on a mutating request, with no
        principal ever verified, must produce no audit write.

        On the vulnerable tree the middleware decoded this header and wrote a
        row attributed to ``framed-operator@victim.test``; this assertion fails
        there, which is the point.
        """
        with TestClient(_app()) as client:
            resp = client.post("/mutate", headers={"Authorization": f"Bearer {FORGED_TOKEN}"})
        assert resp.status_code == 200
        assert written == [], (
            "the middleware wrote an audit row from an unverified Bearer token — "
            "forged claims can enter the tamper-evident chain (GHSA-w4r8-969c-67p2)"
        )

    def test_an_unauthenticated_request_writes_no_audit_row(self, written: list) -> None:
        """Control: no Authorization header, no principal, no write."""
        with TestClient(_app()) as client:
            resp = client.post("/mutate")
        assert resp.status_code == 200
        assert written == []


class TestVerifiedPrincipalsAreStillAudited:
    def test_a_verified_principal_is_audited(self, written: list) -> None:
        """The other direction, which matters just as much.

        Reading the actor from ``request.state`` must not silently stop the
        middleware auditing authenticated routes that do not call
        ``emit_audit`` themselves — which is most of them. A request whose
        ``get_current_user`` resolved a principal is audited as that principal.
        """
        principal = types.SimpleNamespace(
            user_id="11111111-1111-1111-1111-111111111111",
            tenant_id="22222222-2222-2222-2222-222222222222",
            email="real.analyst@corp.example",
        )
        with TestClient(_app(stash_principal=principal)) as client:
            resp = client.post("/mutate", headers={"Authorization": f"Bearer {FORGED_TOKEN}"})
        assert resp.status_code == 200
        assert len(written) == 1, "the middleware stopped auditing a verified, authenticated request"
        row = written[0]
        # The identity is the verified principal, never the forged header.
        assert str(row.tenant_id) == principal.tenant_id
        assert row.actor_email == principal.email
        assert row.actor_email != "framed-operator@victim.test"

    def test_the_header_claims_never_override_the_principal(self, written: list) -> None:
        """Belt and braces: even with a forged header present, the written
        identity is the one ``request.state`` carries."""
        principal = types.SimpleNamespace(
            user_id="33333333-3333-3333-3333-333333333333",
            tenant_id="44444444-4444-4444-4444-444444444444",
            email="owner@corp.example",
        )
        with TestClient(_app(stash_principal=principal)) as client:
            client.post("/mutate", headers={"Authorization": f"Bearer {FORGED_TOKEN}"})
        assert len(written) == 1
        assert written[0].actor_email == "owner@corp.example"
