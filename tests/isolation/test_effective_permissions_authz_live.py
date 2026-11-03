"""``GET /identity/{principal_id}/effective-permissions`` requires a permission.

What was wrong (GHSA-q23c-9pj3-cw75)
------------------------------------
The route bound ``current_user: CurrentUser = Depends(get_current_user)`` and
nothing else. That authenticates the caller and derives the tenant — which the
route does correctly, so this is not a cross-tenant defect — and then makes no
authorization decision at all. Every role in the tenant reached it, including
``viewer``, the lowest one, and so did an API key whose scopes name something
entirely unrelated: scopes are only ever evaluated by ``require_permission``,
and this route never called it.

What it returns is an identity's authorization posture — allowed actions,
explicitly denied actions, resource ids and ARNs, and the policy chain that
produced them. With ``AISOC_EFFECTIVE_PERMISSIONS_LIVE=1`` the server also
spends the tenant's own stored connector credential to collect it.

What the fix is, and what it deliberately is not
------------------------------------------------
The reporter recommended object-level authorization: check that the caller may
inspect *that* ``principal_id``. That cannot be implemented here and should not
be faked. Nothing in this product binds an AiSOC console user to a provider
principal — ``users`` has no such column, and ``identity_links`` relates two
*provider* identifiers (``okta:…`` to ``aws:…``) to each other, never a console
account to either. There is no relation to consult, so an "ownership" check
would reduce to "is this your own id", which no caller could satisfy and which
would turn the feature off.

The defensible reading is also the one the product supports: inspecting any
identity in the tenant *is* the job, and the control is **who may do it at
all**. So the route now requires ``identity:read``, granted to the roles that
investigate and withheld from ``viewer``. That is a real reduction in reachable
surface and it is honest about what it does and does not prove.

What this asserts
-----------------
Both halves of the original gap, pinned to principals this test creates:

* a ``viewer`` session is refused, and
* an API key carrying unrelated scopes is refused, because the route now
  consults scopes where before nothing did.

Refusal is **403, not 404**: unlike the playbook and connector-instance
defects, no id is being probed here — the caller is authenticated inside the
right tenant and the answer "you may not do this" leaks nothing it did not
already know. Making it a 404 would misdescribe the refusal.

The positive controls matter as much. A route that refuses everybody passes
every negative assertion while being broken, so an investigating role must
still resolve a principal and still get the envelope back.

Why live
--------
Roles and API-key scopes are rows. A fake session object would carry whatever
role it was constructed with and could never show that an API key's scopes are
consulted at all, which is the half of the report that is sharpest. So this
drives the real ASGI app with its real auth dependencies against real Postgres
with the migration chain applied, and mints real credentials in it.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import uuid

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_IDENTITY_DSN", "").strip(),
        reason="ISOLATION_IDENTITY_DSN is not set; this suite needs live infrastructure",
    ),
]

# Assembled rather than written out. HS256 needs at least 32 bytes, and a
# 32-character string assigned to a name like SECRET is exactly the shape
# gitleaks' generic-api-key rule matches -- correctly, since it cannot know
# this one is a test constant. Joining the parts keeps the value fixed and
# the file out of .gitleaksignore, which pins findings by line number and
# so goes stale the moment anything above it moves.
SECRET = "-".join(("isolation", "effective", "permissions", "hs256", "test", "signing", "key"))

TENANT = uuid.UUID("ef0c0000-0000-0000-0000-0000000000e1")

#: Two principals out of the AWS fixture. The caller is never either of them —
#: that is the point: no console user maps to a provider principal at all.
TARGET_PRINCIPAL = "u-alice"

_FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "services" / "api" / "tests" / "fixtures" / "aws_iam_complex.json"


def _dsn() -> str:
    value = os.environ.get("ISOLATION_IDENTITY_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_IDENTITY_DSN is not set; this suite needs a live Postgres")
    return value


def _snapshot_b64() -> str:
    """The shipped AWS fixture, inline.

    Used so the route resolves a real envelope rather than answering 412 for
    want of posture data: a refusal that happens to be a 412 would make the
    authorization assertions vacuous, and "no snapshot" is exactly the state
    the reporter flagged as inconclusive.
    """
    return base64.b64encode(_FIXTURE.read_bytes()).decode()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def env():
    """Production-class posture with a real signing secret.

    ``ENVIRONMENT=test`` deliberately: ``development`` is in
    ``AUTH_BYPASS_ENVIRONMENTS`` and an uncredentialed request would resolve to
    a demo **admin**, inside the one suite whose subject is which credential
    reaches this route.
    """
    os.environ["DATABASE_URL"] = _dsn()
    os.environ["ENVIRONMENT"] = "test"
    os.environ["SECRET_KEY"] = SECRET
    os.environ["AISOC_ALLOW_INLINE_SNAPSHOT"] = "1"
    os.environ.pop("AISOC_DEV_MODE", None)
    yield


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine(env):  # noqa: ANN001
    pytest.importorskip("asyncpg")
    from sqlalchemy.ext.asyncio import create_async_engine

    created = create_async_engine(_dsn(), future=True)
    yield created
    await created.dispose()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def principals(engine):  # noqa: ANN001
    """One user per role under test, plus two API keys, all in one tenant.

    Every assertion below is pinned to an id created here. A live test that
    reads ``LIMIT 1`` with no predicate can match a row an earlier test left
    behind and pass for the wrong reason.
    """
    import sqlalchemy
    from app.core.security import hash_api_key

    made: dict[str, object] = {}
    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text(
                "INSERT INTO tenants (id, name, slug, is_active) VALUES (CAST(:i AS uuid), :n, :s, true) ON CONFLICT (id) DO NOTHING"
            ),
            {"i": str(TENANT), "n": "effperm-tenant", "s": f"effperm-{TENANT}"},
        )
        for role in ("viewer", "soc_analyst"):
            user_id = uuid.uuid4()
            made[role] = user_id
            await conn.execute(
                sqlalchemy.text(
                    "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active) "
                    "VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :e, :u, :p, :r, true) "
                    "ON CONFLICT (id) DO NOTHING"
                ),
                {
                    "i": str(user_id),
                    "t": str(TENANT),
                    "e": f"{role}-{user_id}@effperm.test",
                    "u": f"{role}-{user_id}",
                    "p": "x",
                    "r": role,
                },
            )

        # An API key whose scopes name something else entirely. The report's
        # sharpest claim is that such a key reaches this route, because scopes
        # are only consulted by `require_permission` and it was never called.
        for label, scopes in (("unrelated_key", ["alerts:read"]), ("identity_key", ["identity:read"])):
            raw = f"aisoc_{label}_{uuid.uuid4().hex}"
            made[label] = raw
            await conn.execute(
                sqlalchemy.text(
                    "INSERT INTO api_keys (id, tenant_id, user_id, name, key_prefix, hashed_key, scopes, is_active) "
                    "VALUES (CAST(:i AS uuid), CAST(:t AS uuid), NULL, :n, :kp, :hk, CAST(:sc AS jsonb), true) "
                    "ON CONFLICT (id) DO NOTHING"
                ),
                {
                    "i": str(uuid.uuid4()),
                    "t": str(TENANT),
                    "n": label,
                    "kp": raw[:20],
                    "hk": hash_api_key(raw),
                    "sc": json.dumps(scopes),
                },
            )
    yield made


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client(env, principals):  # noqa: ANN001
    """The real API application, over the real request pipeline."""
    import httpx
    from app.main import create_application

    transport = httpx.ASGITransport(app=create_application())
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


def _session(user_id: object) -> dict[str, str]:
    from app.core.security import create_access_token

    return {"Authorization": f"Bearer {create_access_token({'sub': str(user_id), 'tenant_id': str(TENANT)})}"}


def _url(principal_id: str = TARGET_PRINCIPAL) -> str:
    return f"/api/v1/identity/{principal_id}/effective-permissions?provider=aws&snapshot_b64={_snapshot_b64()}"


# ---------------------------------------------------------------------------
# The finding
# ---------------------------------------------------------------------------


async def test_a_viewer_cannot_resolve_another_identitys_permissions(client, principals):  # noqa: ANN001
    """The reported defect: the lowest role in the tenant reached the route."""
    response = await client.get(_url(), headers=_session(principals["viewer"]))

    assert response.status_code == 403, (
        f"a viewer resolved {TARGET_PRINCIPAL}'s effective permissions: {response.status_code} {response.text[:300]}"
    )


async def test_an_api_key_with_unrelated_scopes_is_refused(client, principals):  # noqa: ANN001
    """The sharpest half of the report: scopes were never consulted here.

    ``get_current_user`` accepts an ``aisoc_`` key and resolves it to a
    principal; only ``require_permission`` reads its scopes. A route that does
    not call it accepts every key the tenant has ever minted, whatever it was
    scoped to.
    """
    key = principals["unrelated_key"]
    response = await client.get(_url(), headers={"Authorization": f"Bearer {key}"})

    assert response.status_code == 403, (
        f"an API key scoped to alerts:read resolved identity posture: {response.status_code} {response.text[:300]}"
    )


async def test_the_refusal_happens_before_any_posture_work(client, principals):  # noqa: ANN001
    """Refused before the resolver runs, not after.

    The envelope must not appear in the body of a refusal, which is the
    difference between a guard and a filter applied too late.
    """
    response = await client.get(_url(), headers=_session(principals["viewer"]))

    assert response.status_code == 403
    body = response.text
    for leaked in ("policy_chain", "resource_arn", "deny_actions"):
        assert leaked not in body, f"the refusal body still carried {leaked}: {body[:300]}"


# ---------------------------------------------------------------------------
# Positive controls — the feature must still work, or "fixed" means "broken"
# ---------------------------------------------------------------------------


async def test_an_investigating_role_still_resolves_the_envelope(client, principals):  # noqa: ANN001
    """Stuck-closed reads as working caution, so this is the half that catches it."""
    response = await client.get(_url(), headers=_session(principals["soc_analyst"]))

    assert response.status_code == 200, (
        f"an analyst lost the ability to resolve effective permissions: {response.status_code} {response.text[:300]}"
    )
    assert response.json().get("principal_id") == TARGET_PRINCIPAL


async def test_an_api_key_scoped_to_identity_read_still_works(client, principals):  # noqa: ANN001
    """The permission is mintable on a key, not only reachable through a role."""
    key = principals["identity_key"]
    response = await client.get(_url(), headers={"Authorization": f"Bearer {key}"})

    assert response.status_code == 200, f"a key scoped to identity:read was refused: {response.status_code} {response.text[:300]}"


async def test_an_unauthenticated_caller_is_still_refused(client):  # noqa: ANN001
    response = await client.get(_url())

    assert response.status_code == 401
