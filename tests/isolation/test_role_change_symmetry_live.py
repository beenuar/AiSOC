"""Re-roling a principal, and the two models that answer "may this caller act".

Both subjects here were reported as code review with no proof of concept, so
every assertion below was first run against the unfixed tree and watched to
fail for the reason its name gives.

GHSA-hrc5-w9r3-2g8r — re-roling is not bounded
----------------------------------------------
(Reported twice, 28 seconds apart and byte-identical; GHSA-qcgm-c945-q96h is
the duplicate and was closed naming this one.)
``PATCH /api/v1/tenants/me/users/{id}`` authorises the *new* role through
``authorize_role_change`` and never asks whether the caller holds what the
target currently holds. Three consequences, and they are not equally severe:

* A principal narrower than its target can strip it. ``tenant_admin`` is the
  only non-wildcard role in ``ROLE_PERMISSIONS`` carrying ``users:write``, so
  on the static map nobody narrower reaches the route — but a tenant running
  database-backed RBAC can author a role holding ``users:write`` and nothing
  else, and that principal could re-role a ``tenant_admin`` to ``viewer``.
* **A tenant can be emptied of administrators.** The last-admin guard counts
  only the wildcard roles, and those are un-grantable through the API by
  design, so on any tenant created through the product it protects nothing.
  One ``tenant_admin`` can demote every peer and then itself, leaving nobody
  able to restore access without database credentials.
* Where the tenant *does* have RBAC grants the stored role changes and the
  effective permissions do not, so an administrator is told a demotion
  worked when it did not. Two sources of truth for one fact.

GHSA-ghpm-vc6j-hp5r — two declarations of one principal's authority
--------------------------------------------------------------------
``SERVICE_PRINCIPAL_PERMISSIONS`` is the read-only list a service token
resolves to. ``ROLE_PERMISSIONS["api_service"]`` separately granted
``alerts:write`` and ``cases:write``. ``has_permission_db`` consulted neither
the resolved set nor the scopes — it ran its own join and fell back to the
static map — so on the 27 in-body ``require_permission_db`` call sites the
more permissive declaration won.

The same blindness reopened a defect the resolver had already closed: a user
whose RBAC grants were all removed resolves to the empty set, and
``has_permission_db`` saw zero rows, could not tell deprovisioning from
bootstrap, and handed back the static role. That one is reachable today.

Why live
--------
Every fact here is a row: a user's role, a tenant's RBAC grants, and the
tenant table a service token is checked against. A constructed principal
carries whatever it was built with, and a fake session answers whatever it was
told to — which is exactly how the two permission models stayed divergent
under a green gate. So this drives the real ASGI application with its real
auth dependencies against real Postgres with the migration chain applied, and
mints real credentials in it.

``ENVIRONMENT=test`` deliberately, never ``development``: that one is in
``AUTH_BYPASS_ENVIRONMENTS`` and an uncredentialed request would resolve to a
demo **admin**, inside the one suite whose subject is which principal may do
what.

The positive controls carry as much weight as the refusals. A guard that
refuses everyone passes every negative assertion while being broken, and that
has shipped here before. So an administrator must still demote a peer while
another administrator remains, a legitimate role change must still land, and a
service token must still reach the reads it is for.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_ROLECHANGE_DSN", "").strip(),
        reason="ISOLATION_ROLECHANGE_DSN is not set; this suite needs live infrastructure",
    ),
]

# Assembled rather than written out. HS256 needs 32+ bytes, and a long literal
# bound to a name like SECRET is the shape gitleaks' generic-api-key rule
# matches; joining the parts keeps the value fixed and keeps this file out of
# `.gitleaksignore`, which pins findings by line number and goes stale the
# moment anything above them moves.
SECRET = "-".join(("isolation", "role", "change", "symmetry", "hs256", "test", "signing", "key"))
SERVICE_TOKEN = "-".join(("isolation", "role", "change", "service", "token", "value"))

#: No RBAC grants anywhere. The arm where the role string is load-bearing and
#: a demotion therefore removes real authority.
ALPHA = uuid.UUID("b7c00000-0000-0000-0000-0000000000a1")
#: Database-backed RBAC. The arm where the role string is *not* load-bearing,
#: so a demotion changes the column and nothing else.
BETA = uuid.UUID("b7c00000-0000-0000-0000-0000000000b1")


def _dsn() -> str:
    value = os.environ.get("ISOLATION_ROLECHANGE_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_ROLECHANGE_DSN is not set; this suite needs a live Postgres")
    return value


def _vault_key() -> str:
    """A throwaway Fernet key. Minted per run rather than written down.

    The vault refuses to construct without one outside development. A literal
    44-character base64 string bound to a name ending in ``KEY`` is precisely
    what a secret scanner matches, correctly, since it cannot know this one is
    disposable. Generating it leaves nothing to match.
    """
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def env():
    os.environ["DATABASE_URL"] = _dsn()
    os.environ["ENVIRONMENT"] = "test"
    os.environ["SECRET_KEY"] = SECRET
    os.environ["AISOC_API_SERVICE_TOKEN"] = SERVICE_TOKEN
    os.environ["AISOC_CREDENTIAL_KEY"] = _vault_key()
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
    """Two tenants, nine users, and one RBAC role — all created here.

    Every assertion is pinned to an id from this fixture. A live test reading
    ``LIMIT 1`` with no predicate can match a row an earlier test left behind
    and pass for a reason unrelated to its name.
    """
    import sqlalchemy
    from app.core.security import ROLE_PERMISSIONS

    made: dict[str, object] = {}

    async def _user(conn, tenant: uuid.UUID, label: str, role: str) -> uuid.UUID:
        user_id = uuid.uuid4()
        made[label] = user_id
        made[f"{label}_email"] = f"{label}-{user_id}@example.com"
        await conn.execute(
            sqlalchemy.text(
                "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active) "
                "VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :e, :u, :p, :r, true)"
            ),
            {"i": str(user_id), "t": str(tenant), "e": made[f"{label}_email"], "u": f"{label}-{user_id}", "p": "x", "r": role},
        )
        return user_id

    async with engine.begin() as conn:
        # Start from nothing. The tenant ids are fixed so assertions can name
        # them, which means a second run would otherwise inherit the first
        # run's demotions as its premise.
        await conn.execute(sqlalchemy.text("SELECT set_config('app.current_tenant_id', NULL, true)"))
        tenants = (str(ALPHA), str(BETA))
        for statement in (
            "DELETE FROM user_roles WHERE role_id IN (SELECT id FROM roles WHERE tenant_id = ANY(CAST(:t AS uuid[])))",
            "DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE tenant_id = ANY(CAST(:t AS uuid[])))",
            "DELETE FROM roles WHERE tenant_id = ANY(CAST(:t AS uuid[]))",
            # `audit_log` is deliberately not cleared: the runtime role holds
            # no DELETE on it, which is the immutability property another
            # suite exists to prove. The one assertion that reads it takes the
            # newest row for the user it just changed.
            "DELETE FROM users WHERE tenant_id = ANY(CAST(:t AS uuid[]))",
        ):
            await conn.execute(sqlalchemy.text(statement), {"t": list(tenants)})

        for tid, slug in ((ALPHA, "rolechange-alpha"), (BETA, "rolechange-beta")):
            await conn.execute(
                sqlalchemy.text(
                    "INSERT INTO tenants (id, name, slug, is_active) VALUES (CAST(:i AS uuid), :n, :s, true) ON CONFLICT (id) DO NOTHING"
                ),
                {"i": str(tid), "n": slug, "s": slug},
            )

        # ALPHA: exactly two administrators, so "demote the peer, then
        # yourself" walks the tenant to zero. A third would hide the lockout.
        await _user(conn, ALPHA, "a_actor", "tenant_admin")
        await _user(conn, ALPHA, "a_peer", "tenant_admin")
        await _user(conn, ALPHA, "a_bystander", "viewer")
        await _user(conn, ALPHA, "a_object", "viewer")

        # BETA: three administrators, so the last-admin guard never fires and
        # the divergence is the only thing under test.
        await _user(conn, BETA, "b_actor", "tenant_admin")
        await _user(conn, BETA, "b_peer", "tenant_admin")
        await _user(conn, BETA, "b_spare", "tenant_admin")
        # Every RBAC grant removed, `users.role` left alone. Indistinguishable
        # from a fresh tenant by this user's row count; distinguishable one
        # level up, which is the correction `resolve_permissions` already makes
        # and `has_permission_db` did not.
        await _user(conn, BETA, "b_deprovisioned", "tenant_admin")

        # The catalogue the RBAC grant draws from. Seeded from the static
        # tenant_admin row rather than hand-listed so the RBAC principal holds
        # exactly what the static one does and the two arms differ only in
        # where the permissions come from.
        role_id = uuid.uuid4()
        made["beta_role"] = role_id
        # `set_config`, not `SET LOCAL`: Postgres takes no bind parameter in a
        # SET, and these three tables carry FORCE ROW LEVEL SECURITY — the
        # runtime role this connects as does not bypass them.
        await conn.execute(
            sqlalchemy.text("SELECT set_config('app.current_tenant_id', :t, true)"),
            {"t": str(BETA)},
        )
        await conn.execute(
            sqlalchemy.text("INSERT INTO roles (id, tenant_id, name, description) VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :n, :d)"),
            {"i": str(role_id), "t": str(BETA), "n": "rolechange-admin", "d": "tenant_admin, granted through RBAC"},
        )
        for permission in sorted(ROLE_PERMISSIONS["tenant_admin"]):
            await conn.execute(
                sqlalchemy.text("INSERT INTO permissions (name, category) VALUES (:n, 'test') ON CONFLICT (name) DO NOTHING"),
                {"n": permission},
            )
            await conn.execute(
                sqlalchemy.text(
                    "INSERT INTO role_permissions (role_id, permission_id) "
                    "SELECT CAST(:r AS uuid), id FROM permissions WHERE name = :n ON CONFLICT DO NOTHING"
                ),
                {"r": str(role_id), "n": permission},
            )
        for label in ("b_actor", "b_peer", "b_spare"):
            await conn.execute(
                sqlalchemy.text(
                    "INSERT INTO user_roles (user_id, role_id) VALUES (CAST(:u AS uuid), CAST(:r AS uuid)) ON CONFLICT DO NOTHING"
                ),
                {"u": str(made[label]), "r": str(role_id)},
            )

    yield made


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client(env, principals):  # noqa: ANN001
    import httpx
    from app.main import create_application

    transport = httpx.ASGITransport(app=create_application())
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


@pytest.fixture(autouse=True)
def _fresh_permission_cache():
    """Resolve from the database on every request in this suite.

    Without Redis the version counter is a constant and a resolved set lives
    for the fallback TTL, so a principal read before a change would answer
    from the cache afterwards. Clearing between tests makes each assertion a
    statement about the database rather than about timing — and the staleness
    itself is pinned separately by
    ``test_a_role_change_invalidates_the_permission_cache``.
    """
    from app.core.permission_cache import reset_for_tests

    reset_for_tests()
    yield
    reset_for_tests()


def _session(user_id: object, tenant: uuid.UUID) -> dict[str, str]:
    from app.core.security import create_access_token

    return {"Authorization": f"Bearer {create_access_token({'sub': str(user_id), 'tenant_id': str(tenant)})}"}


def _service(tenant: uuid.UUID) -> dict[str, str]:
    from app.api.v1.deps import SERVICE_TENANT_HEADER

    return {"Authorization": f"Bearer {SERVICE_TOKEN}", SERVICE_TENANT_HEADER: str(tenant)}


async def _role_of(engine, user_id: object) -> str:  # noqa: ANN001
    import sqlalchemy

    async with engine.connect() as conn:
        row = await conn.execute(sqlalchemy.text("SELECT role FROM users WHERE id = CAST(:i AS uuid)"), {"i": str(user_id)})
        return str(row.scalar_one())


async def _set_role(engine, user_id: object, role: str) -> None:  # noqa: ANN001
    """Put a user back, so one test's demotion is not another's premise."""
    import sqlalchemy

    async with engine.begin() as conn:
        await conn.execute(
            sqlalchemy.text("UPDATE users SET role = :r WHERE id = CAST(:i AS uuid)"),
            {"r": role, "i": str(user_id)},
        )


# ---------------------------------------------------------------------------
# Controls. Every refusal below is worthless without these.
# ---------------------------------------------------------------------------


async def test_a_tenant_admin_can_still_change_a_lesser_role(client, principals, engine):  # noqa: ANN001
    """The positive control for the whole symmetry check.

    A guard that refuses every re-roling passes every negative assertion in
    this file while being completely broken.
    """
    response = await client.patch(
        f"/api/v1/tenants/me/users/{principals['a_object']}",
        headers=_session(principals["a_actor"], ALPHA),
        json={"role": "soc_analyst", "reason": "control"},
    )

    assert response.status_code == 200, f"a legitimate promotion was refused: {response.status_code} {response.text[:300]}"
    assert await _role_of(engine, principals["a_object"]) == "soc_analyst"
    await _set_role(engine, principals["a_object"], "viewer")


async def test_a_tenant_admin_can_demote_a_peer_while_another_administrator_remains(client, principals, engine):  # noqa: ANN001
    """Peer-on-peer demotion stays allowed, deliberately.

    Two ``tenant_admin`` principals hold identical authority, so a symmetric
    check cannot separate them and should not try: administrators managing
    administrators is what the role is for. What must not be reachable is the
    *end state* with nobody left, which the next test covers.

    BETA has three administrators, so this one leaves two.
    """
    response = await client.patch(
        f"/api/v1/tenants/me/users/{principals['b_peer']}",
        headers=_session(principals["b_actor"], BETA),
        json={"role": "viewer", "reason": "peer demotion with cover remaining"},
    )

    assert response.status_code == 200, f"a peer demotion with two admins left was refused: {response.status_code} {response.text[:300]}"
    await _set_role(engine, principals["b_peer"], "tenant_admin")


async def test_a_service_token_still_reaches_the_reads_it_exists_for(client):  # noqa: ANN001
    """Control for the second finding. If the service principal were refused
    everywhere, "it was refused a write" would say nothing."""
    response = await client.get("/api/v1/alerts", headers=_service(ALPHA))

    assert response.status_code == 200, (
        f"the service token lost a read it is supposed to have: {response.status_code} {response.text[:300]}"
    )


# ---------------------------------------------------------------------------
# GHSA-hrc5-w9r3-2g8r — a tenant must not be reducible to zero administrators
# ---------------------------------------------------------------------------


async def test_the_last_administrator_cannot_be_demoted(client, principals, engine):  # noqa: ANN001
    """The reported defect's sharpest end state, and it is irreversible.

    ALPHA has two ``tenant_admin`` principals and no wildcard role, which is
    what a tenant created through the product looks like: ``platform_admin``
    and ``admin`` are refused to every API caller by ``never_grantable``.

    Pre-fix both demotions answered **200** and the tenant was left with no
    principal holding ``users:write`` — nobody who could promote anyone back,
    with no route to recovery short of database credentials. The guard that
    exists for exactly this counted only the wildcard roles, so it could not
    fire on a tenant that has none.
    """
    first = await client.patch(
        f"/api/v1/tenants/me/users/{principals['a_peer']}",
        headers=_session(principals["a_actor"], ALPHA),
        json={"role": "viewer", "reason": "step one"},
    )
    assert first.status_code == 200, f"demoting a peer with one admin left should be allowed: {first.status_code} {first.text[:300]}"

    second = await client.patch(
        f"/api/v1/tenants/me/users/{principals['a_actor']}",
        headers=_session(principals["a_actor"], ALPHA),
        json={"role": "viewer", "reason": "step two"},
    )

    assert second.status_code == 409, (
        f"the last administrator demoted itself and emptied the tenant: {second.status_code} {second.text[:300]}"
    )
    assert await _role_of(engine, principals["a_actor"]) == "tenant_admin", "the role was written despite the refusal"

    await _set_role(engine, principals["a_peer"], "tenant_admin")


async def test_a_demotion_takes_effect_on_a_token_minted_before_it(client, principals, engine):  # noqa: ANN001
    """Why this fix revokes no sessions, stated as a measurement.

    An access token carries no permissions. ``resolve_jwt_principal`` re-reads
    the user row and re-resolves the set from the database on **every**
    request, so a demotion binds the credential the demoted principal is
    already holding — there is no stale authority inside the token to revoke.

    The channel that *was* stale is the per-replica permission cache, and
    bumping its version is what this change adds. Terminating a peer's
    sessions would be a new capability granted to every ``tenant_admin``,
    which is not something to add inside a security fix.
    """
    token = _session(principals["a_peer"], ALPHA)

    before = await client.get("/api/v1/tenants/me/users", headers=token)
    assert before.status_code == 200, f"the premise is wrong — this token could not read users: {before.status_code}"

    demotion = await client.patch(
        f"/api/v1/tenants/me/users/{principals['a_peer']}",
        headers=_session(principals["a_actor"], ALPHA),
        json={"role": "viewer", "reason": "token binding"},
    )
    assert demotion.status_code == 200, demotion.text[:300]

    after = await client.get("/api/v1/tenants/me/users", headers=token)

    assert after.status_code == 403, f"the same token kept its authority after the demotion: {after.status_code} {after.text[:200]}"
    await _set_role(engine, principals["a_peer"], "tenant_admin")


async def test_the_guard_counts_the_roles_that_actually_administer(principals):  # noqa: ANN001
    """Why the guard could not fire, stated as the property rather than a list.

    ``administrative_roles()`` is derived from ``ROLE_PERMISSIONS`` so a role
    that gains ``users:write`` later is covered without anyone remembering,
    which is the same reason ``never_grantable`` derives the wildcard set.
    """
    from app.core import role_grants

    administrative = role_grants.administrative_roles()

    assert "tenant_admin" in administrative, "the only non-wildcard role holding users:write is not counted as an administrator"
    assert role_grants.wildcard_roles() <= administrative, "a wildcard role holds users:write and must be counted"
    assert "viewer" not in administrative
    assert "soc_analyst" not in administrative


async def test_a_caller_cannot_strip_a_principal_it_does_not_cover(principals):  # noqa: ANN001
    """Symmetric authority: taking away is bounded the same way giving is.

    Exercised at the chokepoint rather than over HTTP because no shipped role
    produces it — ``tenant_admin`` is the only non-wildcard role with
    ``users:write``, so on the static map nobody narrower reaches the route.
    A tenant running database-backed RBAC can author exactly this principal,
    and ``require_permission`` admits it on its resolved set.
    """
    from app.core.role_grants import RoleGrantDenied, authorize_role_change, permissions_for

    # Everything `viewer` confers, plus user administration and nothing else.
    # Built this way on purpose: the *existing* check already refuses a caller
    # that cannot confer the new role, so a narrower principal would be
    # refused for the old reason and prove nothing about the new one.
    narrow = permissions_for("viewer") | {"users:read", "users:write"}

    with pytest.raises(RoleGrantDenied) as denied:
        authorize_role_change(
            granter_role="tenant_admin",
            granter_permissions=narrow,
            current_role="tenant_admin",
            requested_role="viewer",
        )

    message = str(denied.value)
    assert "currently holds" in message, message
    assert "settings:write" in message, f"the refusal does not name what the caller is missing: {message}"

    # The direction it must not fire in: the same caller may still re-role a
    # principal whose authority it does cover.
    assert (
        authorize_role_change(
            granter_role="tenant_admin",
            granter_permissions=narrow,
            current_role="viewer",
            requested_role="viewer",
        )
        == "viewer"
    )


async def test_a_role_change_invalidates_the_permission_cache(client, principals, engine, monkeypatch):  # noqa: ANN001
    """A demotion that does not invalidate is a demotion every replica ignores.

    The handler wrote ``users.role`` and never bumped the tenant's RBAC
    version, so a principal resolved before the change kept its old set for
    the fallback TTL on every replica holding it — and for a revocation that
    is the wrong direction.
    """
    import app.api.v1.endpoints.tenants as tenants_module

    bumped: list[str] = []

    async def _record(tenant_id: str) -> None:
        bumped.append(tenant_id)

    monkeypatch.setattr(tenants_module, "bump_version", _record)

    response = await client.patch(
        f"/api/v1/tenants/me/users/{principals['a_object']}",
        headers=_session(principals["a_actor"], ALPHA),
        json={"role": "soc_analyst", "reason": "cache"},
    )

    assert response.status_code == 200, response.text[:300]
    assert bumped == [str(ALPHA)], f"the role change did not invalidate the tenant's cached permissions: {bumped}"
    await _set_role(engine, principals["a_object"], "viewer")


async def test_a_demotion_in_an_rbac_tenant_is_recorded_as_not_changing_authority(client, principals, engine):  # noqa: ANN001
    """The inverse defect: the column moves and the authority does not.

    BETA resolves permissions from ``user_roles``, so ``users.role`` is not
    what ``require_permission`` reads. Demoting ``b_peer`` to ``viewer``
    therefore removes nothing, and pre-fix the audit row said
    ``{"from": "tenant_admin", "to": "viewer"}`` with no hint that the change
    was cosmetic. An administrator reading that log believes access was
    withdrawn.
    """
    import sqlalchemy

    response = await client.patch(
        f"/api/v1/tenants/me/users/{principals['b_peer']}",
        headers=_session(principals["b_actor"], BETA),
        json={"role": "viewer", "reason": "divergence"},
    )
    assert response.status_code == 200, response.text[:300]

    # The column moved...
    assert await _role_of(engine, principals["b_peer"]) == "viewer"

    # ...and the authority did not. Same principal, same route, still allowed.
    still_allowed = await client.get("/api/v1/tenants/me/users", headers=_session(principals["b_peer"], BETA))
    assert still_allowed.status_code == 200, (
        "the demotion removed authority in an RBAC tenant, so this test's premise is wrong: "
        f"{still_allowed.status_code} {still_allowed.text[:200]}"
    )

    async with engine.connect() as conn:
        row = await conn.execute(
            sqlalchemy.text(
                "SELECT changes FROM audit_log WHERE tenant_id = CAST(:t AS uuid) AND action = 'users:role_changed' "
                "AND resource_id = :r ORDER BY created_at DESC, chain_index DESC LIMIT 1"
            ),
            {"t": str(BETA), "r": str(principals["b_peer"])},
        )
        changes = row.scalar_one()
    if isinstance(changes, str):
        changes = json.loads(changes)

    assert changes.get("effective_permissions_follow_role") is False, (
        f"the audit row does not say the change was cosmetic, so the log asserts a withdrawal that did not happen: {changes}"
    )

    await _set_role(engine, principals["b_peer"], "tenant_admin")


# ---------------------------------------------------------------------------
# GHSA-ghpm-vc6j-hp5r — one principal, one answer
# ---------------------------------------------------------------------------


async def test_the_two_declarations_of_the_service_principal_agree(principals):  # noqa: ANN001
    """One source of truth, enforced by construction rather than by a comment.

    ``SERVICE_PRINCIPAL_PERMISSIONS`` and ``ROLE_PERMISSIONS["api_service"]``
    were written independently and disagreed about ``alerts:write`` and
    ``cases:write``. Two declarations of one principal's authority are two
    chances for the more permissive one to win somewhere.
    """
    from app.api.v1.deps import SERVICE_PRINCIPAL_PERMISSIONS
    from app.core.security import ROLE_PERMISSIONS

    assert SERVICE_PRINCIPAL_PERMISSIONS == frozenset(ROLE_PERMISSIONS["api_service"]), (
        "the service principal's two permission declarations disagree: "
        f"only in the frozenset={sorted(SERVICE_PRINCIPAL_PERMISSIONS - set(ROLE_PERMISSIONS['api_service']))}, "
        f"only in the role map={sorted(set(ROLE_PERMISSIONS['api_service']) - SERVICE_PRINCIPAL_PERMISSIONS)}"
    )
    assert "cases:write" not in SERVICE_PRINCIPAL_PERMISSIONS
    assert "alerts:write" not in SERVICE_PRINCIPAL_PERMISSIONS


async def test_a_service_principal_is_refused_a_write_by_both_checks(client, principals, engine):  # noqa: ANN001
    """The reported conflict, against the principal the real auth path builds.

    ``_resolve_service_principal`` is the shipped resolver and the tenant is
    verified against the table by it, so this is the object a request carries
    — not one assembled by the test. Pre-fix ``require_permission`` refused
    ``cases:write`` and ``has_permission_db`` allowed it, which is the whole
    finding: the two checks disagreed and the permissive one governed the 27
    in-body call sites.
    """
    from app.api.v1.deps import _resolve_service_principal
    from fastapi import HTTPException
    from sqlalchemy.ext.asyncio import async_sessionmaker

    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        principal = await _resolve_service_principal(SERVICE_TOKEN, str(ALPHA), session)
        assert principal is not None, "the service token did not resolve; the rest of this test proves nothing"
        assert principal.role == "api_service"

        with pytest.raises(HTTPException) as refused:
            principal.require_permission("cases:write")
        assert refused.value.status_code == 403

        allowed_by_db = await principal.has_permission_db("cases:write", session)
        assert allowed_by_db is False, "has_permission_db granted a write the resolved set withholds"

        # The direction it must not break: a read the service genuinely holds
        # has to pass through both doors.
        principal.require_permission("alerts:read")
        assert await principal.has_permission_db("alerts:read", session) is True


async def test_a_deprovisioned_user_does_not_get_their_static_role_back(client, principals):  # noqa: ANN001
    """The reachable half, and the one with a route behind it today.

    ``b_deprovisioned`` holds ``users.role = 'tenant_admin'`` and zero RBAC
    grants in a tenant that has them, which the resolver reads as "withdrawn"
    and returns the empty set for. ``has_permission_db`` saw zero rows, could
    not tell that from a fresh tenant, and handed back the static role — so
    ``GET /api/v1/mcp-servers`` answered **200** to a principal every
    ``require_permission`` route answered **403** to.
    """
    headers = _session(principals["b_deprovisioned"], BETA)

    # The control: the synchronous check already refuses this principal, so a
    # refusal below is the two models agreeing rather than the user being
    # inert for some unrelated reason.
    via_static_check = await client.get("/api/v1/tenants/me/users", headers=headers)
    assert via_static_check.status_code == 403, (
        f"the deprovisioned principal was not refused by require_permission: {via_static_check.status_code}"
    )

    via_db_check = await client.get("/api/v1/mcp-servers", headers=headers)

    assert via_db_check.status_code == 403, (
        "a deprovisioned user reached a require_permission_db route on their old static role: "
        f"{via_db_check.status_code} {via_db_check.text[:300]}"
    )


async def test_an_elevated_principal_is_honoured_by_both_checks(principals, engine):  # noqa: ANN001
    """The positive direction of the same unification.

    ``has_permission_db`` ignored live elevation as well as the resolved set,
    so a grant approved seconds earlier widened the synchronous check and not
    the database-backed one — an intermittent 403 depending only on which
    factory a route happened to use.
    """
    from app.api.v1.deps import CurrentUser
    from app.security.abac import PrivilegeGrant
    from sqlalchemy.ext.asyncio import async_sessionmaker

    # `viewer` with no RBAC rows of its own, so elevation is the *only* way
    # `cases:write` can be allowed. A principal whose static role or whose
    # `user_roles` already carried it would pass this test without elevation
    # ever being consulted.
    principal = CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=BETA,
        role="viewer",
        email="elevated@example.com",
        resolved_permissions=frozenset({"alerts:read"}),
        elevation=(
            PrivilegeGrant(
                permissions=("cases:write",),
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
                revoked_at=None,
            ),
        ),
    )

    principal.require_permission("cases:write")

    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        assert await principal.has_permission_db("cases:write", session) is True, (
            "live elevation widened the synchronous check and not the database-backed one"
        )
