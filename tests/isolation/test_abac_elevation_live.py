"""ABAC conditions, time-boxed elevation and workload identities, live.

Depth plan item 8.2. Migration ``087_enterprise_iam.sql`` created three
tables — ``permission_conditions``, ``privilege_grants`` and
``workload_identities`` — and shipped **no reader for any of them**. The
repository said so itself: ``CHANGELOG.md`` records "nothing reads any of
them", and ``FIX_PASS_PROGRESS.md`` retracted the claim. ``app/security/abac.py``
is a complete, tested evaluator whose only importer was
``role_grants.narrow_by_conditions``, which had no caller either.

A table with no reader cannot be distinguished from a working control by any
offline suite, because the offline suite mocks the database the reader would
have queried. So this drives the real application against real Postgres with
every migration applied, mints real JWTs, and asks the question at the only
layer that answers it: what status code does the route return?

Production posture, deliberately
--------------------------------
``ENVIRONMENT=production``. ``development`` is in ``AUTH_BYPASS_ENVIRONMENTS``,
so an uncredentialed request there resolves to a demo **admin** — inside the
one suite whose purpose is proving that authorization narrows, that would make
every assertion pass for the wrong reason.

Both directions, every time
---------------------------
An authorization control is only proven by its refusal, so each capability is
asserted in both directions:

* a condition that does not match **denies**, and the same request with no
  condition configured **succeeds** — otherwise a route that 403s on
  everything would satisfy the first assertion;
* an elevation grant **allows** a permission the role lacks, and the same
  grant **expired** or **revoked** denies it again;
* a workload credential **authenticates** and a revoked one does not.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_IAM_DSN", "").strip(),
        reason="ISOLATION_IAM_DSN is not set; this suite needs a live Postgres",
    ),
]

#: The test client's peer address under ``httpx.ASGITransport``. Conditions
#: are written to match or miss it deliberately rather than by luck.
CLIENT_IP = "127.0.0.1"
MATCHING_CIDR = "127.0.0.0/8"
MISSING_CIDR = "10.0.0.0/8"

SIGNING_SECRET = "isolation-iam-signing-secret-at-least-32-characters"


def _dsn() -> str:
    value = os.environ.get("ISOLATION_IAM_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_IAM_DSN is not set")
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def app_client():
    """The real application, in production posture, against real Postgres."""
    pytest.importorskip("httpx")
    os.environ["DATABASE_URL"] = _dsn()
    os.environ["ENVIRONMENT"] = "production"
    os.environ["SECRET_KEY"] = SIGNING_SECRET
    # No trusted proxies, so `resolve_client_ip` returns the direct peer and
    # an X-Forwarded-For header cannot move a principal into a permitted
    # range. That property gets its own assertion below.
    os.environ.pop("AISOC_TRUSTED_PROXIES", None)

    import httpx
    from app.main import create_application

    application = create_application()
    transport = httpx.ASGITransport(app=application, client=(CLIENT_IP, 51234))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def pool():
    asyncpg = pytest.importorskip("asyncpg")
    created = await asyncpg.create_pool(_dsn().replace("postgresql+asyncpg://", "postgresql://"), min_size=1, max_size=4)
    yield created
    await created.close()


@pytest.fixture(autouse=True)
def _clean_permission_cache():
    """A resolved set cached from a previous test would answer the next one.

    The cache is keyed on an RBAC version counter the production grant paths
    bump; these tests write rows with SQL, so they clear it by hand.
    """
    from app.core.permission_cache import reset_for_tests

    reset_for_tests()
    yield
    reset_for_tests()


async def _tenant_with_user(pool, *, role: str) -> tuple[str, str]:
    """A tenant and one active user holding ``role``, by raw SQL.

    No RBAC rows, so `resolve_permissions` takes its documented bootstrap
    path and the static map answers — which is the configuration almost every
    deployment is in, and therefore the one an attribute condition has to
    narrow.
    """
    tenant_id, user_id = str(uuid.uuid4()), str(uuid.uuid4())
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1::uuid, $2, $3)",
            tenant_id,
            "iam-depth-82",
            f"iam82-{tenant_id[:8]}",
        )
        await conn.execute(
            """
            INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active)
            VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, TRUE)
            """,
            user_id,
            tenant_id,
            f"u-{user_id[:8]}@iam82.test",
            f"u-{user_id[:8]}",
            "x" * 60,
            role,
        )
    return tenant_id, user_id


def _token(user_id: str, tenant_id: str) -> str:
    """A real access token, signed with the key the server verifies against."""
    from app.core.security import create_access_token

    return create_access_token({"sub": user_id, "tenant_id": tenant_id})


def _auth(user_id: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(user_id, tenant_id)}"}


async def _condition(pool, tenant_id: str, *, permission: str, operator: str, value) -> None:  # noqa: ANN001
    import json

    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO permission_conditions (tenant_id, permission, condition, description, enabled)
            VALUES ($1::uuid, $2, $3::jsonb, $4, TRUE)
            """,
            tenant_id,
            permission,
            json.dumps({"operator": operator, "value": value}),
            f"{operator} on {permission}",
        )


async def _grant(
    pool,
    tenant_id: str,
    user_id: str,
    *,
    permissions: list[str],
    expires_in: timedelta = timedelta(minutes=30),
    revoked: bool = False,
    approved: bool = True,
) -> str:
    """One elevation row. ``approved`` defaults on; the off case is a test.

    A row with ``approved_by_id IS NULL`` is a *request*, not a grant, and
    must confer nothing — otherwise approval is a record rather than a gate.
    """
    approver = None
    if approved:
        _, approver = await _tenant_with_user(pool, role="tenant_admin")
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO privilege_grants
                (tenant_id, user_id, permissions, justification, approved_by_id, expires_at, revoked_at)
            VALUES ($1::uuid, $2::uuid, $3::text[], $4, $5::uuid, $6, $7)
            RETURNING id
            """,
            tenant_id,
            user_id,
            permissions,
            "isolation suite",
            approver,
            datetime.now(UTC) + expires_in,
            datetime.now(UTC) if revoked else None,
        )
    return str(row["id"])


def _case_body() -> dict:
    return {"title": f"iam-82 {uuid.uuid4().hex[:8]}", "severity": "low"}


class TestAnAttributeConditionNarrowsThePermission:
    """`permission_conditions` had no reader, so every row in it was inert."""

    async def test_a_condition_that_does_not_match_denies(self, app_client, pool) -> None:  # noqa: ANN001
        """The reproduce case.

        A `tenant_admin` holds `cases:write` statically. A condition
        restricting that permission to a CIDR the caller is not in must refuse
        the request. Against the pre-fix tree the row is never read and the
        case is created — a 201 where the operator configured a denial.
        """
        tenant_id, user_id = await _tenant_with_user(pool, role="tenant_admin")
        await _condition(pool, tenant_id, permission="cases:write", operator="ip_in_cidr", value=MISSING_CIDR)

        resp = await app_client.post("/api/v1/cases", headers=_auth(user_id, tenant_id), json=_case_body())

        assert resp.status_code == 403, (
            f"a permission_conditions row restricting cases:write to {MISSING_CIDR} did not refuse a "
            f"caller from {CLIENT_IP}; got {resp.status_code}. The table has no reader."
        )

    async def test_with_no_condition_configured_the_same_request_succeeds(self, app_client, pool) -> None:  # noqa: ANN001
        """The negative control for the assertion above.

        Without this, a route that refused everything would satisfy it.
        """
        tenant_id, user_id = await _tenant_with_user(pool, role="tenant_admin")

        resp = await app_client.post("/api/v1/cases", headers=_auth(user_id, tenant_id), json=_case_body())

        assert resp.status_code == 201, f"an unconditioned cases:write was refused ({resp.status_code}): {resp.text[:300]}"

    async def test_a_condition_that_matches_allows(self, app_client, pool) -> None:  # noqa: ANN001
        """Conditions narrow; a satisfied one must not itself become a denial."""
        tenant_id, user_id = await _tenant_with_user(pool, role="tenant_admin")
        await _condition(pool, tenant_id, permission="cases:write", operator="ip_in_cidr", value=MATCHING_CIDR)

        resp = await app_client.post("/api/v1/cases", headers=_auth(user_id, tenant_id), json=_case_body())

        assert resp.status_code == 201, f"a satisfied condition refused the request ({resp.status_code}): {resp.text[:300]}"

    async def test_a_condition_on_another_permission_does_not_leak(self, app_client, pool) -> None:  # noqa: ANN001
        """A condition is scoped to the permission it names.

        An evaluator that applied every row to every check would make one
        narrow rule a tenant-wide outage.
        """
        tenant_id, user_id = await _tenant_with_user(pool, role="tenant_admin")
        await _condition(pool, tenant_id, permission="rules:write", operator="ip_in_cidr", value=MISSING_CIDR)

        resp = await app_client.post("/api/v1/cases", headers=_auth(user_id, tenant_id), json=_case_body())

        assert resp.status_code == 201, f"a condition on rules:write refused cases:write ({resp.status_code})"

    async def test_a_forwarded_header_cannot_move_the_caller_into_the_permitted_range(self, app_client, pool) -> None:  # noqa: ANN001
        """The attribute must not be one the caller can set.

        With no trusted proxies configured, `X-Forwarded-For` is ignored, so a
        caller cannot satisfy an address condition by claiming an address.
        """
        tenant_id, user_id = await _tenant_with_user(pool, role="tenant_admin")
        await _condition(pool, tenant_id, permission="cases:write", operator="ip_in_cidr", value=MISSING_CIDR)

        headers = {**_auth(user_id, tenant_id), "X-Forwarded-For": "10.1.2.3"}
        resp = await app_client.post("/api/v1/cases", headers=headers, json=_case_body())

        assert resp.status_code == 403, f"a caller satisfied an address condition by sending X-Forwarded-For; got {resp.status_code}"

    async def test_a_disabled_condition_is_not_applied(self, app_client, pool) -> None:  # noqa: ANN001
        """`enabled = FALSE` is how an operator turns a rule off without deleting it."""
        tenant_id, user_id = await _tenant_with_user(pool, role="tenant_admin")
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO permission_conditions (tenant_id, permission, condition, enabled)
                VALUES ($1::uuid, 'cases:write', '{"operator": "ip_in_cidr", "value": "10.0.0.0/8"}'::jsonb, FALSE)
                """,
                tenant_id,
            )

        resp = await app_client.post("/api/v1/cases", headers=_auth(user_id, tenant_id), json=_case_body())

        assert resp.status_code == 201, f"a disabled condition was still enforced ({resp.status_code})"

    async def test_another_tenants_condition_does_not_apply(self, app_client, pool) -> None:  # noqa: ANN001
        """Conditions are tenant-scoped, and a reader that forgot the predicate
        would let one tenant's policy refuse another tenant's work."""
        victim_tenant, victim_user = await _tenant_with_user(pool, role="tenant_admin")
        other_tenant, _ = await _tenant_with_user(pool, role="tenant_admin")
        await _condition(pool, other_tenant, permission="cases:write", operator="ip_in_cidr", value=MISSING_CIDR)

        resp = await app_client.post("/api/v1/cases", headers=_auth(victim_user, victim_tenant), json=_case_body())

        assert resp.status_code == 201, f"another tenant's condition refused this tenant's request ({resp.status_code})"


class TestElevationIsTimeBoxed:
    """`privilege_grants` had no reader, so an approved elevation did nothing."""

    async def test_a_live_grant_confers_a_permission_the_role_lacks(self, app_client, pool) -> None:  # noqa: ANN001
        """The reproduce case. A viewer does not hold `roles:read`."""
        from app.core.security import ROLE_PERMISSIONS

        assert "roles:read" not in ROLE_PERMISSIONS["viewer"]

        tenant_id, user_id = await _tenant_with_user(pool, role="viewer")
        await _grant(pool, tenant_id, user_id, permissions=["roles:read"])

        resp = await app_client.get("/api/v1/rbac/roles", headers=_auth(user_id, tenant_id))

        assert resp.status_code == 200, (
            f"a live privilege_grants row conferring roles:read did not take effect; got {resp.status_code}. The table has no reader."
        )

    async def test_without_a_grant_the_same_call_is_refused(self, app_client, pool) -> None:  # noqa: ANN001
        """The negative control: the viewer really does lack the permission."""
        tenant_id, user_id = await _tenant_with_user(pool, role="viewer")

        resp = await app_client.get("/api/v1/rbac/roles", headers=_auth(user_id, tenant_id))

        assert resp.status_code == 403, f"a viewer read the roles screen with no elevation ({resp.status_code})"

    async def test_an_expired_grant_is_refused(self, app_client, pool) -> None:  # noqa: ANN001
        """Automatic expiry, checked at use.

        A sweep job that revokes grants is a job that can be down, and a grant
        outliving its window because a worker crashed is the failure mode JIT
        elevation exists to remove.
        """
        tenant_id, user_id = await _tenant_with_user(pool, role="viewer")
        await _grant(pool, tenant_id, user_id, permissions=["roles:read"], expires_in=timedelta(minutes=-1))

        resp = await app_client.get("/api/v1/rbac/roles", headers=_auth(user_id, tenant_id))

        assert resp.status_code == 403, f"an expired elevation still conferred roles:read ({resp.status_code})"

    async def test_a_revoked_grant_is_refused(self, app_client, pool) -> None:  # noqa: ANN001
        tenant_id, user_id = await _tenant_with_user(pool, role="viewer")
        await _grant(pool, tenant_id, user_id, permissions=["roles:read"], revoked=True)

        resp = await app_client.get("/api/v1/rbac/roles", headers=_auth(user_id, tenant_id))

        assert resp.status_code == 403, f"a revoked elevation still conferred roles:read ({resp.status_code})"

    async def test_an_unapproved_request_confers_nothing(self, app_client, pool) -> None:  # noqa: ANN001
        """Approval is a gate, not a record.

        A row with no approver is a *request*. If it conferred anything, the
        requester would be approving their own elevation by writing it.
        """
        tenant_id, user_id = await _tenant_with_user(pool, role="viewer")
        await _grant(pool, tenant_id, user_id, permissions=["roles:read"], approved=False)

        resp = await app_client.get("/api/v1/rbac/roles", headers=_auth(user_id, tenant_id))

        assert resp.status_code == 403, f"an unapproved elevation request conferred roles:read ({resp.status_code})"

    async def test_a_grant_to_another_user_does_not_elevate_this_one(self, app_client, pool) -> None:  # noqa: ANN001
        tenant_id, user_id = await _tenant_with_user(pool, role="viewer")
        _, other_user = await _tenant_with_user(pool, role="viewer")
        await _grant(pool, tenant_id, other_user, permissions=["roles:read"])

        resp = await app_client.get("/api/v1/rbac/roles", headers=_auth(user_id, tenant_id))

        assert resp.status_code == 403, f"one user's elevation elevated another ({resp.status_code})"

    async def test_an_elevated_permission_is_still_subject_to_conditions(self, app_client, pool) -> None:  # noqa: ANN001
        """Elevation and narrowing compose in the right order.

        If a grant were applied after conditions, elevation would be a way
        around every attribute rule a tenant configured.
        """
        tenant_id, user_id = await _tenant_with_user(pool, role="viewer")
        await _grant(pool, tenant_id, user_id, permissions=["roles:read"])
        await _condition(pool, tenant_id, permission="roles:read", operator="ip_in_cidr", value=MISSING_CIDR)

        resp = await app_client.get("/api/v1/rbac/roles", headers=_auth(user_id, tenant_id))

        assert resp.status_code == 403, f"an elevated permission escaped an attribute condition ({resp.status_code})"


class TestWorkloadIdentitiesAuthenticateAService:
    """`workload_identities` had no reader, so a row in it authenticated nothing."""

    async def _mint(self, pool, *, service: str, scopes: list[str]) -> str:
        from app.services.workload_identity import mint_workload_secret

        secret, prefix, digest = mint_workload_secret()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO workload_identities (service, description, scopes, secret_hash, secret_prefix)
                VALUES ($1, $2, $3::text[], $4, $5)
                """,
                service,
                "isolation suite",
                scopes,
                digest,
                prefix,
            )
        return secret

    async def test_a_workload_credential_authenticates_for_the_declared_tenant(self, app_client, pool) -> None:  # noqa: ANN001
        """The reproduce case: a row in the table is a usable credential."""
        from app.api.v1.deps import SERVICE_TENANT_HEADER

        tenant_id, _ = await _tenant_with_user(pool, role="viewer")
        secret = await self._mint(pool, service="agents", scopes=["alerts:read"])

        resp = await app_client.get(
            "/api/v1/alerts",
            headers={"Authorization": f"Bearer {secret}", SERVICE_TENANT_HEADER: tenant_id},
        )

        assert resp.status_code == 200, f"a workload identity did not authenticate; got {resp.status_code}. The table has no reader."

    async def test_a_workload_credential_naming_no_tenant_is_refused(self, app_client, pool) -> None:  # noqa: ANN001
        """One shared credential across tenants is a cross-tenant read, so the
        tenant is mandatory and absent means refuse, never 'no filter'."""
        secret = await self._mint(pool, service="agents", scopes=["alerts:read"])

        resp = await app_client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {secret}"})

        assert resp.status_code == 403, f"a workload credential with no tenant header was served ({resp.status_code})"

    async def test_a_revoked_workload_credential_is_refused(self, app_client, pool) -> None:  # noqa: ANN001
        from app.api.v1.deps import SERVICE_TENANT_HEADER

        tenant_id, _ = await _tenant_with_user(pool, role="viewer")
        secret = await self._mint(pool, service="agents", scopes=["alerts:read"])
        async with pool.acquire() as conn:
            await conn.execute("UPDATE workload_identities SET revoked_at = NOW() WHERE secret_prefix = $1", secret[:16])

        resp = await app_client.get(
            "/api/v1/alerts",
            headers={"Authorization": f"Bearer {secret}", SERVICE_TENANT_HEADER: tenant_id},
        )

        assert resp.status_code == 401, f"a revoked workload credential still authenticated ({resp.status_code})"

    async def test_a_workload_credential_is_held_to_its_own_scopes(self, app_client, pool) -> None:  # noqa: ANN001
        """A per-service credential exists so the ingest pipeline does not
        present the same authority as the agents worker."""
        from app.api.v1.deps import SERVICE_TENANT_HEADER

        tenant_id, _ = await _tenant_with_user(pool, role="viewer")
        secret = await self._mint(pool, service="ingest", scopes=["alerts:read"])

        resp = await app_client.post(
            "/api/v1/cases",
            headers={"Authorization": f"Bearer {secret}", SERVICE_TENANT_HEADER: tenant_id},
            json=_case_body(),
        )

        assert resp.status_code == 403, (
            f"a workload credential scoped to alerts:read created a case ({resp.status_code}); scopes are not enforced"
        )
