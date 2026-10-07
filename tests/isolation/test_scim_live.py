"""SCIM provisioning against the real application and a real Postgres.

Maturity: the evidence that takes **SCIM 2.0, white-label, usage
metering** to Stable.
See `docs/audit/MATURITY_DEFINITION.md` for what the label requires.

Why the offline suite is not enough
------------------------------------
`services/api/tests/test_scim_provisioning.py` is 40 good tests and two
things about its harness make it unable to certify this capability:

**It runs on `sqlite+aiosqlite:///:memory:` with `@compiles` shims** that
translate `JSONB`, `UUID`, `INET` and `ARRAY` into something SQLite will
accept. Those four types are where Postgres and SQLite disagree most, and
a shim that makes a column *accept* a value is not evidence the real
column stores or queries it. This repository has already shipped one
defect of exactly that shape — a query naming two columns the table does
not have, green across thirty tests against a fake.

**It builds its own `FastAPI()` and mounts the router alone.** So the
production middleware stack, the exception handlers and the real
dependency overrides are not what the assertions run through. A 401 that
the app's own handler would turn into a SCIM-shaped error body is not
exercised.

This suite uses `app.main:create_application` and real Postgres, so the
types, the constraints, the middleware and the auth are the ones a
deployment runs.

What it covers, and why the three additions matter
---------------------------------------------------
Create, list and discovery were here from the start. PATCH, group
membership and deactivation were not, and those are the three operations
whose correctness depends on the things SQLite cannot reproduce:

* **PATCH** is how both providers deactivate, and the two send the value
  in incompatible shapes — Okta an object with no `path` and a lowercase
  `op`, Entra an explicit `path` and the *string* `"False"`, for which
  `bool("False")` is `True`. The effect is a write to `users.is_active`
  and a `TIMESTAMPTZ` stamp, neither of which a shimmed column proves.
* **Group membership** writes `aisoc_scim_group_members`, a composite
  primary key over two `UUID` columns with cascading foreign keys. The
  offline harness compiles both types away, and the two providers remove
  a member in opposite arrangements (Okta through a path filter with no
  value, Entra with `path: "members"` and the id in a value array).
* **Deactivation** is the one that has to be true: it revokes API keys by
  count, stamps `sessions_revoked_at`, and `DELETE` must deactivate
  rather than erase. The whole point is a row that survives with access
  withdrawn, which only a real foreign-key graph can demonstrate.

The negative control
--------------------
`test_an_unauthenticated_request_is_refused` and
`test_another_tenants_token_cannot_read_these_users` are what stop the
positive assertions passing for the wrong reason: a surface that returned
everything to everyone would satisfy "the user I created is listed".
`TestGroupsAreTenantScoped` does the same for the group surface, which has
its own list handler and would not be covered by the user one.
"""

from __future__ import annotations

import ast
import os
import pathlib
import uuid

import pytest
import pytest_asyncio

# One event loop for the whole module, and the application built once in
# it.
#
# `create_application()` opens engines bound to the loop that built it.
# With a loop per test, the second test closes the first loop while the
# first app's pool still holds connections, and every subsequent test
# dies with "Event loop is closed" — a message about the harness that
# says nothing about the code. Each test still gets its own tenants, so
# they remain independent of one another.
# Skip as a *module*, not only in the fixture.
#
# The offline isolation job collects this directory with no stores
# running. With the skip only in the fixture, any test that does not take
# it ran anyway and failed there — which is a failure about the harness,
# reported against a capability.
pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_SCIM_DSN", "").strip(),
        reason="ISOLATION_SCIM_DSN is not set; this suite needs live infrastructure",
    ),
]

# A skip in a job that exists to run live is a green report over nothing.
#
# The skip above is right for the offline collection job and wrong for
# `scim-live.yml`, and pytest cannot tell them apart — so the live job sets
# this flag and the suite refuses to collect rather than skipping. Raising
# at import is deliberate: a collection error is red, where a skipped
# module is not.
#
# `wet-eval.yml` reported success on eight consecutive weekly runs with
# every real step skipped. This is the same shape, one directory down.
if os.environ.get("ISOLATION_REQUIRE_LIVE", "").strip() and not os.environ.get("ISOLATION_SCIM_DSN", "").strip():
    raise RuntimeError(
        "ISOLATION_REQUIRE_LIVE is set and ISOLATION_SCIM_DSN is not. This job is supposed to "
        "exercise SCIM against a real Postgres, and skipping would report success having run nothing."
    )

SCIM_CONTENT_TYPE = "application/scim+json"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"

# The two providers' request shapes, transcribed rather than paraphrased.
#
# Copied from `services/api/tests/test_scim_provisioning.py` rather than
# imported: that module installs `@compiles(..., "sqlite")` shims and builds
# its own app at import time, and importing it here would apply both to a
# suite whose entire purpose is to avoid them.
# `TestTheVendorPayloadsHaveNotDrifted` reads the offline module's source
# and fails if the two copies stop agreeing.
OKTA_DEACTIVATE = {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "replace", "value": {"active": False}}]}
ENTRA_DEACTIVATE = {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "Replace", "path": "active", "value": "False"}]}
ENTRA_DEACTIVATE_BOOL = {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "Replace", "path": "active", "value": False}]}
OKTA_ADD_MEMBER = {
    "schemas": [PATCH_SCHEMA],
    "Operations": [{"op": "add", "path": "members", "value": [{"value": "__USER__", "display": "ada@example.com"}]}],
}
OKTA_REMOVE_MEMBER = {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "remove", "path": 'members[value eq "__USER__"]'}]}
ENTRA_ADD_MEMBER = {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "Add", "path": "members", "value": [{"value": "__USER__"}]}]}
ENTRA_REMOVE_MEMBER = {
    "schemas": [PATCH_SCHEMA],
    "Operations": [{"op": "Remove", "path": "members", "value": [{"value": "__USER__"}]}],
}

#: Where the offline copies live, for the drift pin.
OFFLINE_SUITE = pathlib.Path(__file__).resolve().parents[2] / "services" / "api" / "tests" / "test_scim_provisioning.py"


def _dsn() -> str:
    value = os.environ.get("ISOLATION_SCIM_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_SCIM_DSN is not set; this suite needs a live Postgres")
    return value


def _with_user(payload: dict, user_id: str) -> dict:
    """Substitute the member placeholder, including inside a path filter."""
    import json

    return json.loads(json.dumps(payload).replace("__USER__", user_id))


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def app_client():
    """The real application, against real Postgres.

    `create_application()` rather than a bare `FastAPI()` with the router
    mounted: the middleware, the exception handlers and the dependency
    graph are part of what a SCIM client talks to, and a harness that
    skips them is testing a different surface.
    """
    import httpx

    os.environ["DATABASE_URL"] = _dsn()
    # Not `development`, which is in `AUTH_BYPASS_ENVIRONMENTS`: an
    # uncredentialed request there resolves to a demo **admin**, inside the
    # one suite whose purpose is proving the tenant comes from the
    # credential. `test_an_unauthenticated_request_is_refused` would then be
    # asserting against a bypass rather than against SCIM's own auth.
    # `"test"` was removed from that bypass set for exactly this reason.
    os.environ["ENVIRONMENT"] = "test"

    from app.main import create_application

    application = create_application()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def db():
    """One SQLAlchemy engine for setup and for verification.

    An asyncpg pool beside a SQLAlchemy engine looks tidier and is not:
    under pytest-asyncio the two end up bound to different event loops,
    and the teardown of one fails with "Event loop is closed" while
    telling you nothing about the code under test.
    """
    # Imported, not `importorskip`ed: a missing driver in the job that is
    # supposed to be live is a broken job, and turning it into a skip makes
    # that report green.
    import asyncpg  # noqa: F401
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(_dsn(), future=True)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


async def _tenant(session) -> str:  # noqa: ANN001
    import sqlalchemy

    tenant_id = uuid.uuid4()
    await session.execute(
        sqlalchemy.text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s) ON CONFLICT DO NOTHING"),
        {"i": tenant_id, "n": f"scim-{tenant_id.hex[:8]}", "s": f"scim-{tenant_id.hex[:8]}"},
    )
    await session.commit()
    return str(tenant_id)


@pytest_asyncio.fixture(loop_scope="module")
async def tenants(db):  # noqa: ANN001
    """Two tenants, each with a real SCIM token minted by production code."""
    from app.services.scim import tokens

    a, b = await _tenant(db), await _tenant(db)
    minted: dict[str, str] = {}
    for name, tenant_id in (("a", a), ("b", b)):
        # `mint_token` returns `(token, raw)` and the raw secret is the
        # only time it exists outside an IdP's configuration.
        _token, raw = await tokens.mint_token(
            db,
            tenant_id=uuid.UUID(tenant_id),
            org_id=None,
            name=f"ci-{name}",
            created_by=None,
        )
        minted[name] = raw
    await db.commit()

    yield {"a": a, "b": b, "token_a": minted["a"], "token_b": minted["b"]}

    # Deliberately does not delete the tenants.
    #
    # `audit_log` rows are immutable by design — a trigger raises on
    # DELETE — and deleting a tenant cascades into them. That is correct
    # product behaviour and this suite found it by trying: an audit trail
    # a test can erase is not an audit trail.
    #
    # Every identifier here is unique per run, and CI gets a fresh
    # container, so leaving the rows costs nothing. Users are removed
    # because they are what the assertions count.
    import sqlalchemy

    for tenant_id in (a, b):
        try:
            await db.execute(
                sqlalchemy.text("DELETE FROM users WHERE tenant_id = CAST(:t AS uuid)"),
                {"t": tenant_id},
            )
            await db.commit()
        except Exception:  # noqa: BLE001, S110 — teardown is best effort
            await db.rollback()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": SCIM_CONTENT_TYPE}


class TestTheNegativeControls:
    async def test_an_unauthenticated_request_is_refused(self, app_client, tenants) -> None:  # noqa: ANN001
        """Without this, every assertion below could pass on a surface
        that serves everyone."""
        response = await app_client.get("/scim/v2/Users")
        assert response.status_code in (401, 403), f"SCIM served an uncredentialed caller with {response.status_code}"

    async def test_a_garbage_token_is_refused(self, app_client, tenants) -> None:  # noqa: ANN001
        response = await app_client.get("/scim/v2/Users", headers=_auth("aisoc_scim_not_a_real_token"))
        assert response.status_code in (401, 403)


class TestProvisioningAgainstRealTypes:
    async def test_a_user_created_over_scim_is_a_row(self, app_client, db, tenants) -> None:  # noqa: ANN001
        """The round trip the SQLite harness cannot certify.

        `users` carries UUID and JSONB columns that the offline suite
        compiles away; here they are the real types.
        """
        email = f"ci-{uuid.uuid4().hex[:8]}@example.com"
        response = await app_client.post(
            "/scim/v2/Users",
            headers=_auth(tenants["token_a"]),
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": email,
                "name": {"givenName": "Ada", "familyName": "Lovelace"},
                "emails": [{"value": email, "primary": True}],
                "active": True,
            },
        )
        assert response.status_code == 201, f"{response.status_code}: {response.text[:300]}"

        import sqlalchemy

        result = await db.execute(
            sqlalchemy.text("SELECT email, tenant_id FROM users WHERE email = :e"),
            {"e": email},
        )
        row = result.first()
        assert row is not None, "SCIM answered 201 and wrote no row"
        assert str(row.tenant_id) == tenants["a"], "the user was created against a tenant other than the token's"

    async def test_the_created_user_is_listed(self, app_client, tenants) -> None:  # noqa: ANN001
        email = f"ci-{uuid.uuid4().hex[:8]}@example.com"
        await app_client.post(
            "/scim/v2/Users",
            headers=_auth(tenants["token_a"]),
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": email,
                "active": True,
            },
        )
        listed = await app_client.get("/scim/v2/Users", headers=_auth(tenants["token_a"]))
        assert listed.status_code == 200
        assert email in listed.text


class TestTenantIsolation:
    async def test_another_tenants_token_cannot_read_these_users(self, app_client, tenants) -> None:  # noqa: ANN001
        """The isolation claim, through the real auth stack.

        Tenant A provisions a user; tenant B's token must not see it. A
        surface that returned everything would have passed the listing
        test above.
        """
        email = f"ci-{uuid.uuid4().hex[:8]}@example.com"
        created = await app_client.post(
            "/scim/v2/Users",
            headers=_auth(tenants["token_a"]),
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": email,
                "active": True,
            },
        )
        assert created.status_code == 201

        theirs = await app_client.get("/scim/v2/Users", headers=_auth(tenants["token_b"]))
        assert theirs.status_code == 200
        assert email not in theirs.text, "tenant B's SCIM token listed a user provisioned by tenant A"


async def _provision(app_client, token: str, email: str | None = None) -> tuple[str, str]:  # noqa: ANN001
    """Create a user over SCIM and return `(id, email)`."""
    address = email or f"ci-{uuid.uuid4().hex[:8]}@example.com"
    created = await app_client.post(
        "/scim/v2/Users",
        headers=_auth(token),
        json={"schemas": [USER_SCHEMA], "userName": address, "active": True},
    )
    assert created.status_code == 201, f"{created.status_code}: {created.text[:300]}"
    return created.json()["id"], address


async def _group(app_client, token: str, name: str | None = None) -> str:
    """Create a group over SCIM and return its id."""
    created = await app_client.post(
        "/scim/v2/Groups",
        headers=_auth(token),
        json={"schemas": [GROUP_SCHEMA], "displayName": name or f"AiSOC-SOC-Analysts-{uuid.uuid4().hex[:6]}"},
    )
    assert created.status_code == 201, f"{created.status_code}: {created.text[:300]}"
    return created.json()["id"]


async def _members(db, group_id: str) -> set[str]:  # noqa: ANN001
    """Membership read straight out of Postgres, not off the response.

    The response is the handler describing itself. The table is what the
    next sync and every authorisation decision read.
    """
    import sqlalchemy

    rows = await db.execute(
        sqlalchemy.text("SELECT user_id FROM aisoc_scim_group_members WHERE group_id = CAST(:g AS uuid)"),
        {"g": group_id},
    )
    await db.commit()
    return {str(row[0]) for row in rows}


class TestPatchInBothProvidersDialects:
    """PATCH is how Okta and Entra deactivate, and they disagree about how.

    Both bodies are asserted against `users.is_active` in Postgres rather
    than against the response, because a handler that returns a correct
    resource and writes nothing is the shape a 200 hides.
    """

    @pytest.mark.parametrize(
        ("label", "body"),
        [
            # No `path`, value is an object, `op` lowercase.
            ("okta", OKTA_DEACTIVATE),
            # Explicit `path`, `op` capitalised, value is the *string*
            # "False" — for which `bool("False")` is True, so a naive read
            # deactivates nothing and returns 200.
            ("entra-string", ENTRA_DEACTIVATE),
            # Entra also sends a real boolean in some versions.
            ("entra-bool", ENTRA_DEACTIVATE_BOOL),
        ],
    )
    async def test_a_deactivating_patch_turns_the_row_inactive(self, app_client, db, tenants, label, body) -> None:  # noqa: ANN001
        import sqlalchemy

        user_id, email = await _provision(app_client, tenants["token_a"])

        before = await db.execute(sqlalchemy.text("SELECT is_active FROM users WHERE email = :e"), {"e": email})
        await db.commit()
        assert before.scalar_one() is True, f"{label}: the user was not active to begin with"

        patched = await app_client.patch(f"/scim/v2/Users/{user_id}", headers=_auth(tenants["token_a"]), json=body)
        assert patched.status_code == 200, f"{label}: {patched.status_code}: {patched.text[:300]}"

        after = await db.execute(sqlalchemy.text("SELECT is_active FROM users WHERE email = :e"), {"e": email})
        await db.commit()
        assert after.scalar_one() is False, f"{label}: SCIM answered 200 and left the account active"

    async def test_a_patch_can_rename_a_principal(self, app_client, db, tenants) -> None:  # noqa: ANN001
        """A directory rename is the other PATCH a provider sends routinely,
        and it writes the column every other surface joins on."""
        import sqlalchemy

        user_id, _ = await _provision(app_client, tenants["token_a"])
        renamed = f"ci-{uuid.uuid4().hex[:8]}@example.com"

        response = await app_client.patch(
            f"/scim/v2/Users/{user_id}",
            headers=_auth(tenants["token_a"]),
            json={"schemas": [PATCH_SCHEMA], "Operations": [{"op": "replace", "path": "userName", "value": renamed}]},
        )
        assert response.status_code == 200, f"{response.status_code}: {response.text[:300]}"

        rows = await db.execute(sqlalchemy.text("SELECT email FROM users WHERE id = CAST(:i AS uuid)"), {"i": user_id})
        await db.commit()
        assert rows.scalar_one() == renamed

    async def test_another_tenants_token_cannot_patch_this_user(self, app_client, db, tenants) -> None:  # noqa: ANN001
        """The isolation claim on the write side.

        Reading is covered below; a surface that scoped its list and not
        its PATCH would let one customer deactivate another's staff.
        """
        import sqlalchemy

        user_id, email = await _provision(app_client, tenants["token_a"])

        response = await app_client.patch(f"/scim/v2/Users/{user_id}", headers=_auth(tenants["token_b"]), json=OKTA_DEACTIVATE)
        assert response.status_code == 404, f"tenant B reached tenant A's user with {response.status_code}"

        rows = await db.execute(sqlalchemy.text("SELECT is_active FROM users WHERE email = :e"), {"e": email})
        await db.commit()
        assert rows.scalar_one() is True, "tenant B's PATCH deactivated tenant A's user"


class TestGroupMembershipInBothProvidersDialects:
    """`aisoc_scim_group_members` is a composite key over two `UUID`
    columns with cascading foreign keys — the shape the offline harness
    compiles away. Every assertion reads the table.
    """

    @pytest.mark.parametrize(("label", "body"), [("okta", OKTA_ADD_MEMBER), ("entra", ENTRA_ADD_MEMBER)])
    async def test_adding_a_member_writes_the_row(self, app_client, db, tenants, label, body) -> None:  # noqa: ANN001
        user_id, _ = await _provision(app_client, tenants["token_a"])
        group_id = await _group(app_client, tenants["token_a"])

        assert await _members(db, group_id) == set(), f"{label}: the group was not empty to begin with"

        response = await app_client.patch(
            f"/scim/v2/Groups/{group_id}",
            headers=_auth(tenants["token_a"]),
            json=_with_user(body, user_id),
        )
        assert response.status_code == 200, f"{label}: {response.status_code}: {response.text[:300]}"
        assert await _members(db, group_id) == {user_id}, f"{label}: the membership row was not written"

    @pytest.mark.parametrize(
        ("label", "removal"),
        [
            # Okta puts the id in a path filter and sends no `value` at all.
            ("okta", OKTA_REMOVE_MEMBER),
            # Entra names the attribute in `path` and the member in `value`
            # — the opposite arrangement.
            ("entra", ENTRA_REMOVE_MEMBER),
        ],
    )
    async def test_removing_a_member_deletes_the_row(self, app_client, db, tenants, label, removal) -> None:  # noqa: ANN001
        user_id, _ = await _provision(app_client, tenants["token_a"])
        group_id = await _group(app_client, tenants["token_a"])

        added = await app_client.patch(
            f"/scim/v2/Groups/{group_id}",
            headers=_auth(tenants["token_a"]),
            json=_with_user(OKTA_ADD_MEMBER, user_id),
        )
        assert added.status_code == 200
        assert await _members(db, group_id) == {user_id}, f"{label}: nothing to remove, so the removal proves nothing"

        response = await app_client.patch(
            f"/scim/v2/Groups/{group_id}",
            headers=_auth(tenants["token_a"]),
            json=_with_user(removal, user_id),
        )
        assert response.status_code == 200, f"{label}: {response.status_code}: {response.text[:300]}"
        assert await _members(db, group_id) == set(), f"{label}: the membership row survived the removal"

    async def test_a_group_name_resolves_to_the_role_it_advertises(self, app_client, tenants) -> None:  # noqa: ANN001
        """The resolved role is returned on the resource so an administrator
        can confirm what a group grants by reading the same response their
        provider sees. A `null` there means it grants nothing."""
        group_id = await _group(app_client, tenants["token_a"], name="AiSOC-SOC-Analysts")
        response = await app_client.get(f"/scim/v2/Groups/{group_id}", headers=_auth(tenants["token_a"]))

        assert response.status_code == 200
        extension = response.json().get("urn:aisoc:params:scim:schemas:extension:2.0:Group", {})
        assert extension.get("mappedRole") == "soc_analyst", response.text[:300]

    async def test_a_group_name_matching_nothing_grants_nothing(self, app_client, tenants) -> None:  # noqa: ANN001
        """The control for the case above.

        Without it, a resolver that returned a role for every name would
        pass — and the set of people who can create a directory group is
        larger than the set of AiSOC administrators.
        """
        group_id = await _group(app_client, tenants["token_a"], name=f"Bowling-Club-{uuid.uuid4().hex[:6]}")
        response = await app_client.get(f"/scim/v2/Groups/{group_id}", headers=_auth(tenants["token_a"]))

        assert response.status_code == 200
        extension = response.json().get("urn:aisoc:params:scim:schemas:extension:2.0:Group", {})
        assert extension.get("mappedRole") is None, response.text[:300]


class TestGroupsAreTenantScoped:
    async def test_another_tenants_token_cannot_read_this_group(self, app_client, tenants) -> None:  # noqa: ANN001
        """The group surface has its own list handler.

        The user-listing control above says nothing about it, and a group
        carries the membership that decides what a principal may do.
        """
        name = f"AiSOC-SOC-Leads-{uuid.uuid4().hex[:8]}"
        await _group(app_client, tenants["token_a"], name=name)

        theirs = await app_client.get("/scim/v2/Groups", headers=_auth(tenants["token_b"]))
        assert theirs.status_code == 200
        assert name not in theirs.text, "tenant B's SCIM token listed a group provisioned by tenant A"


class TestDeprovisioningEndsAccess:
    """Deactivation has to do three things, and the doc says all three.

    The row surviving with access withdrawn is the whole design, so this
    needs a real foreign-key graph rather than a shimmed one.
    """

    async def test_a_deactivation_revokes_the_principals_api_keys(self, app_client, db, tenants) -> None:  # noqa: ANN001
        """An API key outlives a session and is reached by neither the
        `is_active` flag nor the session-revocation stamp."""
        import sqlalchemy

        user_id, _ = await _provision(app_client, tenants["token_a"])
        await db.execute(
            sqlalchemy.text(
                "INSERT INTO api_keys (id, tenant_id, user_id, name, key_prefix, hashed_key, is_active) "
                "VALUES (gen_random_uuid(), CAST(:t AS uuid), CAST(:u AS uuid), 'ci', 'aisoc_ci', :h, TRUE)"
            ),
            {"t": tenants["a"], "u": user_id, "h": uuid.uuid4().hex},
        )
        await db.commit()

        active_before = await db.execute(
            sqlalchemy.text("SELECT count(*) FROM api_keys WHERE user_id = CAST(:u AS uuid) AND is_active"),
            {"u": user_id},
        )
        await db.commit()
        assert active_before.scalar_one() == 1, "no active key to revoke, so this proves nothing"

        patched = await app_client.patch(f"/scim/v2/Users/{user_id}", headers=_auth(tenants["token_a"]), json=OKTA_DEACTIVATE)
        assert patched.status_code == 200, patched.text[:300]

        active_after = await db.execute(
            sqlalchemy.text("SELECT count(*) FROM api_keys WHERE user_id = CAST(:u AS uuid) AND is_active"),
            {"u": user_id},
        )
        await db.commit()
        assert active_after.scalar_one() == 0, "the principal was deactivated and their API key still authenticates"

    async def test_a_deactivation_stamps_the_session_revocation_time(self, app_client, db, tenants) -> None:  # noqa: ANN001
        """A `TIMESTAMPTZ` write, which is where the offline harness is
        weakest: a shimmed column accepts a value without storing a
        comparable one, and every token issued before this instant is
        refused by comparing against it."""
        import sqlalchemy

        user_id, _ = await _provision(app_client, tenants["token_a"])
        patched = await app_client.patch(f"/scim/v2/Users/{user_id}", headers=_auth(tenants["token_a"]), json=ENTRA_DEACTIVATE)
        assert patched.status_code == 200, patched.text[:300]

        rows = await db.execute(
            sqlalchemy.text("SELECT sessions_revoked_at FROM users WHERE id = CAST(:u AS uuid)"),
            {"u": user_id},
        )
        await db.commit()
        stamped = rows.scalar_one()
        assert stamped is not None, "deactivation left no session-revocation stamp, so an open token keeps working"
        assert stamped.tzinfo is not None, "the stamp came back naive; a comparison against an aware `now()` would raise"

    async def test_delete_deactivates_rather_than_erasing_the_row(self, app_client, db, tenants) -> None:  # noqa: ANN001
        """RFC 7644 permits it, and erasing would take the principal's
        audit attribution, case ownership and approval history with it.
        Access ends either way."""
        import sqlalchemy

        user_id, email = await _provision(app_client, tenants["token_a"])

        response = await app_client.delete(f"/scim/v2/Users/{user_id}", headers=_auth(tenants["token_a"]))
        assert response.status_code == 204, f"{response.status_code}: {response.text[:300]}"

        rows = await db.execute(sqlalchemy.text("SELECT is_active FROM users WHERE email = :e"), {"e": email})
        await db.commit()
        surviving = rows.all()
        assert len(surviving) == 1, "DELETE erased the row, taking its audit attribution with it"
        assert surviving[0][0] is False

    async def test_reactivating_does_not_restore_the_revoked_api_keys(self, app_client, db, tenants) -> None:  # noqa: ANN001
        """A key whose owner cannot see it was revoked is a key nobody will
        rotate."""
        import sqlalchemy

        user_id, _ = await _provision(app_client, tenants["token_a"])
        await db.execute(
            sqlalchemy.text(
                "INSERT INTO api_keys (id, tenant_id, user_id, name, key_prefix, hashed_key, is_active) "
                "VALUES (gen_random_uuid(), CAST(:t AS uuid), CAST(:u AS uuid), 'ci', 'aisoc_ci', :h, TRUE)"
            ),
            {"t": tenants["a"], "u": user_id, "h": uuid.uuid4().hex},
        )
        await db.commit()

        await app_client.patch(f"/scim/v2/Users/{user_id}", headers=_auth(tenants["token_a"]), json=OKTA_DEACTIVATE)
        reactivated = await app_client.patch(
            f"/scim/v2/Users/{user_id}",
            headers=_auth(tenants["token_a"]),
            json={"schemas": [PATCH_SCHEMA], "Operations": [{"op": "replace", "path": "active", "value": True}]},
        )
        assert reactivated.status_code == 200, reactivated.text[:300]

        rows = await db.execute(
            sqlalchemy.text(
                "SELECT u.is_active, (SELECT count(*) FROM api_keys k WHERE k.user_id = u.id AND k.is_active) "
                "FROM users u WHERE u.id = CAST(:u AS uuid)"
            ),
            {"u": user_id},
        )
        await db.commit()
        is_active, live_keys = rows.one()
        assert is_active is True, "re-activation did not restore sign-in"
        assert live_keys == 0, "re-activation resurrected an API key the deprovisioning revoked"


class TestTheVendorPayloadsHaveNotDrifted:
    """The offline suite holds the same payloads, and two copies disagreeing
    is how a live test ends up certifying a shape no provider sends.

    Read from source rather than imported: that module installs
    `@compiles(..., "sqlite")` type shims and builds its own application at
    import time, both of which this suite exists to avoid.
    """

    SHARED = (
        "OKTA_DEACTIVATE",
        "ENTRA_DEACTIVATE",
        "ENTRA_DEACTIVATE_BOOL",
        "OKTA_ADD_MEMBER",
        "OKTA_REMOVE_MEMBER",
        "ENTRA_ADD_MEMBER",
        "ENTRA_REMOVE_MEMBER",
    )

    def test_every_shared_payload_matches_the_offline_copy(self) -> None:
        assert OFFLINE_SUITE.exists(), f"{OFFLINE_SUITE} has moved; this pin is reading nothing"
        tree = ast.parse(OFFLINE_SUITE.read_text(encoding="utf-8"))

        offline = {
            target.id: ast.literal_eval(node.value)
            for node in tree.body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name) and target.id in self.SHARED
        }

        missing = set(self.SHARED) - set(offline)
        assert not missing, f"the offline suite no longer defines {sorted(missing)}"

        here = globals()
        differing = {name: (offline[name], here[name]) for name in self.SHARED if offline[name] != here[name]}
        assert not differing, f"the live and offline vendor payloads have drifted: {sorted(differing)}"


class TestTheDiscoveryEndpoints:
    async def test_service_provider_config_is_served(self, app_client, tenants) -> None:  # noqa: ANN001
        """An IdP reads this first. If it 404s, nothing else is reached."""
        response = await app_client.get("/scim/v2/ServiceProviderConfig", headers=_auth(tenants["token_a"]))
        assert response.status_code == 200
        assert "schemas" in response.json()

    async def test_the_user_schema_is_served(self, app_client, tenants) -> None:  # noqa: ANN001
        response = await app_client.get("/scim/v2/Schemas", headers=_auth(tenants["token_a"]))
        assert response.status_code == 200
