"""SCIM 2.0 against the request shapes two identity providers actually send.

Gap-closure Phase 13.1 gate.

Why the payloads below are written out in full
-----------------------------------------------
A hand-written SCIM test agrees with the handler it was written beside. Both
providers this platform supports deviate from the obvious reading of RFC 7644,
in opposite directions, and a test that paraphrases their payloads reproduces
whatever the author assumed rather than what the provider sends. So the bodies
here are transcribed in the shape the providers emit, including the parts that
look like mistakes:

* deactivation with no ``path`` and an object value (Okta), versus an explicit
  ``path`` and the *string* ``"False"`` (Entra)
* ``op`` lowercase (Okta) versus capitalised (Entra)
* member removal through a path filter with no value (Okta), versus
  ``path: "members"`` with the id in a value array (Entra)
* ``userName`` omitted entirely in favour of ``emails`` (Entra, when the
  directory's username attribute is unset)

They are synthetic reproductions of documented request shapes, not captures
from a customer tenant.

The two sequences at the bottom are the acceptance criterion: create, update,
group membership, deactivate, run end to end in each provider's dialect.

Everything here runs on one event loop through ``httpx.ASGITransport``. The
threaded test client would put the request on a different loop from the
fixtures, and the shared in-memory SQLite connection cannot be reached from
two.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
import pytest_asyncio
from app.api.v1.endpoints.scim import ScimAuthFailed
from app.api.v1.endpoints.scim import router as scim_router
from app.core.security import create_access_token, token_is_revoked
from app.db.database import Base, get_db
from app.models.audit import AuditLog
from app.models.scim import ScimGroup, ScimGroupMember, ScimToken, ScimUser
from app.models.tenant import ApiKey, User
from app.services.scim import provisioning, resources, roles, tokens
from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-0000000000a1")
OTHER_TENANT = uuid.UUID("bbbbbbbb-0000-0000-0000-0000000000b1")

BASE = resources.SCIM_BASE


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(_type_, _compiler_, **_kw_):
    return "TEXT"


@compiles(PgUUID, "sqlite")
def _uuid_sqlite(_type_, _compiler_, **_kw_):
    return "CHAR(36)"


@compiles(INET, "sqlite")
def _inet_sqlite(_type_, _compiler_, **_kw_):
    return "TEXT"


# ---------------------------------------------------------------------------
# Vendor-shaped request bodies (synthetic reproductions)
# ---------------------------------------------------------------------------

PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

#: Okta: no `path`, value is an object, `op` lowercase.
OKTA_DEACTIVATE = {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "replace", "value": {"active": False}}]}

#: Entra: explicit `path`, `op` capitalised, and the value is the *string*
#: "False". `bool("False")` is True, so a naive read deactivates nothing
#: while returning 200.
ENTRA_DEACTIVATE = {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "Replace", "path": "active", "value": "False"}]}

#: Entra also sends a real boolean in some versions. Both must work.
ENTRA_DEACTIVATE_BOOL = {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "Replace", "path": "active", "value": False}]}

#: Okta group member add.
OKTA_ADD_MEMBER = {
    "schemas": [PATCH_SCHEMA],
    "Operations": [{"op": "add", "path": "members", "value": [{"value": "__USER__", "display": "ada@example.com"}]}],
}

#: Okta group member removal: the id lives in a path filter, and there is no
#: `value` at all.
OKTA_REMOVE_MEMBER = {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "remove", "path": 'members[value eq "__USER__"]'}]}

#: Entra group member add: capitalised op, member objects in `value`.
ENTRA_ADD_MEMBER = {"schemas": [PATCH_SCHEMA], "Operations": [{"op": "Add", "path": "members", "value": [{"value": "__USER__"}]}]}

#: Entra group member removal: `path` names the attribute and `value` names
#: the member. The opposite arrangement from Okta's removal above.
ENTRA_REMOVE_MEMBER = {
    "schemas": [PATCH_SCHEMA],
    "Operations": [{"op": "Remove", "path": "members", "value": [{"value": "__USER__"}]}],
}

#: Okta user create. `userName` present, name sub-attributes present.
OKTA_CREATE_USER = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "ada@example.com",
    "name": {"givenName": "Ada", "familyName": "Lovelace"},
    "emails": [{"primary": True, "value": "ada@example.com", "type": "work"}],
    "displayName": "Ada Lovelace",
    "active": True,
    "externalId": "00u1okta0000000001",
    "groups": [],
}

#: Entra user create. No `userName`; the address is only in `emails`, and the
#: enterprise-user extension arrives alongside the core schema.
ENTRA_CREATE_USER = {
    "schemas": [
        "urn:ietf:params:scim:schemas:core:2.0:User",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
    ],
    "externalId": "8a7b6c5d-entra-0000-0000-000000000001",
    "emails": [{"primary": True, "type": "work", "value": "grace@example.com"}],
    "name": {"givenName": "Grace", "familyName": "Hopper"},
    "displayName": "Grace Hopper",
    "active": True,
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "Security"},
}


def _with_user(template: dict, user_id: str) -> dict:
    """Substitute a real user id into a recorded payload."""
    return json.loads(json.dumps(template).replace("__USER__", user_id))


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

_TABLES = [
    User.__table__,
    ApiKey.__table__,
    AuditLog.__table__,
    ScimToken.__table__,
    ScimUser.__table__,
    ScimGroup.__table__,
    ScimGroupMember.__table__,
]


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        # Only the tables these paths touch. A whole-metadata create_all
        # drags in models using Postgres ARRAY, which SQLite cannot render.
        await conn.run_sync(Base.metadata.create_all, tables=_TABLES)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def secrets(session_factory):
    """A tenant with one SCIM credential, and a second tenant beside it."""
    async with session_factory() as db:
        _token, raw = await tokens.mint_token(db, tenant_id=TENANT, org_id=None, name="okta-primary", created_by=None)
        _other, other_raw = await tokens.mint_token(db, tenant_id=OTHER_TENANT, org_id=None, name="other", created_by=None)
        await db.commit()
    return {"raw": raw, "other_raw": other_raw}


def _build_app(session_factory) -> FastAPI:
    app = FastAPI()
    app.include_router(scim_router)

    @app.exception_handler(ScimAuthFailed)
    async def _refused(_request, _exc):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=resources.error_response(401, "Invalid SCIM credential"),
            media_type=resources.SCIM_CONTENT_TYPE,
        )

    async def _override_db():
        # Mirrors app.db.database.get_db, including the trailing commit.
        # Without it the harness would diverge from production for any write
        # a dependency makes and a handler does not commit, which is exactly
        # how `last_used_at` on a read-only SCIM call would be lost.
        async with session_factory() as db:
            try:
                yield db
                await db.commit()
            except Exception:
                await db.rollback()
                raise

    app.dependency_overrides[get_db] = _override_db
    return app


@pytest_asyncio.fixture
async def client(session_factory, secrets):
    app = _build_app(session_factory)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://scim.test",
        headers={"Authorization": f"Bearer {secrets['raw']}"},
    ) as http:
        yield http


@pytest_asyncio.fixture
async def anonymous(session_factory):
    app = _build_app(session_factory)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://scim.test") as http:
        yield http


async def _seed_user(session_factory, *, email: str, tenant: uuid.UUID = TENANT, with_key: bool = False) -> uuid.UUID:
    user_id = uuid.uuid4()
    async with session_factory() as db:
        db.add(
            User(
                id=user_id,
                tenant_id=tenant,
                email=email,
                username=email,
                hashed_password="!x",
                role="soc_analyst",
                is_active=True,
            )
        )
        if with_key:
            db.add(
                ApiKey(
                    tenant_id=tenant,
                    user_id=user_id,
                    name="minted before leaving",
                    key_prefix="aisoc_zzz123",
                    hashed_key=uuid.uuid4().hex,
                    scopes=["*"],
                    is_active=True,
                )
            )
        await db.commit()
    return user_id


# ---------------------------------------------------------------------------
# The credential
# ---------------------------------------------------------------------------


class TestTokens:
    async def test_raw_secret_is_not_recoverable_from_the_row(self, secrets, session_factory):
        """What is stored is a digest; the prefix is not the secret."""
        raw = secrets["raw"]
        assert raw.startswith(tokens.TOKEN_PREFIX)
        async with session_factory() as db:
            row = (await db.execute(select(ScimToken).where(ScimToken.name == "okta-primary"))).scalar_one()
        assert row.token_hash == tokens.hash_token(raw)
        assert raw not in row.token_hash
        assert row.token_prefix != raw
        assert len(row.token_prefix) < len(raw)

    @pytest.mark.parametrize("header", ["Bearer not-a-scim-token", "Bearer aisoc_scim_deadbeef", "Bearer "])
    async def test_a_bad_credential_gets_a_scim_error_with_no_detail(self, anonymous, header):
        response = await anonymous.get(f"{BASE}/Users", headers={"Authorization": header})
        assert response.status_code == 401
        body = response.json()
        assert body["schemas"] == [resources.ERROR_SCHEMA]
        # The reason is logged, not returned. A caller must not learn whether
        # a secret was wrong, revoked or merely expired.
        assert "revoked" not in body["detail"].casefold()
        assert "expired" not in body["detail"].casefold()

    async def test_no_credential_at_all_is_refused(self, anonymous):
        assert (await anonymous.get(f"{BASE}/Users")).status_code == 401

    async def test_revoked_and_expired_tokens_are_refused(self, session_factory):
        async with session_factory() as db:
            live, live_raw = await tokens.mint_token(db, tenant_id=TENANT, org_id=None, name="live", created_by=None)
            revoked, revoked_raw = await tokens.mint_token(db, tenant_id=TENANT, org_id=None, name="revoked", created_by=None)
            expired, expired_raw = await tokens.mint_token(db, tenant_id=TENANT, org_id=None, name="expired", created_by=None)
            revoked.revoked_at = datetime.now(UTC)
            expired.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            await db.commit()

            assert (await tokens.verify_token(db, live_raw)).tenant_id == TENANT
            assert live.is_usable()
            for raw in (revoked_raw, expired_raw):
                with pytest.raises(tokens.ScimAuthError):
                    await tokens.verify_token(db, raw)

    async def test_rotation_leaves_an_overlap_window_then_closes_it(self, session_factory):
        """Both secrets work during the grace window; the old one then expires.

        A rotation that cut over instantly would take the integration down
        for as long as it takes a person to paste the new secret across,
        which is why rotation gets deferred and secrets get old.
        """
        async with session_factory() as db:
            old, old_raw = await tokens.mint_token(db, tenant_id=TENANT, org_id=None, name="rotating", created_by=None)
            await db.commit()
            new, new_raw = await tokens.rotate_token(db, token=old, created_by=None, grace=timedelta(hours=1))
            await db.commit()

            assert new.rotated_from_id == old.id
            assert (await tokens.verify_token(db, old_raw)).tenant_id == TENANT
            assert (await tokens.verify_token(db, new_raw)).tenant_id == TENANT

            later = datetime.now(UTC) + timedelta(hours=2)
            with pytest.raises(tokens.ScimAuthError):
                await tokens.verify_token(db, old_raw, now=later)
            assert (await tokens.verify_token(db, new_raw, now=later)).tenant_id == TENANT

    async def test_zero_grace_revokes_the_old_secret_at_once(self, session_factory):
        """Rotation after a disclosure must not leave the leaked secret live."""
        async with session_factory() as db:
            old, old_raw = await tokens.mint_token(db, tenant_id=TENANT, org_id=None, name="leaked", created_by=None)
            await db.commit()
            await tokens.rotate_token(db, token=old, created_by=None, grace=timedelta(0))
            await db.commit()
            with pytest.raises(tokens.ScimAuthError):
                await tokens.verify_token(db, old_raw)

    async def test_rotation_never_extends_an_earlier_deadline(self, session_factory):
        async with session_factory() as db:
            soon = datetime.now(UTC) + timedelta(minutes=5)
            old, _raw = await tokens.mint_token(db, tenant_id=TENANT, org_id=None, name="short-lived", created_by=None, expires_at=soon)
            await db.commit()
            await tokens.rotate_token(db, token=old, created_by=None, grace=timedelta(hours=48))
            await db.commit()
            assert old.expires_at == soon

    async def test_last_used_is_recorded_so_an_abandoned_integration_is_visible(self, client, session_factory):
        await client.get(f"{BASE}/ServiceProviderConfig")
        async with session_factory() as db:
            row = (await db.execute(select(ScimToken).where(ScimToken.name == "okta-primary"))).scalar_one()
        assert row.last_used_at is not None

    async def test_a_token_addresses_exactly_one_tenant(self, client, secrets):
        """Cross-tenant reach is impossible because there is no field for it."""
        created = await client.post(f"{BASE}/Users", json=OKTA_CREATE_USER)
        assert created.status_code == 201
        user_id = created.json()["id"]
        seen = await client.get(f"{BASE}/Users/{user_id}", headers={"Authorization": f"Bearer {secrets['other_raw']}"})
        assert seen.status_code == 404


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


class TestDiscovery:
    async def test_service_provider_config_describes_what_is_implemented(self, client):
        body = (await client.get(f"{BASE}/ServiceProviderConfig")).json()
        assert body["patch"]["supported"] is True
        assert body["filter"]["supported"] is True
        # Declared false rather than omitted: advertising either would have a
        # provider configure itself to use an endpoint that is not there.
        assert body["bulk"]["supported"] is False
        assert body["sort"]["supported"] is False

    async def test_resource_types_and_schemas_are_fetchable_individually(self, client):
        listed = (await client.get(f"{BASE}/ResourceTypes")).json()
        assert {entry["id"] for entry in listed["Resources"]} == {"User", "Group"}
        assert (await client.get(f"{BASE}/ResourceTypes/User")).status_code == 200

        schemas = (await client.get(f"{BASE}/Schemas")).json()
        ids = {entry["id"] for entry in schemas["Resources"]}
        assert {resources.USER_SCHEMA, resources.GROUP_SCHEMA} <= ids
        assert (await client.get(f"{BASE}/Schemas/{resources.USER_SCHEMA}")).status_code == 200

    async def test_discovery_requires_a_credential(self, anonymous):
        """RFC 7644 permits anonymous discovery; this deployment does not.

        The documents say which SCIM features are enabled here, which is not
        something to publish to anyone who asks.
        """
        assert (await anonymous.get(f"{BASE}/ServiceProviderConfig")).status_code == 401
        assert (await anonymous.get(f"{BASE}/Schemas")).status_code == 401

    async def test_responses_carry_the_scim_content_type(self, client):
        response = await client.get(f"{BASE}/ServiceProviderConfig")
        assert response.headers["content-type"].startswith(resources.SCIM_CONTENT_TYPE)


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


class TestFiltering:
    async def test_equality_filter_finds_the_user_a_provider_is_about_to_create(self, client):
        await client.post(f"{BASE}/Users", json=OKTA_CREATE_USER)
        found = (await client.get(f"{BASE}/Users", params={"filter": 'userName eq "ada@example.com"'})).json()
        assert found["totalResults"] == 1
        assert found["Resources"][0]["userName"] == "ada@example.com"

    async def test_a_filter_that_matches_nothing_returns_an_empty_list_not_everything(self, client):
        await client.post(f"{BASE}/Users", json=OKTA_CREATE_USER)
        found = (await client.get(f"{BASE}/Users", params={"filter": 'userName eq "nobody@example.com"'})).json()
        assert found["totalResults"] == 0
        assert found["Resources"] == []

    async def test_an_unsupported_filter_is_refused_rather_than_dropped(self, client):
        """Dropping it would return every principal in the tenant.

        A provider reading that concludes the user it was about to create
        already exists, or picks the first result and updates the wrong one.
        """
        await client.post(f"{BASE}/Users", json=OKTA_CREATE_USER)
        response = await client.get(f"{BASE}/Users", params={"filter": 'userName eq "ada@example.com" and active eq "true"'})
        assert response.status_code == 400
        assert response.json()["scimType"] == "invalidFilter"

    async def test_username_matching_ignores_case(self, client):
        """Providers do not guarantee address casing is stable between syncs."""
        await client.post(f"{BASE}/Users", json=OKTA_CREATE_USER)
        found = (await client.get(f"{BASE}/Users", params={"filter": 'userName eq "ADA@Example.com"'})).json()
        assert found["totalResults"] == 1

    async def test_external_id_filter_finds_a_renamed_principal(self, client):
        """The id a provider stores has to survive a change of address."""
        created = await client.post(f"{BASE}/Users", json=OKTA_CREATE_USER)
        user_id = created.json()["id"]
        await client.patch(
            f"{BASE}/Users/{user_id}",
            json={"schemas": [PATCH_SCHEMA], "Operations": [{"op": "replace", "value": {"userName": "ada2@example.com"}}]},
        )
        found = (await client.get(f"{BASE}/Users", params={"filter": 'externalId eq "00u1okta0000000001"'})).json()
        assert found["totalResults"] == 1
        assert found["Resources"][0]["userName"] == "ada2@example.com"

    async def test_total_results_counts_the_match_not_the_page(self, client):
        """Providers page on totalResults.

        Returning the page size instead stops a sync after the first page
        while reporting success.
        """
        for index in range(5):
            await client.post(
                f"{BASE}/Users",
                json={**OKTA_CREATE_USER, "userName": f"u{index}@example.com", "externalId": f"ext-{index}"},
            )
        page = (await client.get(f"{BASE}/Users", params={"count": 2})).json()
        assert page["totalResults"] == 5
        assert page["itemsPerPage"] == 2


# ---------------------------------------------------------------------------
# Deprovisioning: the operation that has to be real
# ---------------------------------------------------------------------------


class TestDeprovisioning:
    async def test_deactivation_revokes_sessions_and_api_keys(self, session_factory):
        """Three things end, and two of them are not the flag."""
        user_id = await _seed_user(session_factory, email="leaver@example.com", with_key=True)
        async with session_factory() as db:
            user = await db.get(User, user_id)
            result = await provisioning.deactivate_user(db, user)
            await db.commit()

            assert user.is_active is False
            assert result.api_keys_revoked == 1
            assert result.sessions_revoked_at is not None

            key = (await db.execute(select(ApiKey).where(ApiKey.user_id == user_id))).scalar_one()
            assert key.is_active is False

    def test_a_token_minted_before_deprovisioning_stays_dead_after_reactivation(self):
        """The flag alone is reversible; the timestamp is not.

        Re-enabling a principal must not resurrect tokens minted before they
        were deprovisioned, which are still inside their expiry window.
        """
        revoked_at = datetime.now(UTC)
        before = (revoked_at - timedelta(minutes=5)).timestamp()
        after = (revoked_at + timedelta(minutes=5)).timestamp()

        assert token_is_revoked(before, revoked_at) is True
        assert token_is_revoked(after, revoked_at) is False
        # No revocation recorded: nothing is refused.
        assert token_is_revoked(before, None) is False
        # A token with no `iat` predates the claim being added. Fails closed.
        assert token_is_revoked(None, revoked_at) is True

    def test_minted_tokens_carry_iat_so_the_check_has_something_to_read(self):
        """A revocation check against a claim nothing sets would never fire."""
        claims = jwt.decode(create_access_token({"sub": str(uuid.uuid4())}), options={"verify_signature": False})
        assert "iat" in claims

    async def test_reactivation_does_not_restore_revoked_api_keys(self, session_factory):
        """A key the owner cannot see was revoked is a key they will not rotate."""
        user_id = await _seed_user(session_factory, email="returner@example.com", with_key=True)
        async with session_factory() as db:
            user = await db.get(User, user_id)
            await provisioning.deactivate_user(db, user)
            await provisioning.reactivate_user(db, user)
            await db.commit()

            assert user.is_active is True
            assert user.sessions_revoked_at is not None
            key = (await db.execute(select(ApiKey).where(ApiKey.user_id == user_id))).scalar_one()
            assert key.is_active is False

    async def test_delete_deprovisions_rather_than_erasing(self, client, session_factory):
        """A deleted row takes its audit attribution and case history with it.

        Access ends completely either way, which is what DELETE means here.
        """
        created = await client.post(f"{BASE}/Users", json=OKTA_CREATE_USER)
        user_id = uuid.UUID(created.json()["id"])
        deleted = await client.delete(f"{BASE}/Users/{user_id}")
        assert deleted.status_code == 204

        async with session_factory() as db:
            user = await db.get(User, user_id)
            assert user is not None, "the principal was erased; audit attribution would be lost"
            assert user.is_active is False
            assert user.sessions_revoked_at is not None

    async def test_deprovisioning_through_scim_revokes_the_principals_api_keys(self, client, session_factory):
        """The end-to-end version, driven through the SCIM surface itself."""
        created = await client.post(f"{BASE}/Users", json=OKTA_CREATE_USER)
        user_id = uuid.UUID(created.json()["id"])

        async with session_factory() as db:
            db.add(
                ApiKey(
                    tenant_id=TENANT,
                    user_id=user_id,
                    name="minted before leaving",
                    key_prefix="aisoc_zzz123",
                    hashed_key=uuid.uuid4().hex,
                    scopes=["*"],
                    is_active=True,
                )
            )
            await db.commit()

        deleted = await client.delete(f"{BASE}/Users/{user_id}")
        assert deleted.status_code == 204

        async with session_factory() as db:
            key = (await db.execute(select(ApiKey).where(ApiKey.user_id == user_id))).scalar_one()
            user = await db.get(User, user_id)
        assert key.is_active is False
        assert user.is_active is False
        assert user.sessions_revoked_at is not None


# ---------------------------------------------------------------------------
# Group to role mapping
# ---------------------------------------------------------------------------


class TestRoleMapping:
    def test_the_mapping_only_names_roles_this_platform_enforces(self):
        assert roles.validate_vocabulary() == []

    @pytest.mark.parametrize(
        ("group_name", "expected"),
        [
            ("AiSOC-SOC-Analysts", "soc_analyst"),
            ("soc analyst", "soc_analyst"),
            ("SOC_Analysts", "soc_analyst"),
            ("AiSOC Threat Hunters", "threat_hunter"),
            ("AiSOC-SOC-Leads", "soc_lead"),
            ("Tenant Admins", "tenant_admin"),
            ("Security Viewers", "viewer"),
            ("Triage Team", "soc_analyst"),
            # Unrecognised: confers nothing rather than something unknown.
            ("Marketing", None),
            ("", None),
        ],
    )
    def test_group_names_resolve_to_the_role_they_name_or_to_nothing(self, group_name, expected):
        assert roles.resolve_role(group_name) == expected

    @pytest.mark.parametrize("privileged", ["Platform Admins", "admins", "AiSOC platform_admin", "api service"])
    def test_no_group_name_can_mint_a_wildcard_role(self, privileged):
        """A directory group name must not be able to grant '*' everywhere.

        Whoever can create a group in the customer's directory is usually a
        larger set of people than the platform's administrators.
        """
        assert roles.resolve_role(privileged) not in roles.UNREACHABLE_BY_GROUP

    def test_precedence_is_total_so_sync_order_cannot_change_authority(self):
        assert roles.effective_role(["soc_analyst", "tenant_admin"]) == "tenant_admin"
        assert roles.effective_role(["tenant_admin", "soc_analyst"]) == "tenant_admin"
        assert roles.effective_role([None, None]) == roles.DEFAULT_PROVISIONED_ROLE
        assert roles.effective_role([]) == roles.DEFAULT_PROVISIONED_ROLE

    async def test_membership_grants_the_role_and_removal_takes_it_back(self, client, session_factory):
        """This is the step that makes a group mean anything.

        ``users.role`` is the column the permission check reads, so a group
        that did not write it would be recorded and inert.
        """
        created = await client.post(f"{BASE}/Users", json=OKTA_CREATE_USER)
        user_id = uuid.UUID(created.json()["id"])

        async with session_factory() as db:
            assert (await db.get(User, user_id)).role == roles.DEFAULT_PROVISIONED_ROLE

        group = await client.post(f"{BASE}/Groups", json={"displayName": "AiSOC-SOC-Leads"})
        group_id = group.json()["id"]
        await client.patch(f"{BASE}/Groups/{group_id}", json=_with_user(OKTA_ADD_MEMBER, str(user_id)))

        async with session_factory() as db:
            assert (await db.get(User, user_id)).role == "soc_lead"

        await client.patch(f"{BASE}/Groups/{group_id}", json=_with_user(OKTA_REMOVE_MEMBER, str(user_id)))

        async with session_factory() as db:
            assert (await db.get(User, user_id)).role == roles.DEFAULT_PROVISIONED_ROLE

    async def test_an_unmapped_group_confers_nothing(self, client, session_factory):
        created = await client.post(f"{BASE}/Users", json=OKTA_CREATE_USER)
        user_id = uuid.UUID(created.json()["id"])
        group = await client.post(f"{BASE}/Groups", json={"displayName": "Marketing"})
        assert group.json()[resources.AISOC_GROUP_EXTENSION]["mappedRole"] is None

        await client.patch(f"{BASE}/Groups/{group.json()['id']}", json=_with_user(OKTA_ADD_MEMBER, str(user_id)))
        async with session_factory() as db:
            assert (await db.get(User, user_id)).role == roles.DEFAULT_PROVISIONED_ROLE

    async def test_deleting_the_group_takes_the_role_with_it(self, client, session_factory):
        created = await client.post(f"{BASE}/Users", json=OKTA_CREATE_USER)
        user_id = uuid.UUID(created.json()["id"])
        group = await client.post(f"{BASE}/Groups", json={"displayName": "Tenant Admins"})
        group_id = group.json()["id"]
        await client.patch(f"{BASE}/Groups/{group_id}", json=_with_user(OKTA_ADD_MEMBER, str(user_id)))

        async with session_factory() as db:
            assert (await db.get(User, user_id)).role == "tenant_admin"

        deleted = await client.delete(f"{BASE}/Groups/{group_id}")
        assert deleted.status_code == 204
        async with session_factory() as db:
            assert (await db.get(User, user_id)).role == roles.DEFAULT_PROVISIONED_ROLE


# ---------------------------------------------------------------------------
# End-to-end provider sequences: the acceptance criterion
# ---------------------------------------------------------------------------


async def _sequence(client, *, create_body, deactivate_body, add_member, remove_member, group_name, expected_email):
    """create, update, group membership, deactivate, in one provider's dialect."""
    created = await client.post(f"{BASE}/Users", json=create_body)
    assert created.status_code == 201, created.text
    user = created.json()
    assert user["userName"] == expected_email
    assert user["active"] is True
    user_id = user["id"]

    # A repeated create is a conflict, never a duplicate principal.
    duplicate = await client.post(f"{BASE}/Users", json=create_body)
    assert duplicate.status_code == 409

    # Update: a rename through PUT, which one provider uses for profile
    # changes when attribute sync is enabled.
    renamed = await client.put(f"{BASE}/Users/{user_id}", json={**create_body, "name": {"givenName": "Renamed", "familyName": "Principal"}})
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["name"]["givenName"] == "Renamed"

    # Group membership: create, add, confirm the role it confers, then remove
    # and confirm the role goes with it.
    group = await client.post(f"{BASE}/Groups", json={"displayName": group_name, "members": []})
    assert group.status_code == 201, group.text
    group_id = group.json()["id"]
    assert group.json()[resources.AISOC_GROUP_EXTENSION]["mappedRole"] == "soc_lead"

    added = await client.patch(f"{BASE}/Groups/{group_id}", json=_with_user(add_member, user_id))
    assert added.status_code == 200, added.text
    assert [m["value"] for m in added.json()["members"]] == [user_id]

    seen = (await client.get(f"{BASE}/Users/{user_id}")).json()
    assert [g["value"] for g in seen.get("groups", [])] == [group_id]

    removed = await client.patch(f"{BASE}/Groups/{group_id}", json=_with_user(remove_member, user_id))
    assert removed.status_code == 200, removed.text
    assert removed.json()["members"] == []

    # Deactivate, in this provider's dialect.
    deactivated = await client.patch(f"{BASE}/Users/{user_id}", json=deactivate_body)
    assert deactivated.status_code == 200, deactivated.text
    assert deactivated.json()["active"] is False, "the deactivation did not take effect"

    # Visible on a subsequent read, not only in the response body.
    assert (await client.get(f"{BASE}/Users/{user_id}")).json()["active"] is False
    return user_id


class TestProviderSequences:
    async def test_okta_shaped_sequence(self, client):
        await _sequence(
            client,
            create_body=OKTA_CREATE_USER,
            deactivate_body=OKTA_DEACTIVATE,
            add_member=OKTA_ADD_MEMBER,
            remove_member=OKTA_REMOVE_MEMBER,
            group_name="AiSOC-SOC-Leads",
            expected_email="ada@example.com",
        )

    async def test_entra_shaped_sequence(self, client):
        await _sequence(
            client,
            create_body=ENTRA_CREATE_USER,
            deactivate_body=ENTRA_DEACTIVATE,
            add_member=ENTRA_ADD_MEMBER,
            remove_member=ENTRA_REMOVE_MEMBER,
            group_name="AiSOC SOC Lead",
            expected_email="grace@example.com",
        )

    async def test_the_string_false_really_deactivates(self, client):
        """The single most consequential difference between the two dialects.

        ``bool("False")`` is True. Read naively, this payload deactivates
        nothing and returns 200, so the provider records the deprovisioning
        as successful and the principal keeps their access.
        """
        created = await client.post(f"{BASE}/Users", json=ENTRA_CREATE_USER)
        user_id = created.json()["id"]
        response = await client.patch(f"{BASE}/Users/{user_id}", json=ENTRA_DEACTIVATE)
        assert response.json()["active"] is False

    async def test_both_boolean_spellings_work(self, client):
        created = await client.post(f"{BASE}/Users", json=ENTRA_CREATE_USER)
        user_id = created.json()["id"]
        patched = await client.patch(f"{BASE}/Users/{user_id}", json=ENTRA_DEACTIVATE_BOOL)
        assert patched.json()["active"] is False

    async def test_a_value_that_is_neither_true_nor_false_is_refused(self, client):
        """Refused rather than defaulted.

        A default here would apply something the provider did not ask for,
        and neither side could tell that happened.
        """
        created = await client.post(f"{BASE}/Users", json=OKTA_CREATE_USER)
        user_id = created.json()["id"]
        response = await client.patch(
            f"{BASE}/Users/{user_id}",
            json={"schemas": [PATCH_SCHEMA], "Operations": [{"op": "replace", "path": "active", "value": "perhaps"}]},
        )
        assert response.status_code == 400
        assert response.json()["scimType"] == "invalidValue"

    async def test_an_unknown_attribute_does_not_fail_the_operation_beside_it(self, client):
        """A provider sends its whole mapped attribute set in one body.

        Rejecting ``title`` would fail the deactivation that arrived with it.
        """
        created = await client.post(f"{BASE}/Users", json=OKTA_CREATE_USER)
        user_id = created.json()["id"]
        response = await client.patch(
            f"{BASE}/Users/{user_id}",
            json={
                "schemas": [PATCH_SCHEMA],
                "Operations": [
                    {"op": "replace", "path": "title", "value": "Principal Engineer"},
                    {"op": "replace", "path": "active", "value": "False"},
                ],
            },
        )
        assert response.status_code == 200
        assert response.json()["active"] is False


# ---------------------------------------------------------------------------
# Auditing
# ---------------------------------------------------------------------------


class TestAuditing:
    async def test_every_write_lands_in_the_audit_log_naming_the_token(self, client, session_factory):
        """The actor of a SCIM change is a machine.

        An audit trail that cannot say which machine is not an audit trail.
        """
        created = await client.post(f"{BASE}/Users", json=OKTA_CREATE_USER)
        user_id = created.json()["id"]
        await client.patch(f"{BASE}/Users/{user_id}", json=OKTA_DEACTIVATE)
        group = await client.post(f"{BASE}/Groups", json={"displayName": "AiSOC-SOC-Leads"})
        await client.delete(f"{BASE}/Groups/{group.json()['id']}")

        async with session_factory() as db:
            rows = (await db.execute(select(AuditLog))).scalars().all()

        actions = {row.action for row in rows}
        assert {"scim:user:create", "scim:user:patch", "scim:group:create", "scim:group:delete"} <= actions
        for row in rows:
            assert row.actor_email.startswith("scim:")
            assert row.changes is not None
            assert "provisioned_by" in row.changes
            assert row.changes["provisioned_by"]["integration"] == "okta-primary"

    async def test_the_deprovisioning_record_says_what_it_ended(self, client, session_factory):
        """Counts, not a boolean.

        An audit row saying "deactivated" cannot answer whether the API keys
        went with it, which is the question a review asks.
        """
        created = await client.post(f"{BASE}/Users", json=OKTA_CREATE_USER)
        user_id = uuid.UUID(created.json()["id"])
        async with session_factory() as db:
            db.add(
                ApiKey(
                    tenant_id=TENANT,
                    user_id=user_id,
                    name="k",
                    key_prefix="aisoc_k1",
                    hashed_key=uuid.uuid4().hex,
                    scopes=[],
                    is_active=True,
                )
            )
            await db.commit()

        await client.delete(f"{BASE}/Users/{user_id}")

        async with session_factory() as db:
            rows = (await db.execute(select(AuditLog).where(AuditLog.action == "scim:user:delete"))).scalars().all()
        assert len(rows) == 1
        assert rows[0].changes["programmatic_access_revoked"] == 1
        assert rows[0].changes["sessions_revoked_at"]
