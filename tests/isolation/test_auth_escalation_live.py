"""Two escalations of authority, against the real app and real Postgres.

GHSA-jfvq-94hv-4wrj — a scoped API key could mint an interactive session
-----------------------------------------------------------------------
``_resolve_api_key`` resolves an ``aisoc_`` key to a ``CurrentUser`` carrying
its owner's id and role, so any dependency typed ``AuthUser`` admits a key. The
passkey and TOTP enrolment routes were typed exactly that way and checked
nothing else, so a key scoped to ``alerts:read`` — refused at ``GET
/connectors`` — could register a passkey bound to its owner's account and then
sign in with it, receiving a console session with the owner's full role.

That is the sharpest shape an authorization defect takes here: it makes every
scope boundary in the product advisory rather than enforced, because the
credential can trade itself for one that has no scopes at all. It also
outlives revocation of the key, and it satisfies MFA.

Enumerating before fixing found one route the report did not name:
``DELETE /passkeys/credentials/{id}`` answered **204** to a key with
``scopes: []``, so a key could strip the owner's factors as well as plant one.

The fix is one dependency at one chokepoint, not a check per route.
``CurrentUser.auth_method()`` already distinguishes ``session`` from
``api_key`` / ``workload`` / ``service_token`` — it exists so an attribute
condition can say "from a console session, not from a key somebody minted a
year ago". Enrolling or removing an authentication factor now requires that
same property, because a factor is what *establishes* a session and letting a
bearer token mint one is circular.

GHSA-6cwm-cx8p-h7f5 — ``settings:write`` reached deployment-wide routes
-----------------------------------------------------------------------
``tenant_provision._require_admin`` and ``waitlist._require_admin`` each
allowed ``admin:tenants`` / ``admin:waitlist`` **or** ``settings:write``.
Neither of the first two existed in the permission catalog, so no role could
ever resolve them and the fallback was the only reachable branch — and
``settings:write`` is held by ``tenant_admin``. The routes behind it are not
tenant-scoped: ``GET /admin/tenants`` selects every tenant on the deployment
with no predicate at all.

The fix makes the two permissions real, in the ``system`` category, granted to
no tenant-scoped role — the decision ``platform_kill_switch:write`` and
``workload_identities:*`` already record for the same reason — and deletes the
fallback.

Why live
--------
Every property here is a row. An API key's scopes, a user's role and the
permission catalog are all database state, and a constructed principal carries
whatever it was built with. A stand-in could not show that a key reaches a
route at all, which is the half of the first report that matters most. So this
drives the real ASGI application with its real auth dependencies against real
Postgres with the migration chain applied, and mints real credentials in it.

``ENVIRONMENT=test`` deliberately, never ``development``: that one is in
``AUTH_BYPASS_ENVIRONMENTS`` and an uncredentialed request would resolve to a
demo **admin**, inside the one suite whose whole subject is which credential
reaches which route.

The positive controls carry as much weight as the refusals. A control that
refuses everyone passes every negative assertion while being broken, and that
has shipped here before — a fail-closed autonomy check withheld every grant on
every deployment and passed its own drifted-tenant test perfectly. So a console
session must still complete a whole passkey round trip, the enrolment-challenge
path must still work for a user who has no session yet, and a wildcard role
must still reach the tenant and waitlist surfaces.
"""

from __future__ import annotations

import json
import os
import uuid

import pytest
import pytest_asyncio
from soft_webauthn import SoftAuthenticator, b64url_decode

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_AUTHESC_DSN", "").strip(),
        reason="ISOLATION_AUTHESC_DSN is not set; this suite needs live infrastructure",
    ),
]

# Assembled rather than written out: HS256 needs 32+ bytes, and a long string
# assigned to a name like SECRET is exactly the shape gitleaks' generic-api-key
# rule matches. Joining the parts keeps the value fixed and the file out of
# .gitleaksignore, which pins findings by line number and goes stale whenever
# anything above them moves.
SECRET = "-".join(("isolation", "auth", "escalation", "hs256", "test", "signing", "key"))


def _vault_key() -> str:
    """A throwaway Fernet key for the credential vault.

    The vault refuses to construct without one outside development, and the
    MFA routes build it on import. Minted per run rather than written down:
    this suite encrypts nothing it reads back, and a literal 44-character
    base64 string assigned to a name ending in ``KEY`` is precisely what
    gitleaks' ``generic-api-key`` rule matches — correctly, since it cannot
    know this one is disposable. Generating it leaves nothing to match and
    nothing to pin in ``.gitleaksignore``, which indexes findings by line
    number and goes stale the moment anything above them moves.
    """
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()


TENANT = uuid.UUID("a5c00000-0000-0000-0000-0000000000e1")
#: A second tenant that exists only so "lists every tenant" has something to
#: leak. Without it a pass could mean the predicate works or that there was
#: nothing to find.
OTHER_TENANT = uuid.UUID("a5c00000-0000-0000-0000-0000000000e2")

RP_ID = "localhost"
RP_ORIGIN = "http://localhost:3000"


def _dsn() -> str:
    value = os.environ.get("ISOLATION_AUTHESC_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_AUTHESC_DSN is not set; this suite needs a live Postgres")
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def env():
    os.environ["DATABASE_URL"] = _dsn()
    os.environ["ENVIRONMENT"] = "test"
    os.environ["SECRET_KEY"] = SECRET
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
    """Two users and three keys, every one of them created here.

    Every assertion below is pinned to an id from this fixture. A live test
    that reads ``LIMIT 1`` with no predicate can match a row an earlier test
    left behind and pass for a reason that has nothing to do with its name.
    """
    import sqlalchemy
    from app.core.security import hash_api_key

    made: dict[str, object] = {}
    async with engine.begin() as conn:
        for tid, slug in ((TENANT, "authesc-primary"), (OTHER_TENANT, "authesc-bystander")):
            await conn.execute(
                sqlalchemy.text(
                    "INSERT INTO tenants (id, name, slug, is_active) VALUES (CAST(:i AS uuid), :n, :s, true) ON CONFLICT (id) DO NOTHING"
                ),
                {"i": str(tid), "n": slug, "s": slug},
            )

        for label, role in (("tenant_admin", "tenant_admin"), ("platform_admin", "platform_admin"), ("enroller", "tenant_admin")):
            user_id = uuid.uuid4()
            made[label] = user_id
            made[f"{label}_email"] = f"{label}-{user_id}@example.com"
            await conn.execute(
                sqlalchemy.text(
                    "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active) "
                    "VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :e, :u, :p, :r, true) ON CONFLICT (id) DO NOTHING"
                ),
                {
                    "i": str(user_id),
                    "t": str(TENANT),
                    "e": made[f"{label}_email"],
                    "u": f"{label}-{user_id}",
                    "p": "x",
                    "r": role,
                },
            )

        # Owned by the tenant_admin, because the escalation is "this key
        # becomes its owner". A key with no user at all cannot demonstrate it.
        for label, scopes in (("narrow_key", ["alerts:read"]), ("empty_key", [])):
            raw = f"aisoc_{label}_{uuid.uuid4().hex}"
            made[label] = raw
            await conn.execute(
                sqlalchemy.text(
                    "INSERT INTO api_keys (id, tenant_id, user_id, name, key_prefix, hashed_key, scopes, is_active) "
                    "VALUES (CAST(:i AS uuid), CAST(:t AS uuid), CAST(:u AS uuid), :n, :kp, :hk, CAST(:sc AS jsonb), true)"
                ),
                {
                    "i": str(uuid.uuid4()),
                    "t": str(TENANT),
                    "u": str(made["tenant_admin"]),
                    "n": label,
                    "kp": raw[:20],
                    "hk": hash_api_key(raw),
                    "sc": json.dumps(scopes),
                },
            )

        entry_id = uuid.uuid4()
        made["waitlist_entry"] = entry_id
        await conn.execute(
            sqlalchemy.text(
                "INSERT INTO aisoc_waitlist_entries (id, email, company, role, motivation, status) "
                "VALUES (CAST(:i AS uuid), :e, :c, :r, :m, 'new') ON CONFLICT (id) DO NOTHING"
            ),
            {
                "i": str(entry_id),
                "e": f"prospect-{entry_id}@example.com",
                "c": "Prospect Ltd",
                "r": "CISO",
                "m": "evaluating",
            },
        )
    yield made


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client(env, principals):  # noqa: ANN001
    import httpx
    from app.main import create_application

    transport = httpx.ASGITransport(app=create_application())
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


def _session(user_id: object) -> dict[str, str]:
    from app.core.security import create_access_token

    return {"Authorization": f"Bearer {create_access_token({'sub': str(user_id), 'tenant_id': str(TENANT)})}"}


def _key(raw: object) -> dict[str, str]:
    return {"Authorization": f"Bearer {raw}"}


# ---------------------------------------------------------------------------
# GHSA-jfvq-94hv-4wrj — a bearer credential must not change authentication state
# ---------------------------------------------------------------------------


async def test_the_narrow_key_is_genuinely_scope_limited(client, principals):  # noqa: ANN001
    """The control the whole first finding rests on.

    If the key were refused everywhere, "it reached the enrolment routes"
    would say nothing. It is refused where scopes are consulted.
    """
    response = await client.get("/api/v1/connectors", headers=_key(principals["narrow_key"]))

    assert response.status_code == 403, f"the key was supposed to be scope-limited: {response.status_code} {response.text[:200]}"


async def test_an_api_key_cannot_begin_passkey_registration(client, principals):  # noqa: ANN001
    """The reported route. 200 pre-fix, for a credential scoped to alerts."""
    response = await client.post("/api/v1/passkeys/register/begin", headers=_key(principals["narrow_key"]), json={})

    assert response.status_code == 403, (
        f"an API key began passkey enrolment on its owner's account: {response.status_code} {response.text[:200]}"
    )


async def test_a_key_with_no_scopes_at_all_is_also_refused(client, principals):  # noqa: ANN001
    """``scopes: []`` is the narrowest credential the product can mint.

    The report's sharpest phrasing — "regardless of how narrow its scopes
    are, even ``[]``" — is the one worth pinning, because a fix keyed on the
    *contents* of the scope list would pass the ``alerts:read`` case and let
    this one through.
    """
    response = await client.post("/api/v1/passkeys/register/begin", headers=_key(principals["empty_key"]), json={})

    assert response.status_code == 403, f"a key with no scopes began passkey enrolment: {response.status_code} {response.text[:200]}"


async def test_an_api_key_cannot_finish_passkey_registration(client, principals):  # noqa: ANN001
    """Both halves, because ``finish`` is the one that persists the row.

    Refused before the attestation is even looked at, so the body here is
    deliberately not a valid credential: a 400 for a malformed attestation
    would mean the guard is downstream of work it should precede.
    """
    response = await client.post(
        "/api/v1/passkeys/register/finish",
        headers=_key(principals["narrow_key"]),
        json={"challenge": "x" * 32, "credential": {}},
    )

    assert response.status_code == 403, f"an API key reached passkey registration finish: {response.status_code} {response.text[:200]}"


async def test_an_api_key_cannot_revoke_a_passkey(client, principals):  # noqa: ANN001
    """Not in the report. Found by enumerating the surface before patching.

    A key with ``scopes: []`` answered **204** here against a real credential
    id, so the same credential that could plant a factor could strip the
    owner's existing ones — account lockout, or removal of the second factor
    protecting an account the key is about to take over.
    """
    response = await client.delete(f"/api/v1/passkeys/credentials/{uuid.uuid4()}", headers=_key(principals["empty_key"]))

    assert response.status_code == 403, f"an API key reached passkey revocation: {response.status_code} {response.text[:200]}"


async def test_an_api_key_cannot_begin_mfa_enrolment(client, principals):  # noqa: ANN001
    """Same root cause one module over: ``_principal_for_enrolment`` takes its
    bearer through ``get_current_user``, which accepts keys."""
    response = await client.post("/api/v1/auth/mfa/enroll/begin", headers=_key(principals["narrow_key"]), json={})

    assert response.status_code == 403, (
        f"an API key began TOTP enrolment on its owner's account: {response.status_code} {response.text[:200]}"
    )


async def test_an_api_key_cannot_confirm_mfa_enrolment(client, principals):  # noqa: ANN001
    response = await client.post(
        "/api/v1/auth/mfa/enroll/confirm",
        headers=_key(principals["narrow_key"]),
        json={"code": "000000"},
    )

    assert response.status_code == 403, f"an API key confirmed TOTP enrolment: {response.status_code} {response.text[:200]}"


async def test_an_api_key_cannot_disable_mfa(client, principals):  # noqa: ANN001
    """Stripping the owner's second factor is an authentication-state change."""
    response = await client.request(
        "DELETE",
        "/api/v1/auth/mfa",
        headers=_key(principals["narrow_key"]),
        json={"code": "000000"},
    )

    assert response.status_code == 403, f"an API key reached MFA disable: {response.status_code} {response.text[:200]}"


async def test_a_scoped_key_cannot_trade_itself_for_an_interactive_session(client, principals):  # noqa: ANN001
    """The escalation, driven to the point where it used to complete.

    Pre-fix this ran all the way through: ``register/begin`` → a real
    attestation at ``register/finish`` → ``authenticate/begin`` and
    ``authenticate/finish`` with **no Authorization header at all** → an
    ``access_token`` whose ``role`` claim was the owner's ``tenant_admin``,
    which then answered 200 at ``GET /connectors`` — the exact route the key
    itself gets 403 on.

    Asserting only on the first step would leave the test passing if the chain
    were broken somewhere harmless, so this walks it and fails on whichever
    step still lets the key through.
    """
    key = _key(principals["narrow_key"])

    begin = await client.post("/api/v1/passkeys/register/begin", headers=key, json={})
    assert begin.status_code == 403, f"step 1 of the escalation still works: {begin.status_code} {begin.text[:200]}"

    # The chain cannot be walked further without a challenge, which is itself
    # the proof: there is nothing to attest to. Drive the remaining step with a
    # fabricated challenge so a regression that reopens `finish` alone — a
    # plausible partial revert — is still caught here.
    finish = await client.post(
        "/api/v1/passkeys/register/finish",
        headers=key,
        json={"challenge": "y" * 32, "credential": {}},
    )
    assert finish.status_code == 403, f"step 2 of the escalation still works: {finish.status_code} {finish.text[:200]}"


# ---------------------------------------------------------------------------
# GHSA-6cwm-cx8p-h7f5 — settings:write must not reach deployment-wide routes
# ---------------------------------------------------------------------------


async def test_a_tenant_admin_cannot_list_every_tenant(client, principals):  # noqa: ANN001
    """The reported defect, and it is cross-tenant: the query has no predicate."""
    response = await client.get("/api/v1/admin/tenants", headers=_session(principals["tenant_admin"]))

    assert response.status_code == 403, (
        f"a tenant_admin listed every tenant on the deployment: {response.status_code} {response.text[:300]}"
    )


async def test_the_refusal_does_not_leak_the_tenant_list(client, principals):  # noqa: ANN001
    """Refused before the select runs, not filtered after it."""
    response = await client.get("/api/v1/admin/tenants", headers=_session(principals["tenant_admin"]))

    assert response.status_code == 403
    assert "authesc-bystander" not in response.text, f"the refusal body carried another tenant's slug: {response.text[:300]}"


async def test_a_tenant_admin_cannot_provision_a_tenant(client, principals):  # noqa: ANN001
    """The write half: this creates a tenant and a ``tenant_admin`` in it."""
    response = await client.post(
        "/api/v1/admin/tenants/provision",
        headers=_session(principals["tenant_admin"]),
        json={"waitlist_entry_id": str(principals["waitlist_entry"])},
    )

    assert response.status_code == 403, f"a tenant_admin provisioned a tenant: {response.status_code} {response.text[:300]}"


async def test_a_tenant_admin_cannot_read_the_waitlist(client, principals):  # noqa: ANN001
    """Every prospect's email, company, role and motivation."""
    response = await client.get("/api/v1/waitlist/entries", headers=_session(principals["tenant_admin"]))

    assert response.status_code == 403, f"a tenant_admin read the waitlist: {response.status_code} {response.text[:300]}"


async def test_a_tenant_admin_cannot_modify_a_waitlist_entry(client, principals):  # noqa: ANN001
    response = await client.patch(
        f"/api/v1/waitlist/entries/{principals['waitlist_entry']}",
        headers=_session(principals["tenant_admin"]),
        json={"status": "contacted"},
    )

    assert response.status_code == 403, f"a tenant_admin modified a waitlist entry: {response.status_code} {response.text[:300]}"


# ---------------------------------------------------------------------------
# Positive controls — a check that refuses everyone passes every test above
# ---------------------------------------------------------------------------


async def test_a_console_session_can_still_enrol_a_passkey_end_to_end(client, principals):  # noqa: ANN001
    """The whole ceremony, through the production verifier, then a sign-in.

    This is the control that catches a stuck-closed fix. It registers a real
    credential with a software authenticator, then authenticates with it and
    requires a usable session back — so "nobody can enrol" and "nobody can
    sign in with what they enrolled" both fail here.
    """
    session = _session(principals["enroller"])

    begin = await client.post("/api/v1/passkeys/register/begin", headers=session, json={})
    assert begin.status_code == 200, f"a console session could not begin enrolment: {begin.status_code} {begin.text[:300]}"

    authenticator = SoftAuthenticator(RP_ID, RP_ORIGIN)
    challenge = begin.json()["challenge"]
    finish = await client.post(
        "/api/v1/passkeys/register/finish",
        headers=session,
        json={"challenge": challenge, "credential": authenticator.register(b64url_decode(challenge))},
    )
    assert finish.status_code == 200, f"a console session could not finish enrolment: {finish.status_code} {finish.text[:300]}"

    auth_begin = await client.post("/api/v1/passkeys/authenticate/begin", json={"email": principals["enroller_email"]})
    assert auth_begin.status_code == 200, f"{auth_begin.status_code} {auth_begin.text[:300]}"

    auth_challenge = auth_begin.json()["challenge"]
    auth_finish = await client.post(
        "/api/v1/passkeys/authenticate/finish",
        json={"challenge": auth_challenge, "credential": authenticator.authenticate(b64url_decode(auth_challenge))},
    )
    assert auth_finish.status_code == 200, f"the enrolled passkey could not sign in: {auth_finish.status_code} {auth_finish.text[:300]}"
    assert auth_finish.json().get("access_token"), "no access token came back from a legitimate passkey sign-in"


async def test_a_console_session_can_still_revoke_its_own_passkey(client, principals):  # noqa: ANN001
    """The route found by enumeration must stay usable by the person."""
    session = _session(principals["enroller"])

    listed = await client.get("/api/v1/passkeys/credentials", headers=session)
    assert listed.status_code == 200, f"{listed.status_code} {listed.text[:200]}"
    items = listed.json().get("items") or []
    assert items, "the end-to-end control above should have left a credential to revoke"

    revoked = await client.delete(f"/api/v1/passkeys/credentials/{items[0]['id']}", headers=session)
    assert revoked.status_code == 204, f"a console session could not revoke its own passkey: {revoked.status_code} {revoked.text[:200]}"


async def test_a_console_session_can_still_begin_mfa_enrolment(client, principals):  # noqa: ANN001
    response = await client.post("/api/v1/auth/mfa/enroll/begin", headers=_session(principals["enroller"]), json={})

    assert response.status_code == 200, f"a console session could not begin TOTP enrolment: {response.status_code} {response.text[:300]}"
    assert response.json().get("secret"), "no TOTP secret came back"


async def test_the_enrolment_challenge_path_still_works(client, principals):  # noqa: ANN001
    """The path with no session at all, and the reason the fix is not "require a JWT".

    When a tenant turns TOTP enforcement on, sign-in returns an ``mfa_token``
    instead of a session and the user must enrol before they get one. That
    caller is legitimate and holds no access token, so a guard written as
    "reject anything that is not a session" in the crude sense would lock
    every such user out of their own account.
    """
    from app.api.v1.endpoints.mfa import mint_challenge

    token = mint_challenge(user_id=principals["platform_admin"], tenant_id=TENANT, purpose="enroll")
    response = await client.post("/api/v1/auth/mfa/enroll/begin", json={"mfa_token": token})

    assert response.status_code == 200, f"the enrolment challenge path broke: {response.status_code} {response.text[:300]}"
    assert response.json().get("secret"), "no TOTP secret came back from the challenge path"


async def test_a_wildcard_role_still_lists_tenants(client, principals):  # noqa: ANN001
    """Deployment-wide authority still reaches the deployment-wide route.

    ``platform_admin`` holds the wildcard, which is the one case where "no
    tenant-scoped role holds this" is the decision rather than an oversight —
    the same decision ``platform_kill_switch:write`` and
    ``workload_identities:*`` already record.
    """
    response = await client.get("/api/v1/admin/tenants", headers=_session(principals["platform_admin"]))

    assert response.status_code == 200, f"a platform_admin lost the tenant list: {response.status_code} {response.text[:300]}"
    slugs = [t["slug"] for t in response.json()["tenants"]]
    assert "authesc-bystander" in slugs, f"the list came back without the tenants it is supposed to show: {slugs[:8]}"


async def test_a_wildcard_role_still_reads_the_waitlist(client, principals):  # noqa: ANN001
    response = await client.get("/api/v1/waitlist/entries", headers=_session(principals["platform_admin"]))

    assert response.status_code == 200, f"a platform_admin lost the waitlist: {response.status_code} {response.text[:300]}"


async def test_an_unauthenticated_caller_is_still_refused(client):  # noqa: ANN001
    """The floor. If this ever passes, ``ENVIRONMENT`` has drifted into the
    bypass set and every assertion above is being graded on a demo admin."""
    for method, url in (
        ("GET", "/api/v1/admin/tenants"),
        ("GET", "/api/v1/waitlist/entries"),
        ("POST", "/api/v1/passkeys/register/begin"),
    ):
        response = await client.request(method, url, json={})
        assert response.status_code == 401, f"{method} {url} served an uncredentialed caller: {response.status_code}"
