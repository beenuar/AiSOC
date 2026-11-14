"""``POST /playbook-steps/references`` hands decrypted vendor secrets to the internal peer only.

What was wrong
--------------
The route resolves a playbook ``http`` step's ``${NAME}`` tokens into the
tenant's configured integrations, and for four of the five reference kinds the
resolved value *is* the secret: ``headers`` carries the bearer header value,
``webhook`` the Slack/Teams URL with its embedded token, ``routing_key`` the
PagerDuty Events key, ``smtp`` the whole relay configuration including the
password.

Its own docstring stated the security argument — those halves "are returned to
the agents service, which is an authenticated internal peer holding the service
token" — and the resolver underneath admitted a second class of caller
entirely: an interactive session holding ``actions:execute``, which
``ROLE_PERMISSIONS`` grants to ``soc_analyst``, the role that runs playbooks
day to day. So the lowest role on the platform could read back the plaintext of
every credential the vault exists to protect, over the API, by naming it
(GHSA-c5qq-vhf5-wjqc). The names are guessable from the shipped packs.

RLS is not a second line here, and this suite is written knowing that. The
route depends on ``get_db``, which never binds ``app.current_tenant_id``, so
``aisoc_playbook_references``' policy
``(tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)`` takes its
unbound arm and matches every row. The tenant predicate in
``playbook_references._rows`` is the only thing scoping the read, and *who may
ask at all* was never scoped by anything.

What this asserts
-----------------
The refusal has to hold in the strong form, so three separate things are
checked rather than just the status code:

* a session caller is refused — at **every** role, because the defect is the
  class of caller and not the privilege level, and fixing it by demanding a
  higher permission would leave a tenant admin reading SMTP passwords out of
  an API that was never meant to emit them;
* **no secret value appears in the refusal body**, whatever the status is; and
* the vault is **never asked to decrypt** on the refused path. A refusal that
  still decrypted would leave the plaintext a log line or an exception message
  away, and "it was not in the body this time" is not the property worth
  pinning.

The positive control is as load-bearing as the refusals. A route that refuses
everybody passes every negative assertion while being broken, and stuck-closed
reads as working caution — so the agents service peer must still resolve all
four kinds and still receive the real plaintext, which is the whole reason the
route exists.

Why live
--------
Real Postgres as the ``NOBYPASSRLS`` runtime role, the real ASGI app with its
real auth dependencies, and a real vault doing real Fernet. The secrets are
written as ciphertext and asserted to be ciphertext at rest, so "the plaintext
came back" is a statement about the decrypt path actually running rather than
about a fixture that was never encrypted.

``ENVIRONMENT=production`` deliberately: ``development`` is in
``AUTH_BYPASS_ENVIRONMENTS`` and resolves an uncredentialed request to a demo
**admin**, which would make an authorization test pass for the worst possible
reason.
"""

from __future__ import annotations

import json
import os
import uuid

import httpx
import pytest
import pytest_asyncio

# Skipped as a *module*, not only in the fixture: the offline isolation job
# collects this directory with no Postgres running, and a test that did not
# take the fixture would otherwise run and fail there — a failure about the
# harness, reported against a capability.
pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_PLAYBOOK_REF_DSN", "").strip(),
        reason="ISOLATION_PLAYBOOK_REF_DSN is not set; this suite needs live infrastructure",
    ),
]

SECRET = "isolation-playbook-ref-secret-at-least-32-characters"
SERVICE_TOKEN = "isolation-playbook-ref-service-token"

TENANT = uuid.UUID("c5c5c5c5-0000-0000-0000-0000000005c9")

#: One marker per reference kind that carries a secret half. Distinct strings
#: so a leak names which kind leaked rather than only that something did.
BEARER_MARKER = "MARKER_OKTA_BEARER_c5qq01"
WEBHOOK_MARKER = "https://hooks.slack.example/MARKER_WEBHOOK_c5qq02"
ROUTING_MARKER = "MARKER_PD_ROUTING_c5qq03"
SMTP_MARKER = "MARKER_SMTP_PASSWORD_c5qq04"
ALL_MARKERS = (BEARER_MARKER, WEBHOOK_MARKER, ROUTING_MARKER, SMTP_MARKER)

NAMES = ["OKTA_HEADERS", "SLACK_WEBHOOK", "PAGERDUTY_KEY", "SMTP"]

URL = "/api/v1/playbook-steps/references"


def _dsn() -> str:
    value = os.environ.get("ISOLATION_PLAYBOOK_REF_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_PLAYBOOK_REF_DSN is not set; this suite needs a live Postgres")
    return value


@pytest.fixture(scope="module", autouse=True)
def _env():
    """Production posture and the two credentials both caller shapes need."""
    keys = (
        "ENVIRONMENT",
        "SECRET_KEY",
        "AISOC_AGENTS_SERVICE_TOKEN",
        "AISOC_CREDENTIAL_KEY",
        "DATABASE_URL",
        "AISOC_DEV_MODE",
        "AISOC_DEV_AUTH_BYPASS",
    )
    previous = {k: os.environ.get(k) for k in keys}
    from cryptography.fernet import Fernet

    os.environ["ENVIRONMENT"] = "production"
    os.environ["SECRET_KEY"] = SECRET
    os.environ["AISOC_AGENTS_SERVICE_TOKEN"] = SERVICE_TOKEN
    os.environ["AISOC_CREDENTIAL_KEY"] = Fernet.generate_key().decode()
    os.environ["DATABASE_URL"] = _dsn()
    os.environ.pop("AISOC_DEV_MODE", None)
    os.environ.pop("AISOC_DEV_AUTH_BYPASS", None)
    yield
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


@pytest_asyncio.fixture(scope="module", loop_scope="module", autouse=True)
async def _release_engine(_env):  # noqa: ANN001
    """Hand the shared engine's pool back when this module's loop ends.

    ``app.db.database.engine`` is a module global whose pool binds to whichever
    event loop first used it. Two module-scoped live suites in one pytest
    process therefore leave the second holding connections from a loop that has
    closed, which surfaces as ``RuntimeError: Event loop is closed`` and reads
    like a database fault rather than the harness artefact it is.
    """
    yield
    # Imported here, not at module scope: the engine is constructed from
    # ``settings.DATABASE_URL`` at import time, and ``_env`` above is what sets
    # it. A top-level import would bind the engine to whatever DSN the
    # environment happened to carry.
    from app.db.database import engine

    await engine.dispose()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def seeded(_env):  # noqa: ANN001
    """One tenant, one user per role under test, and all four secret kinds.

    Written through the application's own vault so the rows are genuine
    ciphertext, and asserted to be — a fixture that stored plaintext would make
    every "the secret came back" assertion vacuous.
    """
    import sqlalchemy
    from app.db.database import AsyncSessionLocal
    from app.security.credential_vault import get_vault

    vault = get_vault()

    def sealed(payload: dict) -> str:
        token = str(vault.encrypt_dict({"payload": json.dumps(payload)})["payload"])
        assert token.startswith("vault:v1:"), "the fixture must store ciphertext, or the decrypt path is never exercised"
        return token

    users = {role: uuid.uuid4() for role in ("soc_analyst", "soc_lead", "tenant_admin")}
    rows = (
        ("OKTA_HEADERS", "headers", "", sealed({"Authorization": f"Bearer {BEARER_MARKER}"})),
        ("SLACK_WEBHOOK", "webhook", "slack", sealed({"webhook_url": WEBHOOK_MARKER})),
        ("PAGERDUTY_KEY", "routing_key", "pagerduty", sealed({"routing_key": ROUTING_MARKER})),
        ("SMTP", "smtp", "email", sealed({"smtp_host": "smtp.example.com", "smtp_password": SMTP_MARKER})),
    )

    async with AsyncSessionLocal() as session:
        await session.execute(
            sqlalchemy.text(
                "INSERT INTO tenants (id, name, slug, is_active) VALUES (CAST(:i AS uuid), :n, :s, true) ON CONFLICT (id) DO NOTHING"
            ),
            {"i": str(TENANT), "n": "playbook-ref-isolation", "s": f"pbref-{TENANT}"},
        )
        for role, user_id in users.items():
            await session.execute(
                sqlalchemy.text(
                    "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active, is_verified) "
                    "VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :e, :u, 'unused', :r, true, true) "
                    "ON CONFLICT (id) DO NOTHING"
                ),
                {"i": str(user_id), "t": str(TENANT), "e": f"{role}-{user_id}@example.com", "u": f"{role}-{user_id}", "r": role},
            )
        for name, kind, channel, secret in rows:
            # Bound the way `get_tenant_db` binds a production write: the
            # policy's WITH CHECK arm has no unbound form, so an unbound seed
            # is refused by Postgres rather than silently landing.
            await session.execute(
                sqlalchemy.text("SELECT set_config('app.current_tenant_id', :t, TRUE)"),
                {"t": str(TENANT)},
            )
            await session.execute(
                sqlalchemy.text(
                    "INSERT INTO aisoc_playbook_references "
                    "(id, tenant_id, name, kind, channel, value, secret_value, enabled) "
                    "VALUES (gen_random_uuid(), CAST(:t AS uuid), :n, :k, :c, '', :s, true) "
                    "ON CONFLICT (tenant_id, name) DO UPDATE SET secret_value = EXCLUDED.secret_value, enabled = true"
                ),
                {"t": str(TENANT), "n": name, "k": kind, "c": channel, "s": secret},
            )
        await session.commit()

    yield users

    async with AsyncSessionLocal() as session:
        await session.execute(
            sqlalchemy.text("DELETE FROM aisoc_playbook_references WHERE tenant_id = CAST(:t AS uuid)"),
            {"t": str(TENANT)},
        )
        for user_id in users.values():
            await session.execute(sqlalchemy.text("DELETE FROM users WHERE id = CAST(:i AS uuid)"), {"i": str(user_id)})
        await session.commit()


@pytest_asyncio.fixture(loop_scope="module")
async def client(_env):  # noqa: ANN001
    """The real API ASGI application, over the real request pipeline."""
    from app.main import app as application

    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://api") as http:
        yield http


def session_token(user_id: uuid.UUID, *, role: str) -> str:
    """A real access token, minted by the application's own signer."""
    from app.core.security import create_access_token

    return create_access_token({"sub": str(user_id), "tenant_id": str(TENANT), "role": role})


def _leaked(body: str) -> list[str]:
    return [marker for marker in ALL_MARKERS if marker in body]


# ---------------------------------------------------------------------------
# The finding
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["soc_analyst", "soc_lead", "tenant_admin"])
async def test_a_session_token_cannot_read_back_decrypted_vendor_secrets(client, seeded, role):  # noqa: ANN001
    """The reported defect: a `soc_analyst` session got 200 and four plaintext secrets.

    Parametrised over every role that holds ``actions:execute`` because the
    defect is the *class* of caller. Fixing it by requiring a higher permission
    would move the boundary without closing it — a tenant admin reading SMTP
    passwords back out of the API is the same disclosure with a longer path.
    """
    response = await client.post(
        URL,
        json={"names": NAMES},
        headers={"Authorization": f"Bearer {session_token(seeded[role], role=role)}"},
    )

    assert response.status_code == 403, f"a {role} session reached the reference resolver: {response.status_code} {response.text[:400]}"


@pytest.mark.parametrize("role", ["soc_analyst", "soc_lead", "tenant_admin"])
async def test_no_secret_appears_in_the_refusal_body(client, seeded, role):  # noqa: ANN001
    """Whatever the status code, the body must not carry a decrypted value.

    Asserted separately from the status so a future refactor that changes the
    status cannot quietly take this with it.
    """
    response = await client.post(
        URL,
        json={"names": NAMES},
        headers={"Authorization": f"Bearer {session_token(seeded[role], role=role)}"},
    )

    assert _leaked(response.text) == [], f"the refusal to a {role} carried secrets: {_leaked(response.text)}"


async def test_the_refusal_lands_before_the_vault_is_asked(client, seeded, monkeypatch):  # noqa: ANN001
    """Not merely "no secret in the body": nothing is decrypted at all.

    A refusal that still decrypted would leave the plaintext one log line or
    one exception message away from an unauthorised caller, and the property
    worth holding is that the vault is never opened for a caller this route
    will not serve.
    """
    from app.services import playbook_references

    opened: list[str] = []
    real = playbook_references.get_vault

    def _watched():
        opened.append("decrypt")
        return real()

    monkeypatch.setattr(playbook_references, "get_vault", _watched)

    await client.post(
        URL,
        json={"names": NAMES},
        headers={"Authorization": f"Bearer {session_token(seeded['soc_analyst'], role='soc_analyst')}"},
    )

    assert opened == [], f"the refused request still opened the vault {len(opened)} time(s)"


async def test_an_unauthenticated_caller_is_refused(client, seeded):  # noqa: ANN001
    """No credential at all is a 401, not a 403 — and still carries no secret."""
    response = await client.post(URL, json={"names": NAMES})

    assert response.status_code == 401
    assert _leaked(response.text) == []


async def test_a_wrong_service_token_is_refused(client, seeded):  # noqa: ANN001
    """The service path is a shared secret, so a near-miss must not open it."""
    response = await client.post(
        URL,
        json={"names": NAMES, "tenant_id": str(TENANT)},
        headers={"X-AiSOC-Service-Token": SERVICE_TOKEN + "-wrong"},
    )

    assert response.status_code == 401
    assert _leaked(response.text) == []


# ---------------------------------------------------------------------------
# Positive controls — the route must still do its job, or "fixed" means "broken"
# ---------------------------------------------------------------------------


async def test_the_agents_service_peer_still_resolves_every_kind(client, seeded):  # noqa: ANN001
    """The caller this route exists for, getting the plaintext it needs.

    Every one of the four secret-bearing kinds, because a fix that happened to
    keep ``headers`` working while dropping ``smtp`` would read as success here
    and as "no destination configured" to an operator at 3am.
    """
    response = await client.post(
        URL,
        json={"names": NAMES, "tenant_id": str(TENANT)},
        headers={"X-AiSOC-Service-Token": SERVICE_TOKEN},
    )

    assert response.status_code == 200, f"the internal peer was refused its own references: {response.text[:400]}"
    references = response.json()["references"]
    assert set(references) == set(NAMES), f"the peer lost references it had: {sorted(references)}"
    assert references["OKTA_HEADERS"]["headers"]["Authorization"] == f"Bearer {BEARER_MARKER}"
    assert references["SLACK_WEBHOOK"]["webhook_url"] == WEBHOOK_MARKER
    assert references["PAGERDUTY_KEY"]["pd_routing_key"] == ROUTING_MARKER
    assert references["SMTP"]["smtp_password"] == SMTP_MARKER


async def test_the_service_peer_reads_only_the_tenant_it_names(client, seeded):  # noqa: ANN001
    """Delegation stays bounded: the declared tenant scopes the read.

    RLS cannot be the thing holding this — the route's session never binds
    ``app.current_tenant_id``, so the policy's unbound arm matches every row
    and the predicate in ``_rows`` is the only control. This is what asserts
    the predicate is still there.
    """
    response = await client.post(
        URL,
        json={"names": NAMES, "tenant_id": str(uuid.uuid4())},
        headers={"X-AiSOC-Service-Token": SERVICE_TOKEN},
    )

    assert response.status_code == 200
    assert response.json()["references"] == {}, "a service caller naming another tenant read this tenant's secrets"
    assert _leaked(response.text) == []
