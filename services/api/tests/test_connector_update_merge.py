"""``PATCH /connectors/{id}`` merges the config blobs instead of replacing them.

The defect
----------
The handler wrote ``auth_config`` and ``connector_config`` wholesale. Two
things live beside the fields an operator edits, and both were erased:

* the other secrets — re-typing one token in a connector that holds a client
  id, a client secret and a refresh token left a row holding only that token,
  so the next poll failed authentication;
* the ``checkpoint`` and ``filter_rules`` the connectors service keeps in
  ``connector_config`` — changing a single poll knob dropped the cursor, and
  the next poll re-read the connector's whole lookback window.

Its own docstring said as much ("sending an empty ``auth_config`` dict will
overwrite all secrets"), which is why the console's Configure button answered
"Delete + re-add" instead of opening an editor. A re-added connector loses its
id, its checkpoint, its counters and its push ingest token.

The merge is RFC 7396 at depth one: a supplied key replaces, a ``null`` key
removes, an omitted key survives. The unit tests below pin that contract; the
live test drives the real route against PostgreSQL with the real vault, and
skips where no database answers, like every other ``*_live`` test here.
"""

from __future__ import annotations

import json
import os
import uuid

import httpx
import pytest
import pytest_asyncio
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints import connectors as connectors_endpoint
from app.api.v1.endpoints.connectors import merge_config_patch, router
from app.db.database import get_db
from app.security.credential_vault import CredentialVault
from cryptography.fernet import Fernet
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

# ─── merge_config_patch ──────────────────────────────────────────────────────


def test_keys_the_patch_does_not_name_survive() -> None:
    stored = {"domain": "acme.okta.com", "checkpoint": {"after": "c-41"}, "filter_rules": [{"drop": "debug"}]}
    merged = merge_config_patch(stored, {"domain": "beta.okta.com"})
    assert merged == {"domain": "beta.okta.com", "checkpoint": {"after": "c-41"}, "filter_rules": [{"drop": "debug"}]}


def test_a_null_removes_the_key_and_a_missing_key_is_not_an_error() -> None:
    merged = merge_config_patch({"page_size": 500, "region": "eu"}, {"page_size": None, "never_set": None})
    assert merged == {"region": "eu"}


def test_an_empty_patch_changes_nothing() -> None:
    """The old wholesale write turned ``{}`` into "erase every secret"."""
    stored = {"api_token": "vault:v1:abc", "client_secret": "vault:v1:def"}
    assert merge_config_patch(stored, {}) == stored


def test_nested_values_are_replaced_as_a_unit() -> None:
    """A pasted service-account key is one value, not something to merge into."""
    stored = {"service_account": {"client_email": "old@x.iam", "private_key": "vault:v1:old"}}
    merged = merge_config_patch(stored, {"service_account": {"client_email": "new@x.iam"}})
    assert merged == {"service_account": {"client_email": "new@x.iam"}}


def test_the_stored_mapping_is_not_mutated() -> None:
    stored = {"region": "eu"}
    merge_config_patch(stored, {"region": "us", "extra": 1})
    assert stored == {"region": "eu"}


@pytest.mark.parametrize("stored", [None, [], ["{}"], "corrupt"])
def test_a_stored_value_that_is_not_a_mapping_reads_as_empty(stored: object) -> None:
    assert merge_config_patch(stored, {"region": "eu"}) == {"region": "eu"}


def test_merged_secrets_keep_their_tokens_and_only_new_values_are_encrypted() -> None:
    """What the handler does with the merge: encrypt the result.

    Stored leaves are already vault tokens and must come out byte-identical —
    re-encrypting a token would wrap ciphertext in ciphertext and the
    connector would authenticate with it.
    """
    vault = CredentialVault(Fernet.generate_key())
    stored = vault.encrypt_dict({"client_id": "cid", "client_secret": "keep-me"})

    written = vault.encrypt_dict(merge_config_patch(stored, {"client_id": "rotated"}))

    assert written["client_secret"] == stored["client_secret"]
    assert written["client_id"].startswith("vault:")
    assert vault.decrypt_dict(written) == {"client_id": "rotated", "client_secret": "keep-me"}


# ─── The real route, real PostgreSQL ─────────────────────────────────────────

TENANT = uuid.UUID("0c100000-0000-0000-0000-0000000ed171")
CONNECTOR = uuid.UUID("0c100000-0000-0000-0000-0000000ed172")


@pytest_asyncio.fixture
async def live(monkeypatch: pytest.MonkeyPatch):
    dsn = os.environ.get("DATABASE_MIGRATION_URL", "").strip() or os.environ.get("DATABASE_URL", "")
    if "postgres" not in dsn:
        pytest.skip("requires live PostgreSQL with the API migration chain")
    engine = create_async_engine(dsn)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__})")

    vault = CredentialVault(Fernet.generate_key())
    monkeypatch.setattr(connectors_endpoint, "get_vault", lambda: vault)

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as db:
        try:
            await db.execute(text("DELETE FROM connectors WHERE tenant_id = :t"), {"t": TENANT})
            await db.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:t, 'Connector edit test', :s) ON CONFLICT (id) DO NOTHING"),
                {"t": TENANT, "s": f"connector-edit-{TENANT}"},
            )
            await db.execute(
                text(
                    """INSERT INTO connectors (id, tenant_id, name, connector_type, category, auth_config, connector_config)
                    VALUES (:id, :t, 'Okta production', 'okta', 'iam', CAST(:auth AS jsonb), CAST(:config AS jsonb))"""
                ),
                {
                    "id": CONNECTOR,
                    "t": TENANT,
                    "auth": json.dumps(vault.encrypt_dict({"api_token": "old-token", "client_secret": "keep-me"})),
                    "config": json.dumps(
                        {
                            "okta_domain": "acme.okta.com",
                            "page_size": 200,
                            "checkpoint": {"after": "cursor-41"},
                            "filter_rules": [{"field": "severity", "op": "eq", "value": "debug", "action": "drop"}],
                        }
                    ),
                },
            )
            await db.commit()

            principal = CurrentUser(
                user_id=uuid.uuid4(),
                tenant_id=TENANT,
                role="admin",
                email="connector-edit@example.test",
                resolved_permissions=frozenset({"connectors:read", "connectors:write"}),
            )
            app = FastAPI()
            app.include_router(router, prefix="/api/v1")
            app.dependency_overrides[get_current_user] = lambda: principal

            async def session():
                yield db

            app.dependency_overrides[get_db] = session
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://api.test") as client:
                yield client, db, vault
        finally:
            await db.rollback()
            await db.execute(text("DELETE FROM connectors WHERE tenant_id = :t"), {"t": TENANT})
            await db.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": TENANT})
            await db.commit()
    await engine.dispose()


async def _stored(db, vault: CredentialVault) -> tuple[dict, dict, dict, str]:
    row = (
        await db.execute(
            text("SELECT auth_config, connector_config, name FROM connectors WHERE id = :id"),
            {"id": CONNECTOR},
        )
    ).one()
    return row.auth_config, vault.decrypt_dict(row.auth_config), row.connector_config, row.name


@pytest.mark.asyncio
async def test_rotating_one_secret_keeps_the_rest_and_the_checkpoint(live) -> None:
    client, db, vault = live

    response = await client.patch(
        f"/api/v1/connectors/{CONNECTOR}",
        json={
            "name": "Okta staging",
            "auth_config": {"api_token": "new-token"},
            "connector_config": {"okta_domain": "beta.okta.com", "page_size": None},
        },
    )

    assert response.status_code == 200, response.text
    raw_auth, auth, config, name = await _stored(db, vault)
    assert name == "Okta staging"
    assert auth == {"api_token": "new-token", "client_secret": "keep-me"}
    assert all(str(v).startswith("vault:") for v in raw_auth.values()), "a secret was stored in cleartext"
    assert config == {
        "okta_domain": "beta.okta.com",
        "checkpoint": {"after": "cursor-41"},
        "filter_rules": [{"field": "severity", "op": "eq", "value": "debug", "action": "drop"}],
    }
    assert response.json()["connector_config"] == config
    assert "auth_config" not in response.json()


@pytest.mark.asyncio
async def test_an_empty_auth_config_no_longer_erases_the_credentials(live) -> None:
    client, db, vault = live

    response = await client.patch(f"/api/v1/connectors/{CONNECTOR}", json={"auth_config": {}})

    assert response.status_code == 200, response.text
    _, auth, _, _ = await _stored(db, vault)
    assert auth == {"api_token": "old-token", "client_secret": "keep-me"}


@pytest.mark.asyncio
async def test_a_blank_name_is_refused(live) -> None:
    client, db, vault = live

    response = await client.patch(f"/api/v1/connectors/{CONNECTOR}", json={"name": ""})

    assert response.status_code == 422
    _, _, _, name = await _stored(db, vault)
    assert name == "Okta production"
