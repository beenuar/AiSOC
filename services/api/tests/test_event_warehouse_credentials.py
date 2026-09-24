"""Warehouse credentials come from the tenant's connectors, not from settings.

What these tests are defending
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before this module existed, every event-warehouse driver resolved its
endpoint and secret from process settings — ``ES_URL`` / ``ES_API_KEY`` for
Elasticsearch, ``SPLUNK_URL`` / ``SPLUNK_HMAC_TOKEN`` for Splunk. None of
those were declared fields on ``Settings``; they were read through
``getattr(settings, "ES_URL", None)``, so the lookup returned ``None`` on
every deployment and every scheduled hunt returned zero hits. Because
``Settings`` sets ``extra="ignore"``, an operator who followed the error
message and exported ``ES_URL`` got the same message back.

``test_settings_declare_the_documented_fallback_fields`` pins the first half
of the fix; the rest of the file pins the part that matters more — that the
credentials a driver runs with belong to the tenant whose hunt is running,
and are read from the row the console wizard wrote.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.core.config import Settings, settings
from app.models.connector import Connector
from app.security.credential_vault import CredentialVaultError
from app.services.event_warehouse import (
    HuntNotConfigured,
    WarehouseCredentials,
    connected_warehouse_types,
    resolve_tenant_warehouse,
)

VAULT_PATH = "app.services.event_warehouse.credentials.get_vault"


def _make_connector(
    *,
    tenant_id: uuid.UUID,
    connector_type: str = "elastic",
    name: str = "Prod cluster",
    auth_config: dict[str, Any] | None = None,
    connector_config: dict[str, Any] | None = None,
) -> Connector:
    return Connector(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        name=name,
        connector_type=connector_type,
        category="siem",
        is_enabled=True,
        auth_config=auth_config or {"api_key": "vault:v1:abc"},
        connector_config=connector_config or {},
    )


def _db_returning(*connectors: Connector) -> Any:
    """An ``AsyncSession`` double whose ``execute`` yields ``connectors``.

    Records the statement it was handed so a test can assert on the compiled
    SQL rather than trusting that the filter was applied.
    """
    scalars = MagicMock()
    scalars.first = MagicMock(return_value=connectors[0] if connectors else None)
    scalars.all = MagicMock(return_value=list(connectors))

    result = MagicMock()
    result.scalars = MagicMock(return_value=scalars)

    db = MagicMock()
    db.execute = AsyncMock(return_value=result)
    return db


def _vault_returning(payload: dict[str, Any] | Exception) -> Any:
    vault = MagicMock()
    if isinstance(payload, Exception):
        vault.decrypt_dict = MagicMock(side_effect=payload)
    else:
        vault.decrypt_dict = MagicMock(return_value=payload)
    return vault


class TestSettingsFallback:
    def test_settings_declare_the_documented_fallback_fields(self) -> None:
        """``esql_runner`` has always told operators to "set them in environment
        variables". Until these fields existed, doing so had no effect:
        ``Settings`` ignores undeclared variables."""
        assert hasattr(settings, "ES_URL")
        assert hasattr(settings, "ES_API_KEY")

    def test_exported_env_var_now_reaches_settings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ES_URL", "https://es.example.com:9200")
        monkeypatch.setenv("ES_API_KEY", "secret-key")
        fresh = Settings()
        assert fresh.ES_URL == "https://es.example.com:9200"
        assert fresh.ES_API_KEY == "secret-key"

    def test_fallback_defaults_to_unset(self) -> None:
        """Unset must be ``None``, not a localhost guess — a hunt silently
        pointed at 127.0.0.1 is worse than one that says it is unconfigured."""
        assert Settings().ES_URL is None


class TestResolveTenantWarehouse:
    async def test_returns_decrypted_credentials_for_the_tenant(self) -> None:
        tenant_id = uuid.uuid4()
        connector = _make_connector(tenant_id=tenant_id, connector_config={"index": "logs-*"})
        db = _db_returning(connector)

        with patch(VAULT_PATH, return_value=_vault_returning({"api_key": "plaintext", "base_url": "https://es:9200"})):
            creds = await resolve_tenant_warehouse(db, tenant_id, connector_types=("elastic",))

        assert isinstance(creds, WarehouseCredentials)
        assert creds.connector_type == "elastic"
        assert creds.connector_name == "Prod cluster"
        assert creds.get("api_key") == "plaintext"
        assert creds.get("base_url") == "https://es:9200"
        # Non-secret connector_config is merged into the lookup surface.
        assert creds.get("index") == "logs-*"

    async def test_query_is_scoped_to_tenant_enabled_and_type(self) -> None:
        """The three filters are the isolation boundary. Asserting on the
        compiled SQL catches a regression that a mocked return value cannot."""
        tenant_id = uuid.uuid4()
        db = _db_returning(_make_connector(tenant_id=tenant_id))

        with patch(VAULT_PATH, return_value=_vault_returning({"api_key": "k"})):
            await resolve_tenant_warehouse(db, tenant_id, connector_types=("elastic",))

        stmt = db.execute.await_args.args[0]
        compiled = str(stmt.compile(compile_kwargs={"literal_binds": False}))
        assert "connectors.tenant_id = " in compiled
        assert "connectors.is_enabled IS true" in compiled
        assert "connectors.connector_type IN " in compiled

    async def test_pinned_connector_id_is_still_tenant_filtered(self) -> None:
        """Naming a connector must not bypass the tenant filter — otherwise an
        id from another tenant would resolve to their credentials."""
        tenant_id = uuid.uuid4()
        pinned = uuid.uuid4()
        db = _db_returning(_make_connector(tenant_id=tenant_id))

        with patch(VAULT_PATH, return_value=_vault_returning({"api_key": "k"})):
            await resolve_tenant_warehouse(db, tenant_id, connector_types=("elastic",), connector_id=pinned)

        compiled = str(db.execute.await_args.args[0])
        assert "connectors.tenant_id = " in compiled
        assert "connectors.id = " in compiled

    async def test_raises_when_tenant_has_no_matching_connector(self) -> None:
        db = _db_returning()

        with pytest.raises(HuntNotConfigured) as excinfo:
            await resolve_tenant_warehouse(db, uuid.uuid4(), connector_types=("elastic",))

        # The message has to be actionable in the console, not in a shell.
        assert "console" in str(excinfo.value)
        assert "no enabled connector" in str(excinfo.value)

    async def test_undecryptable_secret_is_distinguishable_from_no_connector(self) -> None:
        """An operator must be able to tell "nobody connected a SIEM" from
        "the vault key rotated and the stored secret is unreadable"."""
        tenant_id = uuid.uuid4()
        db = _db_returning(_make_connector(tenant_id=tenant_id))

        with patch(VAULT_PATH, return_value=_vault_returning(CredentialVaultError("bad key"))):
            with pytest.raises(HuntNotConfigured) as excinfo:
                await resolve_tenant_warehouse(db, tenant_id, connector_types=("elastic",))

        assert "could not be decrypted" in str(excinfo.value)

    async def test_decryption_failure_does_not_leak_ciphertext(self) -> None:
        tenant_id = uuid.uuid4()
        connector = _make_connector(tenant_id=tenant_id, auth_config={"api_key": "vault:v1:SUPERSECRETBLOB"})
        db = _db_returning(connector)

        with patch(VAULT_PATH, return_value=_vault_returning(CredentialVaultError("bad key"))):
            with pytest.raises(HuntNotConfigured) as excinfo:
                await resolve_tenant_warehouse(db, tenant_id, connector_types=("elastic",))

        assert "SUPERSECRETBLOB" not in str(excinfo.value)


class TestConnectedWarehouseTypes:
    async def test_returns_only_types_the_tenant_enabled(self) -> None:
        tenant_id = uuid.uuid4()
        db = _db_returning(
            _make_connector(tenant_id=tenant_id, connector_type="splunk"),
            _make_connector(tenant_id=tenant_id, connector_type="splunk", name="DR"),
        )

        found = await connected_warehouse_types(db, tenant_id, candidate_types=("elastic", "splunk"))

        assert found == {"splunk"}

    async def test_empty_candidate_list_does_not_query(self) -> None:
        db = _db_returning()

        found = await connected_warehouse_types(db, uuid.uuid4(), candidate_types=())

        assert found == set()
        db.execute.assert_not_awaited()


class TestWarehouseCredentialsLookup:
    def _creds(self, **kwargs: Any) -> WarehouseCredentials:
        return WarehouseCredentials(
            connector_id=uuid.uuid4(),
            connector_type="elastic",
            connector_name="c",
            **kwargs,
        )

    def test_auth_wins_over_config(self) -> None:
        creds = self._creds(auth={"base_url": "from-auth"}, config={"base_url": "from-config"})
        assert creds.get("base_url") == "from-auth"

    def test_falls_back_to_config(self) -> None:
        creds = self._creds(auth={}, config={"base_url": "from-config"})
        assert creds.get("base_url") == "from-config"

    def test_tries_alias_names_in_order(self) -> None:
        creds = self._creds(auth={"url": "second-choice"}, config={})
        assert creds.get("base_url", "url") == "second-choice"

    def test_empty_string_is_treated_as_absent(self) -> None:
        """A connector saved with a blank field must not defeat the fallback."""
        creds = self._creds(auth={"base_url": ""}, config={"base_url": "real"})
        assert creds.get("base_url") == "real"

    def test_false_is_preserved(self) -> None:
        """``ssl_verify: False`` is a real value and must not be skipped as empty."""
        creds = self._creds(auth={}, config={"ssl_verify": False})
        assert creds.get("ssl_verify", default=True) is False
