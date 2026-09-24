"""The warehouse drivers run against the tenant's connector, and Splunk runs.

Regression notes
~~~~~~~~~~~~~~~~

``TestSplunkProvider`` is new behaviour in the strict sense: the previous
``SplunkProvider.run_hunt`` raised :class:`HuntNotConfigured`
unconditionally. Its first branch checked ``settings.SPLUNK_URL`` and
``settings.SPLUNK_HMAC_TOKEN`` — neither is a declared field on
``Settings`` — and the line after it raised "provider scaffolded but live
SPL execution not yet shipped" regardless. Every one of these tests fails
against that implementation, including the ones that only assert an error
message, because the old message was the scaffold text.

``TestElasticsearchProvider`` covers the same shift for ES|QL: the driver
called ``resolve_es_credentials()``, which read the same kind of undeclared
setting, so it could not reach a cluster and could not be pointed at a
per-tenant one.
"""

from __future__ import annotations

import base64
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.core.airgap import AirgapViolation
from app.services.esql_runner import ESQLExecutionError, ESQLResult
from app.services.event_warehouse import HuntExecutionError, HuntNotConfigured, WarehouseCredentials
from app.services.event_warehouse.elasticsearch import ElasticsearchProvider, elastic_auth_header
from app.services.event_warehouse.splunk import SplunkProvider
from app.services.spl_runner import SPLExecutionError, SPLResult

ES_RUN = "app.services.event_warehouse.elasticsearch.run_esql_query"
SPL_RUN = "app.services.event_warehouse.splunk.run_spl_query"


def _hunt(**translated: str) -> Any:
    hunt = MagicMock()
    hunt.id = uuid.uuid4()
    hunt.tenant_id = uuid.uuid4()
    hunt.translated_query = dict(translated)
    return hunt


def _creds(connector_type: str, auth: dict[str, Any], config: dict[str, Any] | None = None) -> WarehouseCredentials:
    return WarehouseCredentials(
        connector_id=uuid.uuid4(),
        connector_type=connector_type,
        connector_name="Prod",
        auth=auth,
        config=config or {},
    )


class TestElasticAuthHeader:
    def test_api_key_wins(self) -> None:
        creds = _creds("elastic", {"api_key": "k", "username": "u", "password": "p"})
        assert elastic_auth_header(creds) == "ApiKey k"

    def test_basic_auth_fallback(self) -> None:
        """Self-managed clusters commonly use a service account; the connector
        schema offers username/password as an alternative to an API key."""
        creds = _creds("elastic", {"username": "u", "password": "p"})
        expected = base64.b64encode(b"u:p").decode()
        assert elastic_auth_header(creds) == f"Basic {expected}"

    def test_neither_is_an_actionable_error(self) -> None:
        creds = _creds("elastic", {"base_url": "https://es:9200"})
        with pytest.raises(HuntNotConfigured, match="neither an API key nor a"):
            elastic_auth_header(creds)

    def test_error_does_not_echo_the_secret_fields(self) -> None:
        creds = _creds("elastic", {"password": "hunter2"})
        with pytest.raises(HuntNotConfigured) as excinfo:
            elastic_auth_header(creds)
        assert "hunter2" not in str(excinfo.value)


class TestElasticsearchProvider:
    def setup_method(self) -> None:
        self.provider = ElasticsearchProvider()

    async def test_runs_against_the_connectors_url(self) -> None:
        hunt = _hunt(esql="FROM logs-* | LIMIT 5")
        creds = _creds("elastic", {"base_url": "https://tenant-a.es.example.com:9200", "api_key": "k"})

        with patch(ES_RUN, new=AsyncMock(return_value=ESQLResult(columns=["h"], rows=[["a"], ["b"]], took_ms=4))) as run:
            hits = await self.provider.run_hunt(hunt, credentials=creds, max_rows=25)

        assert hits == 2
        kwargs = run.await_args.kwargs
        assert kwargs["es_url"] == "https://tenant-a.es.example.com:9200"
        assert kwargs["auth_header"] == "ApiKey k"
        assert kwargs["max_rows"] == 25

    async def test_ssrf_allow_list_is_the_connectors_own_url(self) -> None:
        """Per-tenant allow-list: this tenant's hunt can reach the cluster they
        registered and nothing else. The allow-list used to be a global
        setting, so it could not describe more than one cluster."""
        hunt = _hunt(esql="FROM logs-*")
        creds = _creds("elastic", {"base_url": "https://tenant-a.es.example.com:9200", "api_key": "k"})

        with patch(ES_RUN, new=AsyncMock(return_value=ESQLResult([], [], 1))) as run:
            await self.provider.run_hunt(hunt, credentials=creds)

        assert run.await_args.kwargs["allowed_url"] == "https://tenant-a.es.example.com:9200"

    async def test_missing_url_is_an_actionable_skip(self) -> None:
        hunt = _hunt(esql="FROM logs-*")
        creds = _creds("elastic", {"api_key": "k"})

        with pytest.raises(HuntNotConfigured, match="no cluster URL"):
            await self.provider.run_hunt(hunt, credentials=creds)

    async def test_untranslated_hunt_is_unsupported_not_an_error(self) -> None:
        from app.services.event_warehouse import UnsupportedTranslation

        hunt = _hunt(spl="index=main")
        creds = _creds("elastic", {"base_url": "https://es:9200", "api_key": "k"})

        with pytest.raises(UnsupportedTranslation):
            await self.provider.run_hunt(hunt, credentials=creds)

    async def test_execution_error_becomes_hunt_execution_error(self) -> None:
        hunt = _hunt(esql="FROM logs-*")
        creds = _creds("elastic", {"base_url": "https://es:9200", "api_key": "k"})

        with patch(ES_RUN, new=AsyncMock(side_effect=ESQLExecutionError("ES 500"))):
            with pytest.raises(HuntExecutionError, match="ES 500"):
                await self.provider.run_hunt(hunt, credentials=creds)

    async def test_airgap_violation_is_re_raised_unchanged(self) -> None:
        hunt = _hunt(esql="FROM logs-*")
        creds = _creds("elastic", {"base_url": "https://es:9200", "api_key": "k"})

        with patch(ES_RUN, new=AsyncMock(side_effect=AirgapViolation("blocked"))):
            with pytest.raises(AirgapViolation):
                await self.provider.run_hunt(hunt, credentials=creds)


class TestSplunkProvider:
    """Every test here fails against the previous driver, which raised
    :class:`HuntNotConfigured` on every call."""

    def setup_method(self) -> None:
        self.provider = SplunkProvider()

    def test_declares_the_splunk_connector_type(self) -> None:
        assert self.provider.connector_types == ("splunk",)
        assert self.provider.translated_query_key == "spl"

    async def test_runs_the_translated_spl_and_counts_rows(self) -> None:
        hunt = _hunt(spl="index=* earliest=-24h | head 500")
        creds = _creds("splunk", {"base_url": "https://splunk.example.com:8089", "token": "t"})

        with patch(SPL_RUN, new=AsyncMock(return_value=SPLResult(rows=[{"a": 1}, {"a": 2}, {"a": 3}], took_ms=9))) as run:
            hits = await self.provider.run_hunt(hunt, credentials=creds, max_rows=100)

        assert hits == 3
        kwargs = run.await_args.kwargs
        assert kwargs["spl"] == "index=* earliest=-24h | head 500"
        assert kwargs["base_url"] == "https://splunk.example.com:8089"
        assert kwargs["token"] == "t"
        assert kwargs["max_rows"] == 100

    async def test_accepts_basic_auth_credentials(self) -> None:
        hunt = _hunt(spl="index=main")
        creds = _creds("splunk", {"base_url": "https://splunk:8089", "username": "svc", "password": "pw"})

        with patch(SPL_RUN, new=AsyncMock(return_value=SPLResult(rows=[], took_ms=1))) as run:
            await self.provider.run_hunt(hunt, credentials=creds)

        assert run.await_args.kwargs["username"] == "svc"
        assert run.await_args.kwargs["password"] == "pw"

    async def test_ssl_verify_defaults_to_on_when_the_key_is_absent(self) -> None:
        """A missing key must read as "verify". Defaulting the other way would
        silently disable certificate checking for every connector saved before
        the field existed."""
        hunt = _hunt(spl="index=main")
        creds = _creds("splunk", {"base_url": "https://splunk:8089", "token": "t"})

        with patch(SPL_RUN, new=AsyncMock(return_value=SPLResult(rows=[], took_ms=1))) as run:
            await self.provider.run_hunt(hunt, credentials=creds)

        assert run.await_args.kwargs["verify_ssl"] is True

    async def test_ssl_verify_false_is_honoured(self) -> None:
        hunt = _hunt(spl="index=main")
        creds = _creds("splunk", {"base_url": "https://splunk:8089", "token": "t"}, {"ssl_verify": False})

        with patch(SPL_RUN, new=AsyncMock(return_value=SPLResult(rows=[], took_ms=1))) as run:
            await self.provider.run_hunt(hunt, credentials=creds)

        assert run.await_args.kwargs["verify_ssl"] is False

    async def test_zero_rows_is_a_result_not_a_skip(self) -> None:
        hunt = _hunt(spl="index=main")
        creds = _creds("splunk", {"base_url": "https://splunk:8089", "token": "t"})

        with patch(SPL_RUN, new=AsyncMock(return_value=SPLResult(rows=[], took_ms=1))):
            assert await self.provider.run_hunt(hunt, credentials=creds) == 0

    async def test_missing_url_names_the_management_port(self) -> None:
        """Users paste the 8000 web URL; the message has to say 8089."""
        hunt = _hunt(spl="index=main")
        creds = _creds("splunk", {"token": "t"})

        with pytest.raises(HuntNotConfigured, match="8089"):
            await self.provider.run_hunt(hunt, credentials=creds)

    async def test_missing_credentials_is_an_actionable_skip(self) -> None:
        hunt = _hunt(spl="index=main")
        creds = _creds("splunk", {"base_url": "https://splunk:8089"})

        with pytest.raises(HuntNotConfigured, match="neither a token nor a"):
            await self.provider.run_hunt(hunt, credentials=creds)

    async def test_execution_error_becomes_hunt_execution_error(self) -> None:
        hunt = _hunt(spl="index=main")
        creds = _creds("splunk", {"base_url": "https://splunk:8089", "token": "t"})

        with patch(SPL_RUN, new=AsyncMock(side_effect=SPLExecutionError("Splunk 503"))):
            with pytest.raises(HuntExecutionError, match="Splunk 503"):
                await self.provider.run_hunt(hunt, credentials=creds)

    async def test_airgap_violation_is_re_raised_unchanged(self) -> None:
        hunt = _hunt(spl="index=main")
        creds = _creds("splunk", {"base_url": "https://splunk:8089", "token": "t"})

        with patch(SPL_RUN, new=AsyncMock(side_effect=AirgapViolation("blocked"))):
            with pytest.raises(AirgapViolation):
                await self.provider.run_hunt(hunt, credentials=creds)
