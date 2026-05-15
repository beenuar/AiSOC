"""Tests for the shared ES|QL runner — Track 3, T3.4 (`/hunt` NL surface).

Pins the contract of :mod:`app.services.esql_runner`, the small async
helper that both the request-scoped ``/nl-query/execute`` endpoint and
the out-of-band saved-hunt scheduler call to execute ES|QL queries
against Elasticsearch.

Coverage map
~~~~~~~~~~~~

* :func:`_validate_es_url` — SSRF guard rejects hosts that don't match
  the configured ES_URL, rejects non-HTTP(S) schemes, and reconstructs
  the URL from validated parts only (no attacker-controlled path leak).
* :func:`resolve_es_credentials` — explicit overrides win, falls back
  to ``ES_URL`` / ``ELASTICSEARCH_URL`` settings, raises a typed
  :class:`ESQLNotConfigured` when both sides come up empty so callers
  can pick "skip" vs "error" semantics.
* :func:`run_esql_query` — happy path returns columns + rows + took_ms,
  appends ``LIMIT`` when missing, propagates the LIMIT the caller
  supplied, surfaces transport errors as :class:`ESQLExecutionError`,
  propagates :class:`AirgapViolation` unchanged when air-gap is on,
  propagates :class:`ValueError` unchanged for SSRF guard failures.

These tests are unit-scoped — we patch ``httpx.AsyncClient`` so the
suite stays sub-second and runs in CI without a network. The full
integration with the saved-hunt scheduler is exercised separately in
``test_saved_hunts_endpoint.py``.

Author: Track 3 / T3.4 (`/hunt` NL surface).
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from app.core.airgap import AirgapViolation
from app.services import esql_runner
from app.services.esql_runner import (
    ESQLExecutionError,
    ESQLNotConfigured,
    ESQLResult,
    _validate_es_url,
    resolve_es_credentials,
    run_esql_query,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class _FakeSettings:
    """Minimal stand-in for the Pydantic ``Settings`` singleton.

    The production deployment reads ES connection fields via
    ``getattr(settings, "ES_URL", None)`` so they don't have to be
    declared on the :class:`Settings` model. The model itself uses
    ``extra="ignore"``, which silently drops ``setattr`` for any field
    that *isn't* declared — that makes ``monkeypatch.setattr`` unusable
    against the real settings object for these fields.

    A plain attribute bag dodges the problem entirely: ``getattr`` does
    exactly what the runner expects, and unset fields fall through to
    the runner's default just like in production.
    """

    def __init__(self, **kwargs: Any) -> None:
        for k, v in kwargs.items():
            setattr(self, k, v)


@pytest.fixture
def pin_es_settings(monkeypatch: pytest.MonkeyPatch):
    """Replace the module-level settings with a fake configured for ES.

    All tests in this module operate against ``http://es.local:9200`` so
    the SSRF guard has a single configured host to compare against. The
    fake exposes the legacy alias (``ELASTICSEARCH_URL``) as well, so
    the resolver's fallback chain has consistent behaviour regardless
    of which one the deployment actually configured.
    """
    fake = _FakeSettings(
        ES_URL="http://es.local:9200",
        ES_API_KEY="test-api-key",
        ELASTICSEARCH_URL="http://es.local:9200",
        OPENSEARCH_URL="http://localhost:9200",
    )
    monkeypatch.setattr(esql_runner, "settings", fake)
    yield fake


def _mock_httpx_client(
    *,
    json_payload: dict[str, Any] | None = None,
    status_code: int = 200,
    raise_on_post: Exception | None = None,
) -> tuple[MagicMock, AsyncMock]:
    """Build a mock ``httpx.AsyncClient`` context manager.

    Returns ``(client_factory, post_mock)`` so tests can assert on the
    post args (URL, headers, json body) without re-mocking the
    response shape.
    """
    response = MagicMock()
    response.status_code = status_code
    response.json = MagicMock(return_value=json_payload or {"columns": [], "values": []})
    if status_code >= 400:
        response.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                "boom", request=MagicMock(), response=response
            )
        )
    else:
        response.raise_for_status = MagicMock()

    post_mock = AsyncMock(return_value=response)
    if raise_on_post is not None:
        post_mock = AsyncMock(side_effect=raise_on_post)

    client = MagicMock()
    client.post = post_mock
    client_cm = MagicMock()
    client_cm.__aenter__ = AsyncMock(return_value=client)
    client_cm.__aexit__ = AsyncMock(return_value=None)

    client_factory = MagicMock(return_value=client_cm)
    return client_factory, post_mock


# ---------------------------------------------------------------------------
# _validate_es_url — SSRF guard
# ---------------------------------------------------------------------------


class TestValidateEsUrl:
    """Direct tests of the SSRF guard.

    The guard is the only line of defence between an attacker-controlled
    URL (via a saved hunt row or future operator-supplied override) and
    the outbound httpx call, so each invariant deserves a pinned test.
    """

    def test_accepts_configured_host(self, pin_es_settings) -> None:
        # Same scheme, same host, same port → allowed. The returned URL
        # must be reconstructed (scheme + netloc only) so any path or
        # query in the input is discarded.
        out = _validate_es_url("http://es.local:9200")
        assert out == "http://es.local:9200"

    def test_strips_user_supplied_path(self, pin_es_settings) -> None:
        # The whole point of the reconstruct: an attacker who can
        # influence the input URL can't smuggle in a path that points
        # at another endpoint on the same host.
        out = _validate_es_url("http://es.local:9200/_internal/secret")
        assert out == "http://es.local:9200"
        assert "_internal" not in out
        assert "secret" not in out

    def test_strips_user_supplied_query(self, pin_es_settings) -> None:
        out = _validate_es_url("http://es.local:9200/_query?inject=1")
        assert "?" not in out
        assert "inject" not in out

    def test_rejects_mismatched_host(self, pin_es_settings) -> None:
        with pytest.raises(ValueError, match="not the configured host"):
            _validate_es_url("http://attacker.example.com:9200")

    def test_rejects_mismatched_port(self, pin_es_settings) -> None:
        # Same host, different port — still a mismatch. ``netloc`` is
        # ``host:port``, so this is one comparison, not two.
        with pytest.raises(ValueError, match="not the configured host"):
            _validate_es_url("http://es.local:9201")

    def test_rejects_ftp_scheme(self, pin_es_settings) -> None:
        # The scheme check is independent of the host check — a hostile
        # input with the right host but a weird scheme should still 422.
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            _validate_es_url("ftp://es.local:9200")

    def test_rejects_file_scheme(self, pin_es_settings) -> None:
        # The crown jewel of SSRF — ``file://`` is the canonical
        # path-traversal vector and must be refused even if the host
        # matches. (urlparse parses ``file://es.local/etc/passwd``
        # with that host; the scheme guard is what stops it.)
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            _validate_es_url("file://es.local/etc/passwd")

    def test_falls_back_to_opensearch_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When ``ES_URL`` is unset, the resolver tries OPENSEARCH_URL."""
        fake = _FakeSettings(
            ES_URL=None,
            ELASTICSEARCH_URL=None,
            OPENSEARCH_URL="http://opensearch.local:9200",
        )
        monkeypatch.setattr(esql_runner, "settings", fake)
        out = _validate_es_url("http://opensearch.local:9200")
        assert out == "http://opensearch.local:9200"


# ---------------------------------------------------------------------------
# resolve_es_credentials
# ---------------------------------------------------------------------------


class TestResolveEsCredentials:
    """Pin the explicit-override-then-settings fallback chain.

    Two callers exercise this from very different angles: the endpoint
    (which always uses the settings — body-supplied URLs were removed
    as a partial-SSRF mitigation) and the scheduler (which also uses
    settings, but a future operator-only API might pass overrides).
    """

    def test_returns_settings_when_no_overrides(self, pin_es_settings) -> None:
        url, key = resolve_es_credentials()
        assert url == "http://es.local:9200"
        assert key == "test-api-key"

    def test_explicit_overrides_win(self, pin_es_settings) -> None:
        url, key = resolve_es_credentials(
            es_url="http://other.local:9200",
            es_api_key="override-key",
        )
        assert url == "http://other.local:9200"
        assert key == "override-key"

    def test_raises_when_url_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeSettings(ES_URL=None, ELASTICSEARCH_URL=None, ES_API_KEY="k")
        monkeypatch.setattr(esql_runner, "settings", fake)
        with pytest.raises(ESQLNotConfigured):
            resolve_es_credentials()

    def test_raises_when_key_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeSettings(ES_URL="http://es.local:9200", ES_API_KEY=None)
        monkeypatch.setattr(esql_runner, "settings", fake)
        with pytest.raises(ESQLNotConfigured):
            resolve_es_credentials()


# ---------------------------------------------------------------------------
# run_esql_query — happy paths
# ---------------------------------------------------------------------------


class TestRunEsqlQueryHappyPath:
    """The 200-response shape pins the contract for both callers."""

    def test_returns_columns_rows_and_took_ms(
        self, pin_es_settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client_factory, _post_mock = _mock_httpx_client(
            json_payload={
                "columns": [{"name": "@timestamp", "type": "date"}, {"name": "host.name", "type": "keyword"}],
                "values": [
                    ["2026-05-15T10:00:00Z", "host1"],
                    ["2026-05-15T10:01:00Z", "host2"],
                ],
            }
        )
        monkeypatch.setattr(esql_runner.httpx, "AsyncClient", client_factory)

        result = asyncio.run(
            run_esql_query(
                esql="FROM logs-* | LIMIT 10",
                es_url="http://es.local:9200",
                es_api_key="test-api-key",
            )
        )

        assert isinstance(result, ESQLResult)
        assert result.columns == ["@timestamp", "host.name"]
        assert result.rows == [
            ["2026-05-15T10:00:00Z", "host1"],
            ["2026-05-15T10:01:00Z", "host2"],
        ]
        assert result.took_ms >= 0

    def test_post_target_url_is_validated_and_rebuilt(
        self, pin_es_settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Even if the caller passes a URL with a path, the runner
        reconstructs the target as ``<scheme>://<netloc>/_query``."""
        client_factory, post_mock = _mock_httpx_client()
        monkeypatch.setattr(esql_runner.httpx, "AsyncClient", client_factory)

        asyncio.run(
            run_esql_query(
                esql="FROM logs-*",
                es_url="http://es.local:9200/some/internal/path",  # path should be stripped
                es_api_key="test-api-key",
            )
        )

        # The post call must hit ``/_query`` against the validated host,
        # *not* ``/some/internal/path/_query``.
        args, kwargs = post_mock.call_args
        called_url = args[0] if args else kwargs.get("url")
        assert called_url == "http://es.local:9200/_query"

    def test_appends_limit_when_caller_did_not(
        self, pin_es_settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client_factory, post_mock = _mock_httpx_client()
        monkeypatch.setattr(esql_runner.httpx, "AsyncClient", client_factory)

        asyncio.run(
            run_esql_query(
                esql="FROM logs-* | WHERE foo == 'bar'",
                es_url="http://es.local:9200",
                es_api_key="test-api-key",
                max_rows=42,
            )
        )

        _, kwargs = post_mock.call_args
        query_sent = kwargs["json"]["query"]
        assert "| LIMIT 42" in query_sent

    def test_preserves_caller_supplied_limit(
        self, pin_es_settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If the translator already emitted ``| LIMIT 10``, the runner
        must not append a second LIMIT — Elasticsearch rejects two
        LIMITs in a single query."""
        client_factory, post_mock = _mock_httpx_client()
        monkeypatch.setattr(esql_runner.httpx, "AsyncClient", client_factory)

        asyncio.run(
            run_esql_query(
                esql="FROM logs-* | LIMIT 10",
                es_url="http://es.local:9200",
                es_api_key="test-api-key",
                max_rows=500,
            )
        )

        _, kwargs = post_mock.call_args
        query_sent = kwargs["json"]["query"]
        # Exactly one LIMIT — and the one the caller supplied, not the
        # max_rows default the runner would otherwise have appended.
        assert query_sent.upper().count("| LIMIT") == 1
        assert "| LIMIT 10" in query_sent

    def test_limit_detection_is_case_insensitive(
        self, pin_es_settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """LLM-enhanced queries may lower-case ``LIMIT``. The detector
        must still notice it and not double-append."""
        client_factory, post_mock = _mock_httpx_client()
        monkeypatch.setattr(esql_runner.httpx, "AsyncClient", client_factory)

        asyncio.run(
            run_esql_query(
                esql="FROM logs-* | limit 10",
                es_url="http://es.local:9200",
                es_api_key="test-api-key",
                max_rows=500,
            )
        )

        _, kwargs = post_mock.call_args
        query_sent = kwargs["json"]["query"]
        assert query_sent.upper().count("| LIMIT") == 1

    def test_authorization_header_is_api_key(
        self, pin_es_settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ES expects ``Authorization: ApiKey <key>``, not Bearer."""
        client_factory, post_mock = _mock_httpx_client()
        monkeypatch.setattr(esql_runner.httpx, "AsyncClient", client_factory)

        asyncio.run(
            run_esql_query(
                esql="FROM logs-*",
                es_url="http://es.local:9200",
                es_api_key="my-secret-key",
            )
        )

        _, kwargs = post_mock.call_args
        headers = kwargs["headers"]
        assert headers["Authorization"] == "ApiKey my-secret-key"
        assert headers["Content-Type"] == "application/json"


# ---------------------------------------------------------------------------
# run_esql_query — error paths
# ---------------------------------------------------------------------------


class TestRunEsqlQueryErrors:
    """Each failure mode maps to a distinct exception so callers can
    surface a precise error to the analyst (rather than a generic 500)."""

    def test_mismatched_host_raises_value_error_before_post(
        self, pin_es_settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SSRF guard fires *before* we open the httpx client, so a
        hostile URL never hits the network."""
        client_factory, post_mock = _mock_httpx_client()
        monkeypatch.setattr(esql_runner.httpx, "AsyncClient", client_factory)

        with pytest.raises(ValueError, match="not the configured host"):
            asyncio.run(
                run_esql_query(
                    esql="FROM logs-*",
                    es_url="http://attacker.example.com:9200",
                    es_api_key="test-api-key",
                )
            )

        post_mock.assert_not_awaited()

    def test_http_status_error_wraps_into_esql_execution_error(
        self, pin_es_settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client_factory, _post_mock = _mock_httpx_client(status_code=500)
        monkeypatch.setattr(esql_runner.httpx, "AsyncClient", client_factory)

        with pytest.raises(ESQLExecutionError, match="ES|QL execution failed"):
            asyncio.run(
                run_esql_query(
                    esql="FROM logs-*",
                    es_url="http://es.local:9200",
                    es_api_key="test-api-key",
                )
            )

    def test_transport_error_wraps_into_esql_execution_error(
        self, pin_es_settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A network-level httpx error (timeout, conn refused, etc.) is
        wrapped into ``ESQLExecutionError`` so callers don't need an
        httpx import in their except clauses."""
        client_factory, _post_mock = _mock_httpx_client(
            raise_on_post=httpx.ConnectError("connection refused")
        )
        monkeypatch.setattr(esql_runner.httpx, "AsyncClient", client_factory)

        with pytest.raises(ESQLExecutionError, match="ES|QL execution failed"):
            asyncio.run(
                run_esql_query(
                    esql="FROM logs-*",
                    es_url="http://es.local:9200",
                    es_api_key="test-api-key",
                )
            )

    def test_airgap_violation_propagates_unchanged(
        self, pin_es_settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Air-gap is special: the endpoint surfaces it as a dedicated
        503, so the runner must propagate the original exception type
        rather than wrap it in ``ESQLExecutionError``."""
        # Pretend the air-gap guard fires for this URL.
        def _explode(_url: str) -> None:
            raise AirgapViolation("blocked by air-gap policy")

        monkeypatch.setattr(esql_runner, "enforce_airgap_for_url", _explode)
        client_factory, post_mock = _mock_httpx_client()
        monkeypatch.setattr(esql_runner.httpx, "AsyncClient", client_factory)

        with pytest.raises(AirgapViolation):
            asyncio.run(
                run_esql_query(
                    esql="FROM logs-*",
                    es_url="http://es.local:9200",
                    es_api_key="test-api-key",
                )
            )

        # The air-gap guard fires before httpx is opened.
        post_mock.assert_not_awaited()
