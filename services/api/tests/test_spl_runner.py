"""Unit tests for the Splunk SPL executor.

Sibling of ``test_esql_runner``. The guards are the same three the ES|QL
runner carries — SSRF allow-list, air-gap policy, row cap — plus two
Splunk-specific behaviours that a missing test would let regress silently:

* ``POST /services/search/jobs`` rejects a search string that does not start
  with ``search`` or a generating ``|``. The platform translator emits
  ``index=* earliest=-24h ... | head 500``, which starts with neither, so
  every hunt would 400 without the prefix.
* The management port is 8089, not the web UI port. Nothing here can enforce
  that, but the connector help text says so and the failure message names it.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from app.core.airgap import AirgapViolation
from app.services.spl_runner import (
    SPLExecutionError,
    _as_search_command,
    _cap_rows,
    _validate_splunk_url,
    run_spl_query,
)

BASE_URL = "https://splunk.example.com:8089"


def _patched_post(resp: Any) -> Any:
    client = MagicMock()
    if isinstance(resp, Exception):
        client.post = AsyncMock(side_effect=resp)
    else:
        client.post = AsyncMock(return_value=resp)
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=client)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return patch("httpx.AsyncClient", return_value=ctx), client


def _ok_response(rows: list[dict[str, Any]]) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    resp.json = MagicMock(return_value={"results": rows})
    resp.text = ""
    return resp


class TestSearchCommandPrefix:
    def test_bare_expression_is_prefixed(self) -> None:
        """The translator's output starts with ``index=``; Splunk's REST API
        requires an explicit leading ``search``."""
        assert _as_search_command("index=* earliest=-24h | head 500") == "search index=* earliest=-24h | head 500"

    def test_existing_search_command_is_left_alone(self) -> None:
        assert _as_search_command("search index=main") == "search index=main"

    def test_generating_pipe_command_is_left_alone(self) -> None:
        assert _as_search_command("| tstats count where index=main") == "| tstats count where index=main"

    def test_prefix_check_is_case_insensitive(self) -> None:
        assert _as_search_command("SEARCH index=main") == "SEARCH index=main"


class TestRowCap:
    def test_appends_head_when_absent(self) -> None:
        assert _cap_rows("search index=main", 250) == "search index=main | head 250"

    def test_respects_an_existing_head(self) -> None:
        assert _cap_rows("search index=main | head 10", 250) == "search index=main | head 10"

    def test_word_head_in_the_search_body_is_not_a_row_cap(self) -> None:
        """A search for the word "head" must still get a cap — otherwise a
        hunt matching that term pulls the whole index into memory."""
        capped = _cap_rows('search index=main message="head crash"', 100)
        assert capped.endswith("| head 100")


class TestUrlValidation:
    def test_matching_host_is_accepted_and_rebuilt(self) -> None:
        assert _validate_splunk_url(BASE_URL, allowed_url=BASE_URL) == "https://splunk.example.com:8089"

    def test_path_and_query_are_discarded(self) -> None:
        """The returned value is rebuilt from scheme+netloc only, so a caller
        cannot steer the request to another path on the same host."""
        got = _validate_splunk_url(f"{BASE_URL}/evil?x=1", allowed_url=BASE_URL)
        assert got == "https://splunk.example.com:8089"

    def test_different_host_is_refused(self) -> None:
        with pytest.raises(ValueError, match="is not the configured host"):
            _validate_splunk_url("https://attacker.example.com", allowed_url=BASE_URL)

    def test_different_port_is_refused(self) -> None:
        """netloc includes the port, so 8000 (web UI) is not 8089 (management)."""
        with pytest.raises(ValueError, match="is not the configured host"):
            _validate_splunk_url("https://splunk.example.com:8000", allowed_url=BASE_URL)

    @pytest.mark.parametrize("scheme", ["file", "ftp", "gopher"])
    def test_non_http_schemes_are_refused(self, scheme: str) -> None:
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            _validate_splunk_url(f"{scheme}://splunk.example.com", allowed_url=BASE_URL)

    def test_empty_allow_list_is_refused(self) -> None:
        with pytest.raises(ValueError, match="No allowed Splunk host"):
            _validate_splunk_url(BASE_URL, allowed_url="")


class TestRunSplQuery:
    async def test_returns_rows_and_sends_a_oneshot_search(self) -> None:
        patcher, client = _patched_post(_ok_response([{"host": "a"}, {"host": "b"}]))
        with patcher:
            result = await run_spl_query(spl="index=main", base_url=BASE_URL, token="t", max_rows=50)

        assert len(result.rows) == 2
        _, kwargs = client.post.await_args
        assert kwargs["data"]["exec_mode"] == "oneshot"
        assert kwargs["data"]["search"] == "search index=main | head 50"
        assert kwargs["headers"]["Authorization"] == "Bearer t"

    async def test_basic_auth_when_no_token(self) -> None:
        patcher, client = _patched_post(_ok_response([]))
        with patcher:
            await run_spl_query(spl="index=main", base_url=BASE_URL, username="svc", password="pw")

        _, kwargs = client.post.await_args
        assert kwargs["auth"] == ("svc", "pw")
        assert "Authorization" not in kwargs["headers"]

    async def test_non_dict_rows_are_dropped(self) -> None:
        patcher, _ = _patched_post(_ok_response(["not-a-row", {"host": "a"}]))  # type: ignore[list-item]
        with patcher:
            result = await run_spl_query(spl="index=main", base_url=BASE_URL, token="t")

        assert result.rows == [{"host": "a"}]

    async def test_missing_credentials_raise_value_error(self) -> None:
        with pytest.raises(ValueError, match="token or a username/password"):
            await run_spl_query(spl="index=main", base_url=BASE_URL)

    async def test_http_error_is_wrapped_with_the_body(self) -> None:
        """Splunk puts the useful diagnostic in the body; the status alone
        sends an operator looking at the wrong thing."""
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 400
        resp.text = "Unknown search command 'indexx'"
        err = httpx.HTTPStatusError("bad", request=MagicMock(), response=resp)
        resp.raise_for_status = MagicMock(side_effect=err)
        patcher, _ = _patched_post(resp)

        with patcher:
            with pytest.raises(SPLExecutionError, match="Unknown search command"):
                await run_spl_query(spl="index=main", base_url=BASE_URL, token="t")

    async def test_transport_error_is_wrapped(self) -> None:
        patcher, _ = _patched_post(httpx.ConnectError("refused"))
        with patcher:
            with pytest.raises(SPLExecutionError, match="SPL execution failed"):
                await run_spl_query(spl="index=main", base_url=BASE_URL, token="t")

    async def test_airgap_violation_propagates_before_any_request(self) -> None:
        patcher, client = _patched_post(_ok_response([]))
        with (
            patcher,
            patch(
                "app.services.spl_runner.enforce_airgap_for_url",
                side_effect=AirgapViolation("egress blocked"),
            ),
        ):
            with pytest.raises(AirgapViolation):
                await run_spl_query(spl="index=main", base_url=BASE_URL, token="t")

        client.post.assert_not_awaited()

    async def test_ssl_verification_is_forwarded(self) -> None:
        patcher, _ = _patched_post(_ok_response([]))
        with patcher as mock_client:
            await run_spl_query(spl="index=main", base_url=BASE_URL, token="t", verify_ssl=False)

        assert mock_client.call_args.kwargs["verify"] is False
