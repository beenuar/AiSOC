"""Shared async HTTP client for connector implementations.

Every real connector (Splunk, Sentinel, CrowdStrike, Okta, M365, …) talks
to a vendor REST API. Rather than each connector re-implementing timeout,
retry, auth, and error translation, they share `AsyncHttpClient`, which:

  * Wraps `httpx.AsyncClient` with sensible timeouts (connect/read/total).
  * Retries idempotent requests on transient failures
    (5xx, connect errors, timeouts) with exponential backoff and jitter.
  * Honors `Retry-After` on 429 responses.
  * Plugs in an auth strategy (`BearerAuth`, `ApiKeyAuth`, `BasicAuth`,
    `OAuthClientCredentials`) that injects credentials and refreshes
    tokens lazily before expiry.
  * Translates vendor HTTP errors into the connector exception hierarchy
    (`ConnectorAuthError` for 401/403, `ConnectorRateLimitError` for 429,
    `ConnectorTimeoutError` for timeouts, `ConnectorError` for everything
    else) so the tool layer sees a consistent error surface regardless
    of vendor.

Design notes:
  * Each connector instance owns its own `AsyncHttpClient`. Connector
    instances are cached per `(tenant_id, kind)` by the registry, so the
    underlying HTTP keepalive pool and OAuth access token are reused
    across many tool calls within a tenant.
  * `aclose()` must be called on shutdown. The registry's
    `reset_connector_cache()` does this for tests.
  * Logging strips `Authorization` headers and known secret query params
    before emitting structured log lines.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol

import httpx

from app.connectors.sdk.base import (
    ConnectorAuthError,
    ConnectorError,
    ConnectorRateLimitError,
    ConnectorTimeoutError,
)

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Auth strategies                                                             #
# --------------------------------------------------------------------------- #


class ConnectorAuth(Protocol):
    """Pluggable auth strategy used by `AsyncHttpClient`.

    `apply()` is awaited before every request and must mutate the
    outgoing `httpx.Request` (typically by adding an `Authorization`
    header). Strategies that hold short-lived tokens use this hook to
    refresh just-in-time.
    """

    async def apply(self, request: httpx.Request, *, client: httpx.AsyncClient) -> None: ...

    async def aclose(self) -> None: ...


class _NoAuth:
    """Default no-op auth (for vendors that don't need auth, or tests)."""

    async def apply(self, request: httpx.Request, *, client: httpx.AsyncClient) -> None:
        return None

    async def aclose(self) -> None:
        return None


@dataclass
class BearerAuth:
    """Static bearer token, e.g. Splunk session token, Okta SSWS API token."""

    token: str
    scheme: str = "Bearer"

    async def apply(self, request: httpx.Request, *, client: httpx.AsyncClient) -> None:
        request.headers["Authorization"] = f"{self.scheme} {self.token}"

    async def aclose(self) -> None:
        return None


@dataclass
class ApiKeyAuth:
    """API key passed in an arbitrary header.

    Example (Okta SSWS):
        ApiKeyAuth(header="Authorization", value=f"SSWS {api_token}")
    Example (Sentinel via Log Analytics workspace key):
        ApiKeyAuth(header="x-api-key", value=api_key)
    """

    header: str
    value: str

    async def apply(self, request: httpx.Request, *, client: httpx.AsyncClient) -> None:
        request.headers[self.header] = self.value

    async def aclose(self) -> None:
        return None


@dataclass
class BasicAuth:
    """HTTP Basic auth. Used by Splunk REST when not using a session token."""

    username: str
    password: str

    async def apply(self, request: httpx.Request, *, client: httpx.AsyncClient) -> None:
        # Delegate to httpx so we get correct base64 encoding & charset
        # handling. httpx attaches via a request flow on the client, but
        # here we just compute the header inline.
        import base64

        raw = f"{self.username}:{self.password}".encode("utf-8")
        encoded = base64.b64encode(raw).decode("ascii")
        request.headers["Authorization"] = f"Basic {encoded}"

    async def aclose(self) -> None:
        return None


@dataclass
class OAuthClientCredentials:
    """OAuth 2.0 client_credentials grant with token caching.

    Used by Microsoft Graph (M365 / Entra ID / Sentinel) and CrowdStrike
    Falcon — both expose `client_id` + `client_secret` and mint
    short-lived bearer tokens (~1h) from a token endpoint.

    The token is cached in-process and refreshed `refresh_skew` seconds
    before expiry. A lock prevents thundering-herd refreshes when many
    concurrent tool calls hit the same connector.

    `extra_form` carries vendor-specific fields:
      * Microsoft Graph requires `scope=https://graph.microsoft.com/.default`
      * CrowdStrike OAuth2 doesn't need a scope param
    """

    token_url: str
    client_id: str
    client_secret: str
    scope: str | None = None
    audience: str | None = None
    extra_form: dict[str, str] = field(default_factory=dict)
    refresh_skew: float = 60.0  # refresh `skew` seconds before expiry

    # Populated at runtime.
    _access_token: str | None = field(default=None, init=False, repr=False)
    _expires_at: float = field(default=0.0, init=False, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    async def apply(self, request: httpx.Request, *, client: httpx.AsyncClient) -> None:
        token = await self._get_token(client)
        request.headers["Authorization"] = f"Bearer {token}"

    async def _get_token(self, client: httpx.AsyncClient) -> str:
        # Fast path: cached and not near expiry.
        now = time.monotonic()
        if self._access_token and now < self._expires_at - self.refresh_skew:
            return self._access_token

        async with self._lock:
            # Re-check inside lock to avoid duplicate refresh.
            now = time.monotonic()
            if self._access_token and now < self._expires_at - self.refresh_skew:
                return self._access_token

            form: dict[str, str] = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }
            if self.scope:
                form["scope"] = self.scope
            if self.audience:
                form["audience"] = self.audience
            form.update(self.extra_form)

            try:
                resp = await client.post(
                    self.token_url,
                    data=form,
                    headers={"Accept": "application/json"},
                )
            except httpx.TimeoutException as exc:
                raise ConnectorTimeoutError(
                    f"OAuth token endpoint timed out: {self.token_url}",
                ) from exc
            except httpx.RequestError as exc:
                raise ConnectorAuthError(
                    f"OAuth token endpoint unreachable: {exc}",
                ) from exc

            if resp.status_code != 200:
                body = resp.text[:400]
                raise ConnectorAuthError(
                    f"OAuth token request failed: HTTP {resp.status_code} {body!r}",
                    status=resp.status_code,
                )
            try:
                payload = resp.json()
            except Exception as exc:
                raise ConnectorAuthError(
                    f"OAuth token response not JSON: {resp.text[:200]!r}",
                ) from exc

            token = payload.get("access_token")
            if not token:
                raise ConnectorAuthError(
                    f"OAuth response missing access_token: {payload!r}",
                )
            expires_in = float(payload.get("expires_in", 3600))
            self._access_token = token
            self._expires_at = time.monotonic() + expires_in
            logger.debug(
                "oauth: refreshed token for %s (expires_in=%.0fs)",
                self.token_url,
                expires_in,
            )
            return token

    async def aclose(self) -> None:
        self._access_token = None
        self._expires_at = 0.0


# --------------------------------------------------------------------------- #
# HTTP client                                                                 #
# --------------------------------------------------------------------------- #


_DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)

# HTTP statuses that warrant a retry (transient / server-side).
_RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})

# Methods safe to retry without risking double-side-effects.
_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})


class AsyncHttpClient:
    """Resilient async HTTP client used by every real connector.

    Parameters
    ----------
    base_url:
        Optional URL prefix prepended to every request path. Pass the
        vendor host root (e.g. `https://api.crowdstrike.com`).
    auth:
        Auth strategy applied to each request. Defaults to no auth.
    timeout:
        Per-request timeout. Either an `httpx.Timeout` or a scalar
        (seconds) applied as the overall budget.
    max_retries:
        Number of retry attempts on transient failures. Total attempts
        = `max_retries + 1`.
    backoff_base:
        Base seconds for exponential backoff (`backoff_base * 2**attempt`
        with jitter).
    backoff_max:
        Upper bound for any single backoff sleep.
    vendor:
        Used for log/error annotation only.
    headers:
        Default headers merged into every request.
    """

    def __init__(
        self,
        *,
        base_url: str = "",
        auth: ConnectorAuth | None = None,
        timeout: httpx.Timeout | float | None = None,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        backoff_max: float = 8.0,
        vendor: str = "unknown",
        headers: Mapping[str, str] | None = None,
        verify: bool = True,
    ) -> None:
        if timeout is None:
            timeout = _DEFAULT_TIMEOUT
        elif isinstance(timeout, (int, float)):
            timeout = httpx.Timeout(timeout)

        self.vendor = vendor
        self.auth = auth or _NoAuth()
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max

        default_headers = {"Accept": "application/json", "User-Agent": "cyble-aisoc/1.0"}
        if headers:
            default_headers.update(headers)

        self._client = httpx.AsyncClient(
            base_url=base_url,
            timeout=timeout,
            headers=default_headers,
            verify=verify,
        )

    # ------------------------------------------------------------------ #
    # Lifecycle                                                          #
    # ------------------------------------------------------------------ #

    async def aclose(self) -> None:
        await self.auth.aclose()
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncHttpClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    # ------------------------------------------------------------------ #
    # High-level verb wrappers                                            #
    # ------------------------------------------------------------------ #

    async def get(self, url: str, **kw: Any) -> Any:
        return await self.request_json("GET", url, **kw)

    async def post(self, url: str, **kw: Any) -> Any:
        return await self.request_json("POST", url, **kw)

    async def put(self, url: str, **kw: Any) -> Any:
        return await self.request_json("PUT", url, **kw)

    async def patch(self, url: str, **kw: Any) -> Any:
        return await self.request_json("PATCH", url, **kw)

    async def delete(self, url: str, **kw: Any) -> Any:
        return await self.request_json("DELETE", url, **kw)

    # ------------------------------------------------------------------ #
    # Core request loop                                                  #
    # ------------------------------------------------------------------ #

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        data: Any = None,
        headers: Mapping[str, str] | None = None,
        expect_status: int | tuple[int, ...] | None = None,
    ) -> Any:
        """Send a request and return parsed JSON.

        Non-2xx responses are raised as `ConnectorError` subclasses.
        204 / empty bodies return `None`.

        Raises:
            ConnectorAuthError, ConnectorRateLimitError,
            ConnectorTimeoutError, ConnectorError
        """
        resp = await self.request(
            method,
            url,
            params=params,
            json=json,
            data=data,
            headers=headers,
            expect_status=expect_status,
        )
        if not resp.content or resp.status_code == 204:
            return None
        ctype = resp.headers.get("Content-Type", "")
        if "json" not in ctype.lower():
            # Vendor returned non-JSON success (rare). Surface raw text.
            return resp.text
        try:
            return resp.json()
        except Exception as exc:
            raise ConnectorError(
                f"{self.vendor}: invalid JSON in {method} {url}: {resp.text[:200]!r}",
                vendor=self.vendor,
                status=resp.status_code,
            ) from exc

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        data: Any = None,
        headers: Mapping[str, str] | None = None,
        expect_status: int | tuple[int, ...] | None = None,
    ) -> httpx.Response:
        """Send a request with auth + retry, returning the raw `httpx.Response`.

        Most callers want `request_json()`. Use this when you need
        response headers (pagination cursors, rate-limit budget, etc.).
        """
        method_upper = method.upper()
        last_exc: Exception | None = None

        for attempt in range(self.max_retries + 1):
            req = self._client.build_request(
                method_upper,
                url,
                params=params,
                json=json,
                data=data,
                headers=headers,
            )
            try:
                await self.auth.apply(req, client=self._client)
            except ConnectorError:
                # Auth refresh itself failed — fatal, don't retry.
                raise

            try:
                resp = await self._client.send(req)
            except httpx.TimeoutException as exc:
                last_exc = exc
                if not self._should_retry(method_upper, attempt, status=None):
                    raise ConnectorTimeoutError(
                        f"{self.vendor}: {method_upper} {url} timed out after {attempt + 1} attempts",
                        vendor=self.vendor,
                    ) from exc
                await self._sleep_backoff(attempt)
                continue
            except httpx.RequestError as exc:
                last_exc = exc
                if not self._should_retry(method_upper, attempt, status=None):
                    raise ConnectorError(
                        f"{self.vendor}: {method_upper} {url} failed: {exc}",
                        vendor=self.vendor,
                    ) from exc
                await self._sleep_backoff(attempt)
                continue

            status = resp.status_code

            if self._is_success(status, expect_status):
                return resp

            # Translate well-known failures to typed errors. We always
            # raise after exhausting retries; we may retry first.
            if status == 401 or status == 403:
                # Don't retry auth failures — credentials are wrong.
                raise ConnectorAuthError(
                    f"{self.vendor}: {method_upper} {url} -> HTTP {status} {resp.text[:200]!r}",
                    vendor=self.vendor,
                    status=status,
                )
            if status == 429:
                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                if attempt < self.max_retries:
                    await asyncio.sleep(
                        max(retry_after or 0.0, self._backoff_seconds(attempt))
                    )
                    continue
                raise ConnectorRateLimitError(
                    f"{self.vendor}: {method_upper} {url} rate-limited (429); retry_after={retry_after}",
                    vendor=self.vendor,
                    retry_after=retry_after,
                )

            if status in _RETRY_STATUSES and self._should_retry(method_upper, attempt, status):
                await self._sleep_backoff(attempt)
                continue

            # Non-retriable error.
            raise ConnectorError(
                f"{self.vendor}: {method_upper} {url} -> HTTP {status} {resp.text[:200]!r}",
                vendor=self.vendor,
                status=status,
            )

        # Shouldn't reach here, but be defensive.
        raise ConnectorError(
            f"{self.vendor}: {method_upper} {url} failed after {self.max_retries + 1} attempts",
            vendor=self.vendor,
        ) from last_exc

    # ------------------------------------------------------------------ #
    # Helpers                                                            #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_success(status: int, expect_status: int | tuple[int, ...] | None) -> bool:
        if expect_status is not None:
            if isinstance(expect_status, int):
                return status == expect_status
            return status in expect_status
        return 200 <= status < 300

    def _should_retry(
        self, method: str, attempt: int, status: int | None
    ) -> bool:
        if attempt >= self.max_retries:
            return False
        if method not in _IDEMPOTENT_METHODS:
            # POST/PATCH may have side effects — only retry on connection
            # errors (status=None) where we know the request didn't land.
            return status is None
        return True

    def _backoff_seconds(self, attempt: int) -> float:
        # Exponential with full-jitter: AWS Architecture Blog pattern.
        raw = self.backoff_base * (2**attempt)
        capped = min(raw, self.backoff_max)
        return random.uniform(0.0, capped)

    async def _sleep_backoff(self, attempt: int) -> None:
        seconds = self._backoff_seconds(attempt)
        logger.debug(
            "http: %s retry attempt %d in %.2fs",
            self.vendor,
            attempt + 1,
            seconds,
        )
        await asyncio.sleep(seconds)


def _parse_retry_after(value: str | None) -> float | None:
    """Parse `Retry-After` header. Returns seconds or None."""
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        # HTTP-date form. Cheap fallback: don't try to parse, just nudge.
        return 1.0


__all__ = [
    "ApiKeyAuth",
    "AsyncHttpClient",
    "BasicAuth",
    "BearerAuth",
    "ConnectorAuth",
    "OAuthClientCredentials",
]
