"""Background-friendly ES|QL executor — Track 3, T3.4 (`/hunt` NL surface).

This module exposes a single async helper, :func:`run_esql_query`, that
both the request-scoped ``/nl-query/execute`` endpoint and the
out-of-band saved-hunt scheduler can call to run an ES|QL query against
the configured Elasticsearch backend.

Why a shared helper instead of inlining the call?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before T3.4 the ES|QL HTTP call lived inside
``services/api/app/api/v1/endpoints/nl_query.py`` and depended on a
``QueryResult`` Pydantic model + FastAPI request scope. The saved-hunt
scheduler (``app/workers/hunt_scheduler.py``) is an asyncio worker
launched from the FastAPI ``lifespan`` hook — it has no request scope
and is *deliberately* free of FastAPI imports so it can be lifted into a
separate sidecar later. The scheduler therefore could not reuse the
endpoint's executor directly, and shipped a stub that always returned
zero hits (see the historical `_execute_hunt` TODO in
``hunt_scheduler.py``).

This module is the lift: a tiny dataclass + plain async function that
takes the URL, API key, and ES|QL string and returns
``(columns, rows, took_ms)``. The endpoint wraps the result back into
its Pydantic ``QueryResult`` shape; the scheduler reads ``len(rows)``
and feeds that into its case-open callback.

Security invariants
~~~~~~~~~~~~~~~~~~~

* **SSRF guard.** :func:`run_esql_query` calls
  :func:`_validate_es_url` to enforce that the target host matches the
  configured ``ES_URL`` / ``ELASTICSEARCH_URL`` / ``OPENSEARCH_URL``
  setting. A mismatched host raises :class:`ValueError` *before* any
  outbound request leaves the process.
* **Air-gap policy.** Each call routes the final URL through
  :func:`enforce_airgap_for_url` so an operator who flipped
  ``AISOC_AIRGAPPED=true`` can't accidentally leak a query to a
  public host.
* **No new dependencies.** Uses ``httpx`` (already a hard dep of the
  API service) for the outbound call.

Test coverage
~~~~~~~~~~~~~

See ``tests/test_esql_runner.py`` for the dedicated unit tests, and
``tests/test_saved_hunts_endpoint.py`` for the scheduler integration
test that wires ``_execute_hunt`` through this helper.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.airgap import AirgapViolation, enforce_airgap_for_url
from app.core.config import settings

__all__ = [
    "ESQLExecutionError",
    "ESQLResult",
    "ESQLNotConfigured",
    "resolve_es_credentials",
    "run_esql_query",
]


@dataclass(slots=True)
class ESQLResult:
    """Plain-data result of a single ES|QL query run.

    The endpoint wraps this into its Pydantic ``QueryResult`` shape; the
    scheduler reads ``len(rows)`` for its hit count. ``took_ms`` is the
    wall-clock time we observed locally (including network) — not the
    Elasticsearch-reported ``took`` field, because the ES|QL endpoint
    does not always return it.
    """

    columns: list[str]
    rows: list[list[Any]]
    took_ms: int


class ESQLExecutionError(RuntimeError):
    """Raised when an ES|QL execution attempt fails after validation passed.

    Distinct from :class:`ValueError` (raised for SSRF / URL validation)
    and :class:`AirgapViolation` (raised for air-gap policy) so callers
    can distinguish "Elasticsearch said 500" from "we refused to make
    the call". The wrapping endpoint typically converts each into a
    different HTTP status code for the analyst-facing UI.
    """


class ESQLNotConfigured(RuntimeError):
    """Raised when no ES URL or API key is configured.

    Callers that want a "skip, don't fail" semantic (the saved-hunt
    scheduler in particular) catch this explicitly and short-circuit
    with zero hits. Endpoints catch it and surface a 200 with a
    structured ``execution_error`` instead of a hard 500.
    """


# ---------------------------------------------------------------------------
# URL validation + credential resolution
# ---------------------------------------------------------------------------


def _validate_es_url(url: str) -> str:
    """Validate ``url`` against the configured Elasticsearch/OpenSearch host.

    Raises :class:`ValueError` if the host or scheme does not match,
    preventing SSRF. Returns a *reconstructed* URL built solely from the
    validated scheme and netloc — this discards any user-supplied path
    or query so that CodeQL's taint tracking does not flag the returned
    value, and so an attacker can't point a saved hunt at an attacker-
    controlled path under the same host.
    """
    allowed_raw = (
        getattr(settings, "ES_URL", None)
        or getattr(settings, "ELASTICSEARCH_URL", None)
        or getattr(settings, "OPENSEARCH_URL", "http://localhost:9200")
    )
    allowed = urlparse(allowed_raw)
    candidate = urlparse(url)
    if candidate.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {candidate.scheme!r}")
    if candidate.netloc != allowed.netloc:
        raise ValueError(
            f"ES URL host {candidate.netloc!r} is not the configured host {allowed.netloc!r}"
        )
    return f"{candidate.scheme}://{candidate.netloc}"


def resolve_es_credentials(
    *,
    es_url: str | None = None,
    es_api_key: str | None = None,
) -> tuple[str, str]:
    """Resolve ES URL + API key from explicit overrides or settings.

    Used by both the endpoint (which lets a caller override per-request)
    and the scheduler (which always uses the configured settings).
    Raises :class:`ESQLNotConfigured` when neither side supplies both
    pieces — letting the caller pick its own "skip" vs "error" policy.
    """
    resolved_url = (
        es_url
        or getattr(settings, "ES_URL", None)
        or getattr(settings, "ELASTICSEARCH_URL", None)
    )
    resolved_key = es_api_key or getattr(settings, "ES_API_KEY", None)
    if not resolved_url or not resolved_key:
        raise ESQLNotConfigured(
            "ES_URL or ES_API_KEY not configured. Set them in environment "
            "variables or pass them explicitly."
        )
    return resolved_url, resolved_key


# ---------------------------------------------------------------------------
# The runner
# ---------------------------------------------------------------------------


async def run_esql_query(
    *,
    esql: str,
    es_url: str,
    es_api_key: str,
    max_rows: int = 500,
    timeout: float = 20.0,
) -> ESQLResult:
    """Run a single ES|QL query and return ``(columns, rows, took_ms)``.

    All three guards run *before* the outbound POST so a misconfigured
    or hostile input never reaches the network:

    1. :func:`_validate_es_url` confirms the host matches the configured
       Elasticsearch host (SSRF guard).
    2. :func:`enforce_airgap_for_url` confirms the host is permitted by
       the air-gap policy (offline / dev guard).
    3. A ``LIMIT`` clause is appended if the caller didn't supply one,
       so a misbehaving translator can't accidentally pull millions of
       rows into memory.

    Raises
    ------
    ValueError
        URL validation failed (mismatched host or unsupported scheme).
    AirgapViolation
        Air-gap policy refuses the URL.
    ESQLExecutionError
        Elasticsearch returned a non-2xx response or the transport
        failed. Wraps the underlying httpx error so callers only need
        to catch one exception type.
    """
    try:
        safe_url = _validate_es_url(es_url)
    except ValueError:
        # Re-raise unchanged — callers distinguish URL errors from
        # transport errors and we don't want to lose that signal.
        raise

    es_query_url = f"{safe_url.rstrip('/')}/_query"
    # enforce_airgap_for_url is a no-op when AISOC_AIRGAPPED is false,
    # so this is safe to call unconditionally.
    enforce_airgap_for_url(es_query_url)

    # Append a LIMIT if the translator didn't already supply one. We
    # match case-insensitively because the deterministic translator
    # emits "LIMIT" but a future LLM enhancement might lower-case it.
    query = esql if "| LIMIT" in esql.upper() else f"{esql}\n| LIMIT {max_rows}"

    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                es_query_url,
                headers={
                    "Authorization": f"ApiKey {es_api_key}",
                    "Content-Type": "application/json",
                },
                json={"query": query},
            )
            resp.raise_for_status()
            data = resp.json()
    except AirgapViolation:
        # Let the air-gap signal propagate unchanged so the endpoint
        # can return its dedicated 503 ``airgap_violation`` body.
        raise
    except httpx.HTTPError as exc:
        # Wrap any transport or HTTP-status error into our own type so
        # callers don't need an httpx import in their except clauses.
        raise ESQLExecutionError(f"ES|QL execution failed: {exc}") from exc

    took_ms = int((time.monotonic() - t0) * 1000)
    columns = [col["name"] for col in data.get("columns", [])]
    rows = data.get("values", [])
    return ESQLResult(columns=columns, rows=rows, took_ms=took_ms)
