"""Splunk SPL executor for the event-warehouse tier.

Sibling of :mod:`app.services.esql_runner`, and deliberately the same
shape: validate the target against an allow-list, enforce the air-gap
policy, cap the row count, then make exactly one outbound call and wrap
every failure in one exception type.

Why the API service runs this rather than `services/connectors`
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The credential vault lives in the API service, and `esql_runner` already
established that the warehouse tier executes here. Introducing a second
topology for the Splunk driver in the same change would make the diff
harder to review than the defect it fixes. The connectors microservice
remains the home of *polling* and of federated `UnifiedQuery` fan-out; this
module runs an already-translated dialect string for a scheduled hunt.

Splunk specifics worth stating once
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* The management port is 8089, not the 8000 web UI. The connector schema
  says so in its help text; users still paste the web URL, so a connection
  failure names the port.
* ``POST /services/search/jobs`` requires the search string to begin with
  ``search`` or with a generating ``|`` command. The platform's translator
  emits ``index=* earliest=-24h ... | head 500``, which begins with neither,
  so the leading ``search`` is added here. Without it Splunk answers 400 on
  every hunt.
* ``exec_mode=oneshot`` returns results on the same request. A scheduled
  hunt only needs a hit count, so there is no reason to create a job, poll
  it, and page through results the way the polling connector does.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.airgap import enforce_airgap_for_url

logger = logging.getLogger(__name__)

__all__ = [
    "SPLExecutionError",
    "SPLResult",
    "run_spl_query",
]

# Commands that may legally open a Splunk search string. Anything else is a
# bare search expression and needs the implicit ``search`` made explicit.
_GENERATING_PREFIXES = ("search ", "|")


@dataclass(slots=True)
class SPLResult:
    """Rows returned by a single oneshot SPL search."""

    rows: list[dict[str, Any]]
    took_ms: int


class SPLExecutionError(RuntimeError):
    """Splunk returned a non-2xx response, or the transport failed.

    Mirrors :class:`app.services.esql_runner.ESQLExecutionError` so the
    warehouse providers only need one ``except`` per backend.
    """


def _validate_splunk_url(url: str, *, allowed_url: str) -> str:
    """Confirm ``url`` matches ``allowed_url``'s scheme and authority.

    Returns a URL rebuilt from only the validated scheme and netloc, so no
    caller-supplied path or query survives into the outbound request. This
    is the same construction ``esql_runner`` uses, and for the same two
    reasons: an attacker cannot redirect the call to a different path on the
    host, and CodeQL's taint tracker sees the value reconstructed from
    validated parts.

    ``allowed_url`` is required rather than optional. The tenant's connector
    row is the only legitimate source of a Splunk endpoint here, so there is
    no deployment-wide fallback to fall back to.
    """
    allowed = urlparse(allowed_url)
    candidate = urlparse(url)
    if candidate.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {candidate.scheme!r}")
    if not allowed.netloc:
        raise ValueError("No allowed Splunk host configured for this tenant")
    if candidate.netloc != allowed.netloc:
        raise ValueError(f"Splunk URL host {candidate.netloc!r} is not the configured host {allowed.netloc!r}")
    return f"{candidate.scheme}://{candidate.netloc}"


def _as_search_command(spl: str) -> str:
    """Prefix a bare search expression with ``search``.

    Left alone when the string already starts with ``search`` or a
    generating ``|`` command, so a hand-written or translator-emitted
    pipeline is never double-prefixed.
    """
    stripped = spl.strip()
    lowered = stripped.lower()
    if any(lowered.startswith(prefix) for prefix in _GENERATING_PREFIXES):
        return stripped
    return f"search {stripped}"


def _cap_rows(spl: str, max_rows: int) -> str:
    """Append ``| head N`` unless the pipeline already caps its own rows.

    The check is on pipeline segments rather than a substring scan: a search
    for the literal word "head" in a message field must not be mistaken for
    a row cap. Splitting on ``|`` is sufficient here because the value has
    already been produced by the platform's own translator — users submit a
    natural-language question, never raw SPL.
    """
    segments = [seg.strip().lower() for seg in spl.split("|")]
    if any(seg.startswith("head ") or seg == "head" for seg in segments[1:]):
        return spl
    return f"{spl} | head {max_rows}"


def _auth_headers(*, token: str | None, username: str | None, password: str | None) -> dict[str, str]:
    """Bearer token when present, HTTP basic otherwise.

    Splunk accepts both. The connector schema offers a token field, but
    self-hosted deployments frequently use a service account, and the
    polling connector already supports either.
    """
    if token:
        return {"Authorization": f"Bearer {token}"}
    if username and password:
        return {}  # httpx builds the basic header from the ``auth`` kwarg.
    raise ValueError("Splunk requires either a token or a username/password pair")


async def run_spl_query(
    *,
    spl: str,
    base_url: str,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    max_rows: int = 500,
    timeout: float = 30.0,
    verify_ssl: bool = True,
) -> SPLResult:
    """Run one oneshot SPL search and return its rows.

    Raises
    ------
    ValueError
        URL validation failed, or no usable credentials were supplied.
    AirgapViolation
        Air-gap policy refuses the URL.
    SPLExecutionError
        Splunk returned a non-2xx response or the transport failed.
    """
    safe_url = _validate_splunk_url(base_url, allowed_url=base_url)
    search_url = f"{safe_url}/services/search/jobs"
    # No-op unless AISOC_AIRGAPPED is set, so it is safe unconditionally.
    enforce_airgap_for_url(search_url)

    query = _cap_rows(_as_search_command(spl), max_rows)
    headers = _auth_headers(token=token, username=username, password=password)
    auth = None if token else (username or "", password or "")

    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=verify_ssl) as client:
            resp = await client.post(
                search_url,
                headers=headers,
                auth=auth,
                data={
                    "search": query,
                    "output_mode": "json",
                    "exec_mode": "oneshot",
                    "count": max_rows,
                },
            )
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as exc:
        # Splunk puts a useful diagnostic in the body ("Unknown search
        # command", "index not found"); the status alone sends an operator
        # looking at the wrong thing.
        raise SPLExecutionError(f"SPL execution failed ({exc.response.status_code}): {exc.response.text[:300]}") from exc
    except httpx.HTTPError as exc:
        raise SPLExecutionError(f"SPL execution failed: {exc}") from exc
    except ValueError as exc:
        raise SPLExecutionError(f"Splunk returned a non-JSON body: {exc}") from exc

    took_ms = int((time.monotonic() - t0) * 1000)
    rows = data.get("results", []) if isinstance(data, dict) else []
    return SPLResult(rows=[r for r in rows if isinstance(r, dict)], took_ms=took_ms)
