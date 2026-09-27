"""Normalize replay input through the connectors service, not through a copy of it.

Gap-closure Phase 1.2.

Why HTTP
--------
``services/connectors`` and ``services/agents`` both package their code as
top-level ``app``. One Python process can therefore hold one of them, and no
amount of path juggling changes that. So the choice was between a second copy
of every vendor's field mapping living here, and one round trip to the service
that owns the mapping.

The copy loses. Replay exists to measure the product on a customer's own data;
a mapping that drifted from the connectors service would grade the agent on an
input shape the product never produces, and it would keep reporting confident
numbers while doing so. This is the same reasoning that put organisation
memory and SIEM writeback behind HTTP calls to the API service rather than
behind a second copy of their SQL.

Batched on purpose
------------------
:func:`fetch_normalized` sends the whole window in one request and returns a
lookup. Two hundred findings are two hundred round trips otherwise, on a path
an operator runs interactively.

The lookup is keyed by a hash of the canonical row rather than by position,
because the runner walks findings in split order and the request is sent in
input order, and a positional mapping that silently slipped by one would
attach every verdict to the wrong analyst label. A row the service did not
return is a :class:`NormalizerUnavailable`, never a substituted mapping.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from typing import Any

import httpx
import structlog

from app.replay.normalize import NormalizerUnavailable

logger = structlog.get_logger()

__all__ = ["PrenormalizedRows", "fetch_normalized", "row_key"]

_SERVICE_URL = os.getenv("CONNECTORS_SERVICE_URL", "http://connectors:8003")
_TIMEOUT_S = float(os.getenv("AISOC_REPLAY_NORMALIZE_TIMEOUT_S", "60"))


def row_key(row: Mapping[str, Any]) -> str:
    """Stable identity for a vendor row, independent of dict ordering."""
    blob = json.dumps(row, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class PrenormalizedRows:
    """A :class:`FindingNormalizer` backed by an already-fetched batch.

    Implements the same one-method port a connector does, so the runner does
    not know or care whether it is holding a connector or a lookup.
    """

    def __init__(self, mapping: Mapping[str, Mapping[str, Any]], *, connector_id: str) -> None:
        self._mapping = dict(mapping)
        self.connector_id = connector_id

    def __len__(self) -> int:
        return len(self._mapping)

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        envelope = self._mapping.get(row_key(raw))
        if envelope is None:
            raise NormalizerUnavailable(
                f"the connectors service returned no normalized envelope for this {self.connector_id} row; "
                f"replay will not substitute its own mapping"
            )
        return dict(envelope)


async def fetch_normalized(
    connector_id: str,
    rows: Sequence[Mapping[str, Any]],
    *,
    tenant_id: str,
    service_url: str | None = None,
    service_token: str | None = None,
) -> PrenormalizedRows:
    """Map every row through the connectors service and return a lookup.

    Raises :class:`NormalizerUnavailable` on any failure. Replay has no
    degraded mode here: a run that could not normalize its input has nothing
    to measure, and continuing with partial coverage would publish a number
    over whichever rows happened to succeed.
    """
    if not rows:
        return PrenormalizedRows({}, connector_id=connector_id)

    base = (service_url or _SERVICE_URL).rstrip("/")
    token = service_token if service_token is not None else os.getenv("AISOC_SERVICE_TOKEN", "").strip()
    if not token:
        raise NormalizerUnavailable(
            "AISOC_SERVICE_TOKEN is unset, so the connectors service will refuse the service path "
            "and replay cannot reach the production normalizer"
        )

    url = f"{base}/connectors/{connector_id}/normalize"
    payload = {"rows": [dict(row) for row in rows]}
    # A service token must declare the tenant it acts for; the connectors
    # service refuses one that does not. The tenant comes from the caller's
    # credential-derived scope, never from a field in the request body.
    headers = {"Authorization": f"Bearer {token}", "X-AiSOC-Tenant-ID": tenant_id}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            response = await client.post(url, json=payload, headers=headers)
    except httpx.HTTPError as exc:
        raise NormalizerUnavailable(f"connectors service unreachable at {base}: {exc}") from exc

    if response.status_code >= 400:
        raise NormalizerUnavailable(
            f"connectors service refused the normalize request for '{connector_id}' with HTTP {response.status_code}: {response.text[:300]}"
        )

    try:
        body = response.json()
    except ValueError as exc:
        raise NormalizerUnavailable("connectors service returned a non-JSON normalize response") from exc

    returned = body.get("rows") if isinstance(body, dict) else None
    if not isinstance(returned, list) or len(returned) != len(rows):
        raise NormalizerUnavailable(
            f"connectors service returned {len(returned) if isinstance(returned, list) else 'no'} envelopes "
            f"for {len(rows)} rows; a partial batch would silently drop findings from the evaluation"
        )

    mapping = {row_key(row): envelope for row, envelope in zip(rows, returned, strict=True)}
    logger.info("replay.normalized", connector_id=connector_id, rows=len(rows), distinct=len(mapping))
    return PrenormalizedRows(mapping, connector_id=connector_id)
