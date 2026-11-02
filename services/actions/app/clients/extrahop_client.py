"""ExtraHop RevealX 360 read client: flow and protocol metadata.

Depth plan wave 2, item 8.2. This is the half the connector does not cover.
The connector polls detections on a schedule; this answers a question about
one address or one device at investigation time, so depth 4.5 can pull
network evidence for a vendor-originated alert rather than asserting around
the gap.

Vendor reference, verified 2026-11-01 against
`https://docs.extrahop.com/current/rest-api-guide/`:

* `POST {host}/oauth2/token`, `Authorization: Basic base64(id:secret)`,
  `grant_type=client_credentials`. An API key works against a sensor or
  console and is not compatible with RevealX 360.
* `POST /api/v1/records/search` performs a record query. The documented
  body fields used here are `from`, `until`, `limit`, `types` and `filter`,
  where a filter object is `{field, operand, operator}` and may nest
  through `rules` under `and` / `or` / `not`. The field name `.ipaddr`
  searches the client, server, sender and receiver roles together, which is
  exactly what "everything involving this address" means.
* `POST /api/v1/devices/search` returns devices. The documented filter
  fields include `ipaddr`, `name`, `macaddr`, `role`, `software` and
  `is_critical`.

One limit, stated rather than discovered
-----------------------------------------
Record search needs somewhere for records to live. The vendor's own text:
in RevealX 360 the query is only fully supported on systems with a
cloud-based recordstore and Premium Investigation. A deployment without one
answers an error, and this client reports that as a *refusal to answer*
rather than as an empty result, because "no flows involving this address"
and "this tenant does not store records" are different facts and only one
of them is evidence.

Read-only
---------
Nothing here writes. The record and device search operations are POSTs
because the vendor models a query as a POST body, not because anything is
created.
"""

from __future__ import annotations

import base64
import time
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

#: Bounded hard. A record query can match millions of rows, and this result
#: reaches a model's context window.
MAX_RECORDS = 100
MAX_DEVICES = 50

#: Projected, never forwarded. A record carries every field its format
#: defines; handing all of it to a model is an unbounded token cost for a
#: bounded amount of signal. These are the fields an analyst reads to answer
#: "what did this address talk to, over what, and how much".
_RECORD_FIELDS = (
    "timestamp",
    "clientAddr",
    "serverAddr",
    "clientPort",
    "serverPort",
    "proto",
    "ipproto",
    "bytes",
    "reqBytes",
    "rspBytes",
    "method",
    "uri",
    "host",
    "statusCode",
    "error",
)


class ExtraHopReadError(RuntimeError):
    """The read could not be performed. Distinct from an empty result."""


class ExtraHopClient:
    """Read-only RevealX 360 client for flow and protocol metadata."""

    def __init__(
        self,
        api_host: str,
        client_id: str,
        client_secret: str,
        *,
        transport: Any | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._host = (api_host or "").strip().rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._transport = transport
        self._timeout = timeout
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    async def _access_token(self) -> str:
        if self._token and time.time() < self._token_expires_at - 60:
            return self._token
        basic = base64.b64encode(f"{self._client_id}:{self._client_secret}".encode()).decode()
        async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
            try:
                response = await client.post(
                    f"{self._host}/oauth2/token",
                    headers={
                        "Authorization": f"Basic {basic}",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    content="grant_type=client_credentials",
                )
                response.raise_for_status()
            except httpx.HTTPError as exc:
                raise ExtraHopReadError(f"RevealX 360 token request failed: {exc}") from exc
            body = response.json()
        token = str(body.get("access_token") or "")
        if not token:
            # A 200 carrying no token would otherwise produce `Bearer None`
            # and the resulting 401 reads to an operator as a bad secret.
            raise ExtraHopReadError("RevealX 360 returned no access_token")
        self._token = token
        self._token_expires_at = time.time() + float(body.get("expires_in") or 3600)
        return token

    async def _post(self, path: str, body: dict[str, Any]) -> Any:
        token = await self._access_token()
        async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
            try:
                response = await client.post(
                    f"{self._host}{path}",
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                    json=body,
                )
            except httpx.HTTPError as exc:
                raise ExtraHopReadError(f"RevealX 360 {path} failed: {exc}") from exc

        if response.status_code == 402 or response.status_code == 404:
            # The documented shape of "this deployment has no recordstore".
            # Reported as a refusal rather than as no results, because an
            # investigation concluding an address was quiet when nothing was
            # ever searched is worse than one that says it could not check.
            raise ExtraHopReadError(
                f"RevealX 360 answered {response.status_code} for {path}. Record search needs a "
                "cloud-based recordstore with Premium Investigation; without one no flow evidence "
                "exists to read, which is not the same as no flows."
            )
        if response.status_code >= 400:
            raise ExtraHopReadError(f"RevealX 360 answered {response.status_code} for {path}")
        return response.json()

    async def search_flows(
        self,
        address: str,
        *,
        hours: int = 1,
        limit: int = MAX_RECORDS,
        record_types: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Flow and protocol records involving one address.

        `.ipaddr` searches the client, server, sender and receiver roles
        together, so a single filter answers "everything involving this
        address" rather than only the half where it was the client.
        """
        body: dict[str, Any] = {
            # Negative milliseconds relative to the request, the shape the
            # vendor documents for a relative window.
            "from": -int(max(1, hours) * 3_600_000),
            "until": 0,
            "limit": max(1, min(int(limit), MAX_RECORDS)),
            "filter": {"field": ".ipaddr", "operand": address, "operator": "="},
        }
        if record_types:
            body["types"] = record_types[:10]

        payload = await self._post("/api/v1/records/search", body)
        return [_project_record(row) for row in _records_of(payload)][:MAX_RECORDS]

    async def search_devices(self, address: str, *, limit: int = MAX_DEVICES) -> list[dict[str, Any]]:
        """Devices the appliance has discovered at one address."""
        body = {
            "active_from": -86_400_000,
            "active_until": 0,
            "limit": max(1, min(int(limit), MAX_DEVICES)),
            "filter": {"field": "ipaddr", "operand": address, "operator": "="},
        }
        payload = await self._post("/api/v1/devices/search", body)
        rows = payload if isinstance(payload, list) else []
        return [_project_device(row) for row in rows if isinstance(row, dict)][:MAX_DEVICES]


def _records_of(payload: Any) -> list[dict[str, Any]]:
    """The record rows, from either documented response envelope.

    A record search returns `{"records": [...], "total": N}`; some
    operations return a bare array. Both are read rather than one being
    assumed, because assuming the wrong one yields zero rows and reads as a
    quiet network.
    """
    if isinstance(payload, dict):
        rows = payload.get("records")
        if isinstance(rows, list):
            return [r for r in rows if isinstance(r, dict)]
        return []
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    return []


def _project_record(row: dict[str, Any]) -> dict[str, Any]:
    """The fields an analyst reads, and nothing else."""
    nested = row.get("_source")
    source: dict[str, Any] = nested if isinstance(nested, dict) else row
    out: dict[str, Any] = {field: source[field] for field in _RECORD_FIELDS if source.get(field) is not None}
    if row.get("_type"):
        out["record_type"] = row["_type"]
    return out


def _project_device(row: dict[str, Any]) -> dict[str, Any]:
    return {
        key: row.get(key)
        for key in (
            "id",
            "display_name",
            "ipaddr4",
            "ipaddr6",
            "macaddr",
            "role",
            "analysis",
            "critical",
            "vendor",
            "software",
            "cloud_instance_name",
        )
        if row.get(key) is not None
    }
