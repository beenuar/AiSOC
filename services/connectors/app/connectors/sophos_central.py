"""Sophos Central alerts, read through the SIEM Integration API.

Vendor reference, from Sophos's developer portal
(`https://developer.sophos.com/getting-started-tenant`,
`https://developer.sophos.com/getting-started` and
`https://developer.sophos.com/reference/siem-v1/alerts/get-alerts/`):

* **Authentication.** OAuth2 client credentials against Sophos ID, never
  against the API host::

      POST https://id.sophos.com/api/v2/oauth2/token
      Content-Type: application/x-www-form-urlencoded
      grant_type=client_credentials&client_id=…&client_secret=…&scope=token

  The response carries `access_token` and `expires_in` (3600).

* **Who the credential belongs to.** `GET https://api.central.sophos.com/whoami/v1`
  answers `id`, `idType` and `apiHosts`. A credential created inside a tenant
  has `idType: tenant`, and `apiHosts.dataRegion` is the host every tenant
  API lives on — there is no single regional endpoint to configure. A
  credential created at partner or organization level has `idType: partner`
  or `organization` and no data region of its own: it can see many tenants,
  so the tenant to read has to be named, and its host is the `apiHost` of
  `GET /{idType}/v1/tenants/{id}`, sent with `X-Partner-ID` or
  `X-Organization-ID`. Sophos's own SIEM client resolves both shapes the same
  way.

* **Alerts.** `GET {dataRegion}/siem/v1/alerts` with `X-Tenant-ID`. Query
  parameters are `from_date` (a Unix timestamp that "must be within last 24
  hours" and is "ignored if cursor is set"), `limit` (200 to 1000) and
  `cursor`. The response is `{items, has_more, next_cursor}`.

Reading the window to the end
-----------------------------
`next_cursor` is present on every page, the last one included, so it cannot
say whether the collection has ended; `has_more` does. The read goes through
`read_token_pages` with `more_field="has_more"` for that reason, and sends
the cursor without `from_date` on each following page, as Sophos's own client
does.

The 24-hour ceiling binds in practice. The scheduler's outage backfill asks
for up to exactly 24 hours, which lands just past the vendor's limit by the
time the request arrives, and the API refuses the whole request. So the
window is shortened to fit and the shortening is logged, rather than turning
a recovery poll into a failed one.

The severity ladder, and why it stops at `high`
-----------------------------------------------
The alert schema's `severity` "must be one of: LOW, MEDIUM, HIGH". Those map
to `low`, `medium` and `high`, and nothing maps to `critical`, because
asserting a tier the vendor did not set is the mirror of collapsing a real
`critical` into `high`. A value outside the published three carries no
`severity` key at all rather than a guessed one; the ingest class for this
connector is 2001 Security Finding, so the alert is still promoted.

Read-only
---------
Nothing here acknowledges, clears or otherwise changes an alert in Sophos
Central.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import httpx
import structlog

from app.connectors._paging import read_token_pages
from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_TOKEN_URL = "https://id.sophos.com/api/v2/oauth2/token"
_GLOBAL_HOST = "https://api.central.sophos.com"
_ALERTS_PATH = "/siem/v1/alerts"

#: The documented maximum. The minimum is 200, so a smaller page is not an
#: option either.
_PAGE_SIZE = 1000

#: `from_date` must be within the last 24 hours. Five minutes short of it,
#: so a request that spends a while in flight is not refused at the edge.
_MAX_LOOKBACK_SECONDS = 24 * 60 * 60 - 5 * 60

#: The vendor's published ladder. Three entries because it publishes three.
_SEVERITIES = {"low": "low", "medium": "medium", "high": "high"}

#: `source` carries this when no user is attached to the alert.
_NO_USER = "n/a"


class SophosCentralError(RuntimeError):
    """Sophos Central refused a step, with a message written for the operator."""


class SophosCentralConnector(BaseConnector):
    connector_id = "sophos_central"
    connector_name = "Sophos Central"
    connector_category = "edr"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Sophos Central alerts — endpoint and server threats, exploit and ransomware "
                "protection, intrusion prevention — via the SIEM Integration API, with the "
                "data region discovered from the credential. Read-only."
            ),
            docs_url="/docs/connectors/sophos-central",
            fields=[
                Field("client_id", "string", "Client ID"),
                Field(
                    "client_secret",
                    "secret",
                    "Client secret",
                    help_text="Created in Sophos Central under Global Settings → API Credentials Management.",
                ),
                Field(
                    "tenant_id",
                    "string",
                    "Tenant ID",
                    required=False,
                    placeholder="57ca9a6b-885f-4e36-95ec-290548c26059",
                    help_text=(
                        "Leave blank for a credential created inside the tenant. Required for a "
                        "partner or organization credential, which can see many tenants: the ID "
                        "of the tenant whose alerts this connector reads."
                    ),
                ),
            ],
            capabilities=cls.capabilities(),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS,)

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        tenant_id: str = "",
        transport: Any | None = None,
    ) -> None:
        tenant = (tenant_id or "").strip()
        if tenant:
            # It is interpolated into a request path, so it is held to the
            # shape Sophos issues rather than passed through.
            try:
                uuid.UUID(tenant)
            except ValueError:
                raise ValueError(
                    f"tenant_id {tenant!r} is not a Sophos Central tenant ID, which is a UUID such as 57ca9a6b-885f-4e36-95ec-290548c26059"
                ) from None
        self._client_id = (client_id or "").strip()
        self._client_secret = client_secret
        self._configured_tenant = tenant
        self._transport = transport
        self._token: str | None = None
        self._token_expires_at = 0.0
        #: (tenant id, data region host), resolved once per instance.
        self._tenant: tuple[str, str] | None = None

    # ------------------------------------------------------------------ auth

    async def _access_token(self, client: httpx.AsyncClient) -> str:
        # A minute of headroom: a token that expires between the check and
        # the call answers 401, which reads as a bad credential.
        if self._token and time.time() < self._token_expires_at - 60:
            return self._token
        response = await client.post(
            _TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": "token",
            },
        )
        if response.status_code != 200:
            raise SophosCentralError(
                f"Sophos ID refused the client credentials (HTTP {response.status_code}). Check the client ID "
                "and secret, and that the API credential has not been deleted or expired."
            )
        try:
            body = response.json()
        except ValueError:
            body = None
        token = body.get("access_token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            raise SophosCentralError("Sophos ID answered the token request without an access token")
        self._token = token
        self._token_expires_at = time.time() + float(body.get("expires_in") or 3600)
        return self._token

    async def _get(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """GET with the bearer token, renewed once if the API says it lapsed."""
        token = await self._access_token(client)
        response = await client.get(url, headers={**headers, "Authorization": f"Bearer {token}"}, params=params)
        if response.status_code == 401:
            self._token = None
            try:
                token = await self._access_token(client)
            except SophosCentralError:
                # The 401 stands and the caller reports it. Raising here
                # instead would escape the page reader part-way through a
                # window and discard the pages it had already read.
                return response
            response = await client.get(url, headers={**headers, "Authorization": f"Bearer {token}"}, params=params)
        return response

    async def _resolve_tenant(self, client: httpx.AsyncClient) -> tuple[str, str]:
        """The tenant to read and the data region host it lives on."""
        if self._tenant is not None:
            return self._tenant

        whoami = await self._get(client, f"{_GLOBAL_HOST}/whoami/v1", {"Accept": "application/json"})
        if whoami.status_code != 200:
            raise SophosCentralError(f"Sophos Central answered HTTP {whoami.status_code} to whoami: {whoami.text[:300]}")
        body = _object(whoami.json())
        id_type = str(body.get("idType") or "")
        own_id = str(body.get("id") or "")
        hosts = _object(body.get("apiHosts"))

        if id_type == "tenant":
            configured = self._configured_tenant
            if configured and configured.lower() != own_id.lower():
                raise SophosCentralError(
                    f"This credential belongs to tenant {own_id}, not to the configured tenant {configured}. "
                    "Clear the Tenant ID field, or use a credential created for that tenant."
                )
            tenant_id, host = own_id, hosts.get("dataRegion")
        elif id_type in ("partner", "organization"):
            if not self._configured_tenant:
                raise SophosCentralError(
                    f"This is {'an' if id_type == 'organization' else 'a'} {id_type} credential, which can see many "
                    "tenants. Set Tenant ID to the tenant whose alerts this connector should read."
                )
            scope_header = "X-Partner-ID" if id_type == "partner" else "X-Organization-ID"
            tenant = await self._get(
                client,
                f"{_GLOBAL_HOST}/{id_type}/v1/tenants/{self._configured_tenant}",
                {"Accept": "application/json", scope_header: own_id},
            )
            if tenant.status_code != 200:
                raise SophosCentralError(
                    f"Sophos Central answered HTTP {tenant.status_code} when looking up tenant "
                    f"{self._configured_tenant} for this {id_type} credential: {tenant.text[:300]}"
                )
            tenant_id, host = self._configured_tenant, _object(tenant.json()).get("apiHost")
        else:
            raise SophosCentralError(f"Sophos Central whoami returned an unrecognised idType {id_type!r}")

        if not tenant_id:
            raise SophosCentralError("Sophos Central whoami returned no tenant ID")
        self._tenant = (tenant_id, _vendor_host(host))
        return self._tenant

    # --------------------------------------------------------------- runtime

    async def _alerts_page(self, client: httpx.AsyncClient, tenant: tuple[str, str], params: dict[str, Any]) -> httpx.Response:
        tenant_id, host = tenant
        return await self._get(
            client,
            f"{host}{_ALERTS_PATH}",
            {"Accept": "application/json", "X-Tenant-ID": tenant_id},
            params={**params, "limit": _PAGE_SIZE},
        )

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=30.0, transport=self._transport) as client:
                tenant = await self._resolve_tenant(client)
                response = await self._alerts_page(client, tenant, {"from_date": int(time.time()) - 60})
            if response.status_code != 200:
                return {"success": False, "connector": self.connector_id, "error": _refusal(response)}
            return {
                "success": True,
                "connector": self.connector_id,
                "tenant_id": tenant[0],
                "data_region": tenant[1],
            }
        except (httpx.HTTPError, SophosCentralError, ValueError) as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        lookback = max(1, int(since_seconds))
        if lookback > _MAX_LOOKBACK_SECONDS:
            logger.warning(
                "sophos_central.window_shortened",
                requested_seconds=lookback,
                read_seconds=_MAX_LOOKBACK_SECONDS,
                detail="the SIEM API refuses a from_date older than 24 hours; alerts before the shortened window are not read",
            )
            lookback = _MAX_LOOKBACK_SECONDS
        from_date = int(time.time()) - lookback

        async with httpx.AsyncClient(timeout=60.0, transport=self._transport) as client:
            tenant = await self._resolve_tenant(client)

            async def page(cursor: str | None) -> httpx.Response:
                params: dict[str, Any] = {"cursor": cursor} if cursor else {"from_date": from_date}
                response = await self._alerts_page(client, tenant, params)
                # Raised, not returned: on the opening page an empty list
                # would read as a quiet estate, and the scheduler records an
                # exception as the failed poll it is. A later page failing is
                # left to the reader, which keeps the pages already read.
                if cursor is None and response.status_code != 200:
                    raise SophosCentralError(_refusal(response))
                return response

            alerts = await read_token_pages(
                request=page,
                items_field="items",
                token_field="next_cursor",
                more_field="has_more",
                feed="sophos_central.alerts",
            )
        return [self.normalize(alert) for alert in alerts]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Canonical envelope, with the vendor record under `raw_event`."""
        data = _object(raw.get("data"))
        source_info = _object(data.get("source_info"))
        ips_threat = _object(data.get("ips_threat"))

        description = _text(raw.get("description"))
        threat = _text(raw.get("threat"))
        alert_type = _text(raw.get("type"))
        user = _text(raw.get("source"))

        event: dict[str, Any] = {
            "source": self.connector_id,
            "external_id": _text(raw.get("id")),
            "title": description or threat or alert_type or "Sophos Central alert",
            "description": description,
            "event_type": alert_type,
            "threat": threat,
            "created_at": _text(raw.get("created_at")) or _text(raw.get("when")),
            # `location` is the name of the device the alert was raised on.
            "hostname": _text(raw.get("location")),
            "actor": None if user and user.lower() == _NO_USER else user,
            "src_ip": _text(source_info.get("ip")),
            # Only an intrusion-prevention alert names a remote peer.
            "dst_ip": _text(ips_threat.get("remote_ip")),
            "endpoint_id": _text(data.get("endpoint_id")),
            "endpoint_type": _text(data.get("endpoint_type")),
            "raw_event": raw,
        }
        severity = _SEVERITIES.get(_text(raw.get("severity")).lower())
        if severity is not None:
            event["severity"] = severity
        return {key: value for key, value in event.items() if value not in (None, "")}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _object(value: Any) -> dict[str, Any]:
    """``value`` when it is a JSON object, otherwise an empty one."""
    return value if isinstance(value, dict) else {}


def _vendor_host(value: Any) -> str:
    """The data region as `https://<host>`, refused unless it is Sophos's.

    The host comes from a response, not from configuration, so the egress
    guard that vets configured URLs never sees it, and the bearer token is
    sent to whatever it names. Holding it to https under sophos.com keeps the
    credential with the vendor that issued it.
    """
    try:
        url = httpx.URL(value) if isinstance(value, str) else None
    except httpx.InvalidURL:
        url = None
    host = url.host.lower() if url is not None else ""
    if url is None or url.scheme != "https" or not host.endswith(".sophos.com"):
        raise SophosCentralError(
            f"Sophos Central named a data region host outside sophos.com ({value!r}); refusing to send the credential there"
        )
    # Rebuilt from the parts that were checked, so a path, query or userinfo
    # riding along in the answer does not reach the request.
    return f"https://{host}" if url.port is None else f"https://{host}:{url.port}"


def _refusal(response: httpx.Response) -> str:
    message = f"Sophos Central answered HTTP {response.status_code} to GET {_ALERTS_PATH}: {response.text[:300]}"
    if response.status_code == 403:
        message += " The API credential's role does not allow reading SIEM alerts for this tenant."
    return message
