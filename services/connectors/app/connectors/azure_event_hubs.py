"""
Azure Event Hubs carrying Entra sign-in logs, Entra audit logs and the
Activity log.

Why this exists beside ``azure_entra.py`` and ``azure_activity.py``
-------------------------------------------------------------------

Both of those poll Microsoft's own APIs — Graph ``auditLogs/signIns`` and the
ARM Activity Log — and both are throttled per tenant rather than per
connector. Graph's sign-in endpoint in particular is paged at a size
Microsoft chooses and rate-limited hard enough that a tenant with tens of
thousands of sign-ins an hour cannot be read continuously through it. That
is why Microsoft's own guidance for a SIEM is a **diagnostic setting**
streaming to an Event Hub: one configuration exports sign-in logs, audit
logs, provisioning logs and the subscription Activity log, at the rate the
tenant actually produces them, with no per-reader throttle.

Both older connectors stay. A small tenant with no Event Hubs namespace
should not have to build one.

How this reads an Event Hub without an AMQP client
--------------------------------------------------

Event Hubs' native consumer protocol is AMQP 1.0, and neither an AMQP
library nor the Azure SDK is a declared dependency of this service. Adding
one would mean a new pin across every declaration site for a service that
otherwise needs only ``httpx``.

So this reads the hub's **Capture** output instead: Capture is an Event Hubs
feature that writes every event the hub receives to a storage account, and
it is the path large estates use anyway because it survives a consumer being
down for a week. The storage account is read over the Data Lake Gen2
filesystem API, which answers in JSON — the classic Blob list API answers in
XML, and parsing XML here would add a parser and a scanner finding for no
functional gain.

Two consequences, stated rather than buried:

* **Latency is the Capture window**, which Azure allows between one and
  fifteen minutes. This connector is therefore near-real-time, not real
  time. A tenant that needs sub-minute latency on sign-ins should keep
  ``azure_entra`` alongside it for the high-signal subset.
* **Capture must be enabled on the hub.** ``test_connection`` says so
  explicitly when the configured container holds nothing, because "no
  events" and "Capture was never switched on" look identical otherwise and
  only one of them is a problem the operator can fix.

Resumption and backpressure
---------------------------

Capture file names embed the partition, and each record carries a sequence
number, so the cursor is ``(EnqueuedTimeUtc, "<path>#<sequence>#<index>")``
— stable across a re-read of the same file, which is what makes an
interrupted poll cost a duplicate rather than a gap. Files already consumed
are skipped by the cursor, not deleted: the storage account is the
customer's and this connector only reads.

``collection_budget`` bounds the poll. A capture container holds whatever
the retention policy keeps, and a first poll against a month of sign-in logs
would otherwise try to read all of it at once.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

import httpx
import structlog

from app.connectors.avro_ocf import AvroError, read_container
from app.connectors.base import (
    BaseConnector,
    Capability,
    CollectionBudget,
    ConnectorSchema,
    Field,
    OAuthHints,
)

logger = structlog.get_logger()

_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_STORAGE_SCOPE = "https://storage.azure.com/.default"

#: The Data Lake Gen2 API version that introduced `List Paths` with the
#: fields this connector reads. Pinned rather than "latest": a service that
#: picks whatever version the account defaults to is a service whose parsing
#: changes without a deploy.
_DFS_API_VERSION = "2023-11-03"

#: Azure's own level vocabulary on an exported diagnostic record. Mapped
#: with `Critical` preserved rather than collapsed into `high` — a vendor's
#: distinct top tier disappearing in normalisation is the loss nobody
#: notices until the one event that needed it is filed as routine.
_LEVEL: dict[str, str] = {
    "Verbose": "info",
    "Informational": "info",
    "Information": "info",
    "Warning": "medium",
    "Error": "high",
    "Critical": "critical",
}

#: Entra audit operations that change who can do what. A success here is
#: more interesting than a failure almost anywhere else.
_PRIVILEGED_AUDIT_OPERATIONS = frozenset(
    {
        "add member to role",
        "add eligible member to role",
        "add app role assignment to service principal",
        "add owner to application",
        "add service principal credentials",
        "consent to application",
        "update conditional access policy",
        "delete conditional access policy",
        "disable strong authentication",
        "reset password (by admin)",
        "update user",
    }
)


def _as_dict(value: Any) -> dict[str, Any]:
    """``value`` when it is a mapping, an empty dict otherwise.

    Written once because the alternative — ``x.get("k") if isinstance(x.get("k"), dict) else {}``
    at every site — widens to ``Any | dict | None`` for the type checker and
    reads as noise for a human.
    """
    return value if isinstance(value, dict) else {}


def _record_severity(record: dict[str, Any]) -> str:
    """Five-tier severity for one exported diagnostic record."""
    base = _LEVEL.get(str(record.get("level") or record.get("Level") or "Informational"), "info")
    category = str(record.get("category") or "")
    props = _as_dict(record.get("properties"))
    result_type = str(record.get("resultType") or "")

    if category == "SignInLogs":
        risk = str(props.get("riskLevelDuringSignIn") or props.get("riskLevelAggregated") or "none").lower()
        if risk == "high":
            return "critical"
        if risk == "medium":
            return "high"
        # resultType "0" is a successful sign-in. Anything else is a
        # failure, and a failure is the interesting half of a sign-in log.
        return "medium" if result_type not in ("0", "") else base
    if category == "AuditLogs":
        operation = str(record.get("operationName") or "").strip().lower()
        failed = str(props.get("result") or result_type).lower() in ("failure", "timeout")
        if operation in _PRIVILEGED_AUDIT_OPERATIONS:
            return "high" if not failed else "medium"
        return "medium" if failed else base
    # Activity log and everything else.
    if result_type.lower() in ("failed", "failure"):
        return max(base, "medium", key=["info", "low", "medium", "high", "critical"].index)
    return base


def _location(record: dict[str, Any]) -> str | None:
    """Country or region, whichever of the two shapes Azure used.

    A sign-in log nests ``properties.location`` as an object with
    ``countryOrRegion``; the Activity log puts an Azure region name in a
    top-level ``location`` string. Reading only one of them renders a dict
    into the console for half the corpus.
    """
    props = _as_dict(record.get("properties"))
    nested = props.get("location")
    if isinstance(nested, dict):
        value = nested.get("countryOrRegion") or nested.get("city")
        if isinstance(value, str) and value:
            return value
    elif isinstance(nested, str) and nested:
        return nested
    top = record.get("location")
    return top if isinstance(top, str) and top else None


def _identity_name(record: dict[str, Any]) -> str | None:
    """The principal, across the three shapes Azure uses for it.

    A sign-in log puts a display name in ``identity`` and the UPN under
    ``properties.userPrincipalName``; an audit log nests the actor under
    ``properties.initiatedBy``; the Activity log carries a claims bag. Three
    readers rather than one because a single ``.get("identity")`` returns a
    dict for one of them and renders as ``{'claims': ...}`` in the console.
    """
    props = _as_dict(record.get("properties"))
    upn = props.get("userPrincipalName")
    if isinstance(upn, str) and upn:
        return upn

    initiated = _as_dict(props.get("initiatedBy"))
    for slot in ("user", "app"):
        actor = _as_dict(initiated.get(slot))
        for key in ("userPrincipalName", "displayName", "servicePrincipalName", "appId"):
            value = actor.get(key)
            if isinstance(value, str) and value:
                return value

    identity = record.get("identity")
    if isinstance(identity, str) and identity:
        return identity
    if isinstance(identity, dict):
        claims = identity.get("claims")
        if isinstance(claims, dict):
            for key in ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", "name", "appid"):
                value = claims.get(key)
                if isinstance(value, str) and value:
                    return value
    return None


class AzureEventHubsConnector(BaseConnector):
    connector_id = "azure_event_hubs"
    connector_name = "Azure Event Hubs (Capture)"
    connector_category = "cloud"

    checkpoint_time_field = ("event_time",)
    checkpoint_id_field = ("record_id",)

    collection_budget = CollectionBudget(
        max_batches_per_poll=50,
        max_events_per_poll=20_000,
        backlog_stays_on_the_queue=(
            "Capture files are read, never deleted — the storage account belongs to the customer. Files past "
            "the budget are simply not opened this poll; the cursor means the next poll resumes at the first "
            "record it has not already emitted rather than re-reading from the start."
        ),
    )

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Entra sign-in logs, Entra audit logs and the Azure Activity log streamed to an "
                "Event Hub by a diagnostic setting and captured to a storage account. One "
                "configuration covers a whole tenant at the rate it actually produces events, "
                "with no Graph throttle."
            ),
            docs_url="/docs/connectors/azure-event-hubs",
            fields=[
                Field("tenant_id", "string", "Entra tenant ID", placeholder="00000000-0000-0000-0000-000000000000"),
                Field("client_id", "string", "Application (client) ID"),
                Field("client_secret", "secret", "Client secret"),
                Field(
                    "storage_account",
                    "string",
                    "Capture storage account name",
                    placeholder="contosologs",
                    help_text="The storage account the Event Hub's Capture writes to (the account name alone, not a URL).",
                ),
                Field(
                    "container",
                    "string",
                    "Capture container / filesystem",
                    placeholder="insights-logs",
                    help_text="The blob container Capture is configured to write into.",
                ),
                Field(
                    "prefix",
                    "string",
                    "Path prefix",
                    required=False,
                    default="",
                    help_text=(
                        "Optional. Narrow to one namespace or hub, e.g. 'contoso-ns/aisoc-hub'. Leave blank to read the whole container."
                    ),
                ),
            ],
            oauth=OAuthHints(
                supported_in_hosted=False,
                authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
                scopes=[_STORAGE_SCOPE],
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_AUDIT, Capability.PULL_LOGS)

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        storage_account: str,
        container: str,
        prefix: str = "",
    ):
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._account = storage_account
        self._container = container
        self._prefix = (prefix or "").strip().strip("/")
        self._access_token: str | None = None

    @property
    def _dfs_root(self) -> str:
        return f"https://{self._account}.dfs.core.windows.net/{quote(self._container, safe='')}"

    async def _authenticate(self, client: httpx.AsyncClient) -> str:
        if self._access_token:
            return self._access_token
        resp = await client.post(
            _TOKEN_URL.format(tenant_id=self._tenant_id),
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": _STORAGE_SCOPE,
            },
        )
        resp.raise_for_status()
        self._access_token = str(resp.json()["access_token"])
        return self._access_token

    def _headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", "x-ms-version": _DFS_API_VERSION}

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                token = await self._authenticate(client)
                paths = await self._list_paths(client, token, limit=1)
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

        result: dict[str, Any] = {
            "success": True,
            "connector": self.connector_id,
            "storage_account": self._account,
            "container": self._container,
            "capture_files_visible": len(paths),
        }
        if not paths:
            # The single most common setup mistake, and it is invisible
            # otherwise: the credential works, the container exists, and no
            # events will ever arrive because Capture was never switched on.
            result["warning"] = (
                "the container is readable but holds no capture files. Enable Capture on the Event Hub "
                "and point it at this container, then re-test — an empty container and a hub with Capture "
                "switched off look identical from here."
            )
        return result

    async def _list_paths(self, client: httpx.AsyncClient, token: str, limit: int) -> list[dict[str, Any]]:
        """Capture files under the configured prefix, oldest first.

        The Data Lake Gen2 ``List Paths`` call answers JSON and returns a
        continuation token in a response header. It is read recursively
        because Capture nests by namespace, hub, partition and timestamp.
        """
        out: list[dict[str, Any]] = []
        continuation: str | None = None
        while len(out) < limit:
            params: dict[str, Any] = {
                "resource": "filesystem",
                "recursive": "true",
                "maxResults": min(5000, max(1, limit - len(out))),
            }
            if self._prefix:
                params["directory"] = self._prefix
            if continuation:
                params["continuation"] = continuation
            resp = await client.get(self._dfs_root, params=params, headers=self._headers(token))
            if resp.status_code == 401:
                self._access_token = None
                resp.raise_for_status()
            resp.raise_for_status()
            payload = resp.json()
            for entry in payload.get("paths") or []:
                if not isinstance(entry, dict) or str(entry.get("isDirectory", "")).lower() == "true":
                    continue
                # Capture writes a zero-length file on every window in which
                # the hub received nothing, unless the operator opted out.
                # Opening those costs a round trip each and yields nothing.
                if int(entry.get("contentLength") or 0) <= 0:
                    continue
                out.append(entry)
                if len(out) >= limit:
                    break
            continuation = resp.headers.get("x-ms-continuation") or None
            if not continuation:
                break
        # Capture file names sort chronologically within a partition, and
        # across partitions the name still begins with the namespace and hub,
        # so a plain sort groups a partition's files together in time order.
        return sorted(out, key=lambda e: str(e.get("name") or ""))

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        """Read up to one budget's worth of capture files.

        ``since_seconds`` is ignored: the cursor is the record sequence, and
        a time window would re-read or skip depending on how the Capture
        window happened to line up with the poll.
        """
        budget = self.collection_budget
        assert budget is not None  # declared on the class; narrows the Optional for mypy
        rows: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                token = await self._authenticate(client)
                paths = await self._list_paths(client, token, limit=budget.max_batches_per_poll)
                for entry in paths:
                    if len(rows) >= budget.max_events_per_poll:
                        logger.info(
                            "azure_event_hubs.budget_reached",
                            rows=len(rows),
                            max_events_per_poll=budget.max_events_per_poll,
                            detail="remaining capture files are left for the next poll",
                        )
                        break
                    name = str(entry.get("name") or "")
                    try:
                        rows.extend(await self._read_capture_file(client, token, name))
                    except AvroError as exc:
                        # A single unreadable file must not strand the poll.
                        # Logged with the path because that is the only way
                        # an operator can decide whether it is one corrupt
                        # window or every file.
                        logger.warning("azure_event_hubs.capture_unreadable", path=name, error=str(exc))
                    except Exception as exc:
                        logger.warning("azure_event_hubs.read_failed", path=name, error=str(exc))
        except Exception as exc:
            logger.warning("azure_event_hubs.poll_failed", account=self._account, error=str(exc))
            return []

        return [self.normalize(row) for row in self.apply_checkpoint(rows)]

    async def _read_capture_file(self, client: httpx.AsyncClient, token: str, name: str) -> list[dict[str, Any]]:
        resp = await client.get(f"{self._dfs_root}/{quote(name, safe='/')}", headers=self._headers(token))
        resp.raise_for_status()
        envelopes: list[dict[str, Any]] = []
        for event in read_container(resp.content):
            body = event.get("Body")
            if not isinstance(body, bytes | bytearray):
                continue
            for index, record in enumerate(self._records_in(bytes(body))):
                envelopes.append(
                    {
                        "capture_path": name,
                        "record_id": f"{name}#{event.get('SequenceNumber')}#{index}",
                        "event_time": str(record.get("time") or event.get("EnqueuedTimeUtc") or ""),
                        "enqueued_time": event.get("EnqueuedTimeUtc"),
                        "record": record,
                    }
                )
        return envelopes

    @staticmethod
    def _records_in(body: bytes) -> list[dict[str, Any]]:
        """The diagnostic records inside one Event Hubs event body.

        Azure Monitor batches: one event's body is ``{"records": [...]}``
        with up to a few hundred entries. A body that is a bare object (what
        a hand-published test event looks like) is returned as a one-element
        list rather than dropped, so a misrouted producer is visible.
        """
        try:
            parsed = json.loads(body.decode("utf-8", errors="replace"))
        except (TypeError, ValueError):
            return []
        if isinstance(parsed, dict):
            records = parsed.get("records")
            if isinstance(records, list):
                return [r for r in records if isinstance(r, dict)]
            return [parsed]
        if isinstance(parsed, list):
            return [r for r in parsed if isinstance(r, dict)]
        return []

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        record: dict[str, Any] = raw.get("record") or {}
        props = _as_dict(record.get("properties"))
        category = str(record.get("category") or "")
        operation = str(record.get("operationName") or "")

        return {
            "source": self.connector_id,
            "category": "identity" if category in ("SignInLogs", "AuditLogs", "NonInteractiveUserSignInLogs") else "cloud",
            "external_id": record.get("correlationId") or props.get("id") or raw.get("record_id"),
            "title": operation or category or "Azure diagnostic record",
            "description": f"{operation or 'diagnostic record'} ({category or 'uncategorised'})",
            "severity": _record_severity(record),
            "cloud_platform": "azure",
            "azure_tenant_id": record.get("tenantId") or self._tenant_id,
            "azure_resource_id": record.get("resourceId"),
            "log_category": category or None,
            "operation_name": operation or None,
            "result_type": record.get("resultType"),
            "user_name": _identity_name(record),
            "src_ip": record.get("callerIpAddress") or props.get("ipAddress"),
            "user_agent": props.get("userAgent") or props.get("clientAppUsed"),
            "location": _location(record),
            "delivery": {"capture_path": raw.get("capture_path"), "enqueued_time": raw.get("enqueued_time")},
            "raw_event": record,
            "created_at": raw.get("event_time"),
        }
