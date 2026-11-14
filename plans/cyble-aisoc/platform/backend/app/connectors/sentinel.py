"""Microsoft Sentinel SIEM connector.

Implements ``BaseSiemConnector`` against Azure Log Analytics — the data
store Sentinel sits on. Both events (``SecurityEvent``, ``CommonSecurityLog``,
``Syslog``, custom ``*_CL`` tables) and alerts (``SecurityAlert``) live in
the same workspace and are queried via KQL through the Log Analytics
Query REST API.

Why query Log Analytics directly
--------------------------------
Sentinel exposes a second, ARM-rooted REST surface for incidents
(``https://management.azure.com/.../Microsoft.SecurityInsights/incidents``)
that returns triaged ``SecurityIncident`` rows. That surface is the right
choice when an analyst wants the case object — assignment, status,
classification — but it is *not* the right choice for
``get_related_alerts``, which needs raw alert rows.

By staying on Log Analytics for both ``search_events`` and
``get_related_alerts``:

  * One OAuth scope (``api.loganalytics.io/.default``) covers both calls.
  * One ``AsyncHttpClient`` (one keepalive pool, one token cache).
  * Tenants without Sentinel (Log Analytics only) work identically.
  * Custom tables (``MyEdr_CL`` etc.) work without code changes.

If a future tool ever needs incident lifecycle ops (close, reassign,
classify), a sibling ``SentinelIncidentConnector`` can plug into ARM
without disturbing this one.

Config (``params``)
-------------------
* ``workspace_id``           — Log Analytics workspace GUID. Required.
                               (The "Workspace ID" from the Sentinel
                               overview blade, *not* the resource id.)
* ``azure_tenant_id``        — Azure AD directory tenant ID (GUID).
                               Required. The OAuth token endpoint is
                               keyed on this. Distinct from our own
                               per-customer ``tenant_id``.
* ``events_table``           — Default events table for KQL. Default
                               ``"SecurityEvent"``. Override to e.g.
                               ``"CommonSecurityLog"`` for CEF feeds
                               or ``"MyEdr_CL"`` for custom logs.
* ``alerts_table``           — Default alerts table. Default
                               ``"SecurityAlert"``.
* ``max_results``            — Per-call row cap. Default ``200``.
                               Hard-capped at 10,000 (Log Analytics
                               returns at most 30k rows per response,
                               but the LLM context window is the
                               binding constraint).
* ``read_timeout_s``         — Per-query read timeout. Default ``60``.
* ``verify_tls``             — Verify TLS certs. Default ``True``.
* ``api_base_url``           — Override for sovereign clouds. Default
                               ``"https://api.loganalytics.io/v1"``.
                               Azure Gov:
                               ``"https://api.loganalytics.us/v1"``.
                               Azure China:
                               ``"https://api.loganalytics.azure.cn/v1"``.
* ``token_url``              — Override for sovereign / national OAuth
                               endpoints. Default builds
                               ``https://login.microsoftonline.com/{azure_tenant_id}/oauth2/v2.0/token``.
* ``oauth_scope``            — Override OAuth scope. Default
                               ``"https://api.loganalytics.io/.default"``.
                               Sovereign clouds need the matching
                               resource (e.g. ``api.loganalytics.us``).
* ``events_query_template``  — Optional KQL override. Placeholders:
                               ``{entity}``, ``{entity_type}``,
                               ``{minutes}``, ``{events_table}``,
                               ``{max_results}``. Entity values are
                               quote-escaped before substitution.
* ``alerts_query_template``  — Optional KQL override. Placeholders:
                               ``{entity}``, ``{hours}``,
                               ``{alerts_table}``, ``{max_results}``.

Config (``secrets``)
--------------------
* ``client_id``     — App registration's Application (client) ID.
* ``client_secret`` — App registration client secret.

The service principal must hold the ``Microsoft Sentinel Reader`` (or
``Log Analytics Reader``) role on the workspace.

KQL injection
-------------
Like SPL, KQL has no parameter binding in the v1 query API. Entity
values reach this connector from alert payloads and LLM-extracted
strings. We defensively:

  1. Reject control characters and NULs in the raw value.
  2. Escape ``\\`` and ``"`` for safe interpolation into a KQL
     double-quoted string literal.
  3. Always wrap the value in double quotes in the rendered KQL.

Table names ride raw into the query (KQL has no quoting for identifier
references), so we validate them against the KQL identifier charset.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Iterable

import httpx

from app.connectors.sdk.base import (
    ConnectorAuthError,
    ConnectorConfig,
    ConnectorError,
)
from app.connectors.sdk.http import AsyncHttpClient, OAuthClientCredentials
from app.connectors.sdk.protocols import BaseSiemConnector

log = logging.getLogger(__name__)


# ─── defaults ────────────────────────────────────────────────────────────

_DEFAULT_API_BASE_URL = "https://api.loganalytics.io/v1"
_DEFAULT_OAUTH_SCOPE = "https://api.loganalytics.io/.default"
_DEFAULT_AAD_AUTHORITY = "https://login.microsoftonline.com"


# Default KQL for ``search_events``. We cast a wide net across the
# field names Microsoft tables commonly use for each entity type. The
# templates terminate with ``project-away`` of large/binary columns so
# the LLM doesn't drown in field salad; tenants with custom shapes
# should supply an explicit ``events_query_template``.
_DEFAULT_EVENTS_KQL = {
    "host": (
        '{events_table}\n'
        '| where TimeGenerated > ago({minutes}m)\n'
        '| where Computer == "{entity}" or HostName == "{entity}" '
        'or DvcHostname == "{entity}" or DeviceName == "{entity}"\n'
        '| top {max_results} by TimeGenerated desc'
    ),
    "user": (
        '{events_table}\n'
        '| where TimeGenerated > ago({minutes}m)\n'
        '| where Account == "{entity}" or TargetAccount == "{entity}" '
        'or SubjectUserName == "{entity}" or UserPrincipalName == "{entity}" '
        'or AccountUpn == "{entity}"\n'
        '| top {max_results} by TimeGenerated desc'
    ),
    "ip": (
        '{events_table}\n'
        '| where TimeGenerated > ago({minutes}m)\n'
        '| where IpAddress == "{entity}" or SourceIP == "{entity}" '
        'or DestinationIP == "{entity}" or ClientIP == "{entity}" '
        'or RemoteIP == "{entity}"\n'
        '| top {max_results} by TimeGenerated desc'
    ),
}

# Default KQL for ``get_related_alerts``. ``Entities`` is a JSON string
# on ``SecurityAlert`` rows; substring matching is the most reliable
# cross-vendor approach because the JSON shape varies by alert
# provider. ``CompromisedEntity`` is the human-readable summary.
_DEFAULT_ALERTS_KQL = (
    '{alerts_table}\n'
    '| where TimeGenerated > ago({hours}h)\n'
    '| where Entities contains "{entity}" '
    'or CompromisedEntity contains "{entity}" '
    'or ExtendedProperties contains "{entity}"\n'
    '| top {max_results} by TimeGenerated desc'
)


# ─── helpers ─────────────────────────────────────────────────────────────


# Characters we refuse to escape in entity values. NUL terminates KQL
# strings on some backends; CR/LF/Tab can break out of multi-line KQL
# definitions; embedded control chars almost certainly indicate injection
# attempts rather than legitimate hostnames/users/IPs.
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x1f\x7f]")

# Azure resource GUIDs (workspace_id, azure_tenant_id) follow the
# canonical 8-4-4-4-12 hex format. Validating early gives a clearer
# error than letting Log Analytics 404 us.
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# KQL identifier rules: leading letter or underscore, then letters,
# digits, or underscores. Covers ``SecurityEvent``, ``MyTable_CL``,
# ``_AzureBackup_Tables`` (Microsoft system tables sometimes lead with
# ``_``).
_KQL_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _escape_kql_value(value: str) -> str:
    """Escape `value` for safe interpolation into a double-quoted KQL string.

    KQL string literals use C-style escaping in double-quoted form
    (``"foo"`` allows ``\\"`` and ``\\\\``). This function returns the
    *content* to be wrapped in ``"..."`` by the caller.

    Raises ``ConnectorError`` if `value` is empty or contains control
    characters — we reject rather than try to sanitise CR/LF/NUL.
    """
    if not isinstance(value, str):
        raise ConnectorError(
            f"sentinel: expected string, got {type(value).__name__}",
            vendor="sentinel",
        )
    if not value:
        raise ConnectorError(
            "sentinel: empty entity value rejected",
            vendor="sentinel",
        )
    if _FORBIDDEN_CHARS.search(value):
        raise ConnectorError(
            f"sentinel: entity {value!r} contains control characters",
            vendor="sentinel",
        )
    # Backslash first — otherwise the subsequent double-quote replacement
    # re-escapes its own slashes.
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _validate_guid(value: Any, *, name: str) -> str:
    """Require `value` to look like an Azure GUID (8-4-4-4-12 hex)."""
    if not isinstance(value, str) or not value:
        raise ConnectorError(
            f"sentinel: {name} must be a non-empty string",
            vendor="sentinel",
        )
    if not _GUID_RE.match(value):
        raise ConnectorError(
            f"sentinel: {name}={value!r} is not a valid Azure GUID",
            vendor="sentinel",
        )
    return value


def _validate_table(value: str, *, field: str) -> str:
    """Validate a KQL table identifier — rides raw into the query."""
    if not isinstance(value, str) or not value:
        raise ConnectorError(
            f"sentinel: {field} must be a non-empty string",
            vendor="sentinel",
        )
    if not _KQL_IDENT_RE.match(value):
        raise ConnectorError(
            f"sentinel: {field}={value!r} is not a valid KQL identifier",
            vendor="sentinel",
        )
    return value


def _coerce_int(value: Any, *, name: str, lo: int, hi: int) -> int:
    """Bound check + cast for integers ingested from external callers."""
    try:
        as_int = int(value)
    except (TypeError, ValueError) as exc:
        raise ConnectorError(
            f"sentinel: {name} must be an integer (got {value!r})",
            vendor="sentinel",
        ) from exc
    if as_int < lo or as_int > hi:
        raise ConnectorError(
            f"sentinel: {name}={as_int} out of range [{lo}, {hi}]",
            vendor="sentinel",
        )
    return as_int


def _to_iso(ts_raw: Any) -> str:
    """Normalise a Log Analytics ``datetime`` column to ISO-8601 with TZ.

    The Log Analytics query API returns ``datetime`` columns as
    ISO-8601 strings (typically ``2026-04-28T17:14:00.123Z``). We
    re-format through ``datetime.fromisoformat`` to canonicalise the
    suffix (``Z`` -> ``+00:00``). Anything unparseable falls through
    as-is so we never drop an event.
    """
    if ts_raw is None:
        return ""
    if isinstance(ts_raw, (int, float)):
        try:
            return datetime.fromtimestamp(float(ts_raw), tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return str(ts_raw)
    if isinstance(ts_raw, str):
        try:
            return datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).isoformat()
        except ValueError:
            return ts_raw
    return str(ts_raw)


def _infer_event_type(row: dict[str, Any]) -> str:
    """Pick a stable ``type`` label for a Log Analytics row.

    Microsoft tables have no single "event type" column — different
    products surface it differently. Priority order picks the most
    specific available; ``Type`` (the table name) is the universal
    fallback because the query API always returns it.
    """
    for field in (
        "EventID",        # SecurityEvent
        "Activity",       # AzureActivity, OfficeActivity
        "Operation",      # AuditLogs
        "OperationName",  # AzureDiagnostics
        "Category",       # generic
        "EventType",
        "Type",           # table name — always present
    ):
        value = row.get(field)
        if value not in (None, ""):
            return str(value)
    return "sentinel_event"


def _query_response_to_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a Log Analytics ``/query`` body to a list of column-named dicts.

    Log Analytics returns one or more ``tables`` with parallel
    ``columns`` and ``rows`` arrays. We only consume the primary
    result; ad-hoc queries that emit multiple tables are out of scope.
    """
    if not isinstance(payload, dict):
        return []
    tables = payload.get("tables")
    if not isinstance(tables, list) or not tables:
        return []
    primary = tables[0]
    if not isinstance(primary, dict):
        return []
    columns = primary.get("columns") or []
    rows = primary.get("rows") or []
    if not isinstance(columns, list) or not isinstance(rows, list):
        return []
    col_names = []
    for col in columns:
        if isinstance(col, dict) and isinstance(col.get("name"), str):
            col_names.append(col["name"])
        else:
            col_names.append("")
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, list):
            continue
        record = {col_names[i]: row[i] for i in range(min(len(col_names), len(row)))}
        out.append(record)
    return out


def _raise_for_query_error(payload: Any) -> None:
    """Some Log Analytics errors come back HTTP-200 with an ``error`` block."""
    if not isinstance(payload, dict):
        return
    error = payload.get("error")
    if not error:
        return
    if isinstance(error, dict):
        message = error.get("message") or error.get("code") or str(error)
    else:
        message = str(error)
    raise ConnectorError(
        f"sentinel: Log Analytics query error: {message}",
        vendor="sentinel",
    )


def _first_truthy(row: dict[str, Any], *, keys: Iterable[str], fallback: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return fallback


# ─── connector ───────────────────────────────────────────────────────────


class SentinelSiemConnector(BaseSiemConnector):
    """Microsoft Sentinel SIEM via Log Analytics Query API.

    Each instance owns one ``AsyncHttpClient`` against
    ``api.loganalytics.io``. The OAuth client_credentials token is
    cached in the auth strategy and refreshed lazily before expiry —
    so within a tenant, repeated tool calls reuse one HTTP pool and
    one access token.
    """

    vendor = "sentinel"

    def __init__(self, config: ConnectorConfig) -> None:
        super().__init__(config)

        workspace_id = config.param("workspace_id")
        azure_tenant_id = config.param("azure_tenant_id")
        if not workspace_id:
            raise ConnectorError(
                "sentinel: missing required param 'workspace_id' "
                "(Log Analytics workspace GUID)",
                vendor="sentinel",
            )
        if not azure_tenant_id:
            raise ConnectorError(
                "sentinel: missing required param 'azure_tenant_id' "
                "(Azure AD directory tenant GUID)",
                vendor="sentinel",
            )
        self._workspace_id = _validate_guid(workspace_id, name="workspace_id")
        self._azure_tenant_id = _validate_guid(
            azure_tenant_id, name="azure_tenant_id"
        )

        self._events_table = _validate_table(
            str(config.param("events_table") or "SecurityEvent"),
            field="events_table",
        )
        self._alerts_table = _validate_table(
            str(config.param("alerts_table") or "SecurityAlert"),
            field="alerts_table",
        )
        self._max_results = _coerce_int(
            config.param("max_results") or 200,
            name="max_results",
            lo=1,
            hi=10_000,
        )
        read_timeout = float(config.param("read_timeout_s") or 60.0)
        verify_tls = bool(config.param("verify_tls", True))

        self._events_template = (
            config.param("events_query_template")
            if isinstance(config.param("events_query_template"), str)
            else None
        )
        self._alerts_template = (
            config.param("alerts_query_template")
            if isinstance(config.param("alerts_query_template"), str)
            else None
        )

        api_base_url = str(
            config.param("api_base_url") or _DEFAULT_API_BASE_URL
        ).rstrip("/")
        self._api_base_url = api_base_url

        # OAuth client_credentials. Azure AD wants the scope (v2.0 token
        # endpoint) — `audience` is the v1.0 equivalent. We use scope.
        client_id = config.secret("client_id")
        client_secret = config.secret("client_secret")
        token_url = config.param("token_url") or (
            f"{_DEFAULT_AAD_AUTHORITY}/{self._azure_tenant_id}/oauth2/v2.0/token"
        )
        oauth_scope = str(config.param("oauth_scope") or _DEFAULT_OAUTH_SCOPE)

        auth = OAuthClientCredentials(
            token_url=str(token_url),
            client_id=client_id,
            client_secret=client_secret,
            scope=oauth_scope,
        )

        self._http = AsyncHttpClient(
            base_url=api_base_url,
            auth=auth,
            timeout=httpx.Timeout(
                connect=10.0, read=read_timeout, write=10.0, pool=5.0
            ),
            vendor="sentinel",
            verify=verify_tls,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )

    # ------------------------------------------------------------------ #
    # Lifecycle                                                          #
    # ------------------------------------------------------------------ #

    async def aclose(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------ #
    # Public protocol surface                                            #
    # ------------------------------------------------------------------ #

    async def health_check(self) -> dict[str, Any]:
        """Run a trivial KQL to verify OAuth + workspace access.

        ``print Ok = "ok"`` returns a single row with no table reference,
        so it succeeds even on workspaces with zero ingested data — it
        only fails when the OAuth token is wrong (401) or the workspace
        ID is wrong (404). Both surface through the HTTP layer as
        typed ``Connector*Error``.
        """
        payload = await self._run_query('print Ok = "ok"')
        rows = _query_response_to_rows(payload)
        return {
            "ok": True,
            "vendor": self.vendor,
            "kind": self.kind.value,
            "workspace_id": self._workspace_id,
            "rows_returned": len(rows),
        }

    async def search_events(
        self, *, entity: str, entity_type: str, minutes: int = 60
    ) -> dict[str, Any]:
        """Run the events KQL for `entity`, return normalized envelope.

        Mirrors ``MockSiemConnector.search_events`` shape so the LLM
        tool surface is unchanged across mock/Splunk/Sentinel routing.
        """
        minutes = _coerce_int(minutes, name="minutes", lo=1, hi=10_080)  # max 7d
        if entity_type not in _DEFAULT_EVENTS_KQL and self._events_template is None:
            raise ConnectorError(
                f"sentinel: unsupported entity_type {entity_type!r} "
                "(expected one of host, user, ip; or supply "
                "events_query_template)",
                vendor="sentinel",
            )

        kql = self._render_events_kql(
            entity=entity, entity_type=entity_type, minutes=minutes
        )
        payload = await self._run_query(kql)
        rows = _query_response_to_rows(payload)
        events = [self._normalize_event(row) for row in rows]
        return {
            "entity": entity,
            "entity_type": entity_type,
            "window_minutes": minutes,
            "events": events,
        }

    async def get_related_alerts(
        self, *, entity: str, hours: int = 24
    ) -> dict[str, Any]:
        """Run the related-alerts KQL for `entity`, return normalized envelope."""
        hours = _coerce_int(hours, name="hours", lo=1, hi=720)  # max 30d
        kql = self._render_alerts_kql(entity=entity, hours=hours)
        payload = await self._run_query(kql)
        rows = _query_response_to_rows(payload)
        related = [self._normalize_alert(row) for row in rows]
        return {
            "entity": entity,
            "related_count": len(related),
            "related": related,
        }

    # ------------------------------------------------------------------ #
    # KQL rendering                                                      #
    # ------------------------------------------------------------------ #

    def _render_events_kql(
        self, *, entity: str, entity_type: str, minutes: int
    ) -> str:
        template = self._events_template or _DEFAULT_EVENTS_KQL[entity_type]
        escaped = _escape_kql_value(entity)
        try:
            return template.format(
                entity=escaped,
                entity_type=entity_type,
                minutes=minutes,
                events_table=self._events_table,
                max_results=self._max_results,
            )
        except KeyError as exc:
            raise ConnectorError(
                f"sentinel: events_query_template references unknown "
                f"placeholder {exc!s}; supported: {{entity}}, {{entity_type}}, "
                "{minutes}, {events_table}, {max_results}",
                vendor="sentinel",
            ) from exc

    def _render_alerts_kql(self, *, entity: str, hours: int) -> str:
        template = self._alerts_template or _DEFAULT_ALERTS_KQL
        escaped = _escape_kql_value(entity)
        try:
            return template.format(
                entity=escaped,
                hours=hours,
                alerts_table=self._alerts_table,
                max_results=self._max_results,
            )
        except KeyError as exc:
            raise ConnectorError(
                f"sentinel: alerts_query_template references unknown "
                f"placeholder {exc!s}; supported: {{entity}}, {{hours}}, "
                "{alerts_table}, {max_results}",
                vendor="sentinel",
            ) from exc

    # ------------------------------------------------------------------ #
    # Log Analytics REST                                                 #
    # ------------------------------------------------------------------ #

    async def _run_query(self, kql: str) -> dict[str, Any]:
        """POST `kql` to the workspace query endpoint, return parsed JSON."""
        endpoint = f"/workspaces/{self._workspace_id}/query"
        log.debug(
            "sentinel: query tenant=%s workspace=%s kql=%r",
            self.tenant_id,
            self._workspace_id,
            kql[:300],
        )
        payload = await self._http.post(endpoint, json={"query": kql})
        if payload is None:
            return {}
        if not isinstance(payload, dict):
            raise ConnectorError(
                f"sentinel: query response was not a JSON object: "
                f"{type(payload).__name__}",
                vendor="sentinel",
            )
        _raise_for_query_error(payload)
        return payload

    # ------------------------------------------------------------------ #
    # Result normalization                                               #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _normalize_event(row: dict[str, Any]) -> dict[str, Any]:
        """Map a Log Analytics row to the SIEM event envelope.

        Output shape mirrors the legacy mock:
        ``{ts, type, ...passthrough}``. We drop ``None`` columns to
        keep the LLM context tight; Log Analytics tables are wide and
        most columns are empty for any given row.
        """
        out: dict[str, Any] = {
            "ts": _to_iso(row.get("TimeGenerated")),
            "type": _infer_event_type(row),
        }
        for key, value in row.items():
            if key in out:
                continue
            if value is None:
                continue
            out[key] = value
        return out

    @staticmethod
    def _normalize_alert(row: dict[str, Any]) -> dict[str, Any]:
        """Map a ``SecurityAlert`` row to the related-alert shape.

        ``SystemAlertId`` is the canonical Sentinel identifier. We fall
        back through ``VendorOriginalId`` (the upstream MDC alert id)
        and ``AlertName`` to cope with custom tables that don't
        populate the standard schema.
        """
        title = (
            row.get("AlertName")
            or row.get("DisplayName")
            or row.get("Title")
            or "sentinel_alert"
        )
        severity = (
            row.get("AlertSeverity")
            or row.get("Severity")
            or "unknown"
        )
        alert_id = _first_truthy(
            row,
            keys=(
                "SystemAlertId",
                "VendorOriginalId",
                "AlertLink",
                "AlertName",
            ),
            fallback="sentinel_alert",
        )
        return {
            "id": str(alert_id),
            "title": str(title),
            "severity": str(severity).lower(),
        }


# ─── factory ─────────────────────────────────────────────────────────────


def make_sentinel_siem(config: ConnectorConfig) -> SentinelSiemConnector:
    """Factory entry-point registered in ``app/connectors/sdk/builtin.py``."""
    return SentinelSiemConnector(config)


__all__ = [
    "SentinelSiemConnector",
    "make_sentinel_siem",
]
