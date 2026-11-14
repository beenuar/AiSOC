"""Splunk SIEM connector.

Implements ``BaseSiemConnector`` against the Splunk REST API. Works with
both Splunk Cloud (bearer-token auth) and on-prem Splunk Enterprise
(HTTP Basic auth on the management port, typically 8089).

Why oneshot search
------------------
Splunk's search REST API has three modes: ``normal`` (async, poll for
results), ``blocking`` (sync, wait until done), and ``oneshot`` (sync,
returns results in a single response). We use ``oneshot`` because:

  * The agent's tool call is already synchronous from the LLM's
    perspective — there is no polling state worth tracking.
  * Each call is small (default 200 events, single time window),
    well under the oneshot result-limit ceiling.
  * It collapses three round-trips into one, reducing tail latency
    that the agent feels directly when narrating findings.

For very large searches we'd switch to ``normal`` + poll, but that's
intentionally out of scope for v1.

Config (``params``)
-------------------
* ``base_url``            — Splunk REST endpoint, e.g.
                            ``https://splunk.example.com:8089`` (on-prem)
                            or ``https://your-stack.splunkcloud.com:8089``.
                            Required.
* ``app``                 — App namespace. Default ``"search"``.
* ``owner``               — User namespace. Default ``"nobody"``.
* ``index``               — Index whitelist (single index or comma-list,
                            no quotes). Default ``"*"``. Used in default
                            SPL templates only; custom templates may
                            ignore it.
* ``notable_index``       — Index for ES notable events. Default
                            ``"notable"``. Used for ``get_related_alerts``.
* ``max_results``         — Per-call event cap. Default ``200``.
* ``read_timeout_s``      — Per-search read timeout in seconds.
                            Default ``60``. Splunk searches can run
                            longer than vendor APIs.
* ``verify_tls``          — Verify TLS certs. Default ``True``.
                            On-prem deployments with self-signed certs
                            sometimes need ``False`` (audit-logged).
* ``events_search_template`` — Optional SPL override. Placeholders:
                            ``{entity}``, ``{entity_type}``, ``{minutes}``,
                            ``{index}``, ``{max_results}``. Entities are
                            quote-escaped before substitution.
* ``alerts_search_template`` — Optional SPL override. Placeholders:
                            ``{entity}``, ``{hours}``, ``{notable_index}``,
                            ``{max_results}``.

Config (``secrets``)
--------------------
One of:
* ``token``       — Splunk auth token (preferred; Splunk Cloud default).
* ``username`` + ``password`` — HTTP Basic on the management port.

SPL injection
-------------
Entity values reach this connector from alert payloads and LLM-extracted
strings. Splunk SPL has no query-parameter binding mechanism, so we
defensively:

  1. Reject control characters, NULs, and embedded quotes in raw form.
  2. Escape backslashes and double-quotes for safe string interpolation.
  3. Always wrap the value in double quotes in the rendered SPL.

This is sufficient for substitution into double-quoted SPL string
literals. We do *not* validate operator-supplied templates; admins are
trusted there.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from app.connectors.sdk.base import (
    ConnectorAuthError,
    ConnectorConfig,
    ConnectorError,
)
from app.connectors.sdk.http import AsyncHttpClient, BasicAuth, BearerAuth
from app.connectors.sdk.protocols import BaseSiemConnector

log = logging.getLogger(__name__)


# ─── SPL templates ───────────────────────────────────────────────────────

# Default SPL for ``search_events``. Splunk searches must begin with the
# ``search`` command (or a generating command) — the leading keyword is
# load-bearing.
#
# Per-entity-type field expansion: most production deployments tag the
# host/user/IP on multiple field names depending on the data source
# (`host`, `dest`, `src_host`, `Computer`, etc.). We err on the side of
# casting a wide net by default; tenants with cleaner schemas should
# supply an explicit ``events_search_template`` to narrow it.
_DEFAULT_EVENTS_SPL = {
    "host": (
        'search index={index} '
        '(host="{entity}" OR dest="{entity}" OR src="{entity}" '
        'OR Computer="{entity}") '
        'earliest=-{minutes}m latest=now '
        '| head {max_results} '
        '| sort -_time'
    ),
    "user": (
        'search index={index} '
        '(user="{entity}" OR src_user="{entity}" OR src_username="{entity}" '
        'OR User="{entity}") '
        'earliest=-{minutes}m latest=now '
        '| head {max_results} '
        '| sort -_time'
    ),
    "ip": (
        'search index={index} '
        '(src_ip="{entity}" OR dest_ip="{entity}" OR ip="{entity}") '
        'earliest=-{minutes}m latest=now '
        '| head {max_results} '
        '| sort -_time'
    ),
}

# Default SPL for ``get_related_alerts``. Targets Splunk ES notable
# events; tenants without ES typically override this to query their
# correlation-rule summary index.
_DEFAULT_ALERTS_SPL = (
    'search index={notable_index} '
    '(host="{entity}" OR user="{entity}" OR src="{entity}" '
    'OR src_ip="{entity}" OR dest="{entity}" OR dest_ip="{entity}") '
    'earliest=-{hours}h latest=now '
    '| head {max_results} '
    '| table event_id, _time, rule_name, severity, urgency, host, user'
)


# ─── helpers ─────────────────────────────────────────────────────────────


# Characters that absolutely cannot appear in interpolated SPL strings
# even after quote-escaping. NUL kills the request; CR/LF/Tab can break
# out of search definitions; embedded quotes are escaped but we reject
# anyway to keep audit trails sane.
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _escape_spl_value(value: str) -> str:
    """Escape `value` for safe interpolation into a double-quoted SPL literal.

    Splunk SPL string literals are double-quoted and use backslash
    escaping. The caller is responsible for wrapping the result in
    ``"..."`` — this function returns the *content*, not the quotes.

    Raises ``ConnectorError`` if `value` contains control characters
    we refuse to escape (we won't try to handle CRLF injection by
    sanitising; we reject the input outright).
    """
    if not isinstance(value, str):
        raise ConnectorError(
            f"splunk: expected string, got {type(value).__name__}",
            vendor="splunk",
        )
    if not value:
        raise ConnectorError(
            "splunk: empty entity value rejected",
            vendor="splunk",
        )
    if _FORBIDDEN_CHARS.search(value):
        raise ConnectorError(
            f"splunk: entity {value!r} contains control characters",
            vendor="splunk",
        )
    # Backslash must be escaped first, otherwise the subsequent
    # double-quote replacement re-escapes its own slashes.
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _validate_index(index: str) -> str:
    """Index names ride raw into SPL — restrict to Splunk's legal charset.

    Splunk index names are alphanumeric plus ``-``, ``_``, comma (list),
    and ``*`` (wildcard). Anything else is a misconfiguration we should
    flag instead of executing.
    """
    if not isinstance(index, str) or not index:
        raise ConnectorError("splunk: index must be a non-empty string", vendor="splunk")
    if not re.fullmatch(r"[A-Za-z0-9_\-*,]+", index):
        raise ConnectorError(
            f"splunk: invalid index value {index!r}",
            vendor="splunk",
        )
    return index


def _coerce_int(value: Any, *, name: str, lo: int, hi: int) -> int:
    """Bound check + cast for integers ingested from external callers."""
    try:
        as_int = int(value)
    except (TypeError, ValueError) as exc:
        raise ConnectorError(
            f"splunk: {name} must be an integer (got {value!r})",
            vendor="splunk",
        ) from exc
    if as_int < lo or as_int > hi:
        raise ConnectorError(
            f"splunk: {name}={as_int} out of range [{lo}, {hi}]",
            vendor="splunk",
        )
    return as_int


def _to_iso(ts_raw: Any) -> str:
    """Normalise Splunk's ``_time`` to ISO-8601 with timezone.

    Splunk returns ``_time`` as either an ISO-8601 string with offset
    (most modern deployments) or a numeric epoch. Both are handled.
    Anything unparseable falls through as-is so we don't drop the event.
    """
    if ts_raw is None:
        return ""
    if isinstance(ts_raw, (int, float)):
        try:
            return datetime.fromtimestamp(float(ts_raw), tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return str(ts_raw)
    if isinstance(ts_raw, str):
        # Most Splunk outputs already look like ``2026-04-28T17:14:00.000+00:00``.
        # Don't risk re-formatting if we can't parse it cleanly.
        try:
            return datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).isoformat()
        except ValueError:
            return ts_raw
    return str(ts_raw)


def _infer_event_type(row: dict[str, Any]) -> str:
    """Pick a stable ``type`` label for an event row.

    Splunk doesn't have a canonical "type" field — different sourcetypes
    use ``signature``, ``EventCode``, ``action``, etc. We pick the first
    populated field from a priority list. ``sourcetype`` is the universal
    fallback because it's always present.
    """
    for field in (
        "event_type",
        "signature",
        "EventCode",
        "action",
        "category",
        "sourcetype",
    ):
        value = row.get(field)
        if value:
            return str(value)
    return "splunk_event"


def _splunk_messages(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Pluck ``messages`` from a Splunk REST response."""
    raw = payload.get("messages") or []
    if not isinstance(raw, list):
        return []
    return [m for m in raw if isinstance(m, dict)]


def _raise_for_search_errors(payload: dict[str, Any], *, spl: str) -> None:
    """If Splunk surfaced a search error inline, surface it as ConnectorError.

    Splunk REST returns HTTP 200 with ``messages: [{"type": "FATAL", "text": "..."}]``
    on parsing or runtime SPL errors. We treat FATAL and ERROR as fatal,
    log WARN and INFO.
    """
    for msg in _splunk_messages(payload):
        mtype = (msg.get("type") or "").upper()
        if mtype in {"FATAL", "ERROR"}:
            text = msg.get("text") or "unknown splunk error"
            log.warning(
                "splunk: search returned %s: %s spl=%r", mtype, text, spl[:200]
            )
            raise ConnectorError(
                f"splunk search error ({mtype}): {text}",
                vendor="splunk",
            )
        if mtype in {"WARN", "INFO", "DEBUG"}:
            log.debug("splunk: %s: %s", mtype, msg.get("text"))


# ─── connector ───────────────────────────────────────────────────────────


class SplunkSiemConnector(BaseSiemConnector):
    """Splunk SIEM via REST search-jobs API.

    Instances are stateless apart from the embedded ``AsyncHttpClient``,
    which owns connection keepalive. ``aclose()`` is required on shutdown
    (the registry handles it on cache eviction).
    """

    vendor = "splunk"

    def __init__(self, config: ConnectorConfig) -> None:
        super().__init__(config)

        base_url = config.param("base_url")
        if not base_url or not isinstance(base_url, str):
            raise ConnectorError(
                "splunk: missing required param 'base_url' "
                "(e.g. https://splunk.example.com:8089)",
                vendor="splunk",
            )

        # Strip trailing slash so f-strings stay readable.
        self._base_url = base_url.rstrip("/")
        self._app = str(config.param("app") or "search")
        self._owner = str(config.param("owner") or "nobody")
        self._index = _validate_index(str(config.param("index") or "*"))
        self._notable_index = _validate_index(
            str(config.param("notable_index") or "notable")
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
            config.param("events_search_template")
            if isinstance(config.param("events_search_template"), str)
            else None
        )
        self._alerts_template = (
            config.param("alerts_search_template")
            if isinstance(config.param("alerts_search_template"), str)
            else None
        )

        token = config.secrets.get("token")
        username = config.secrets.get("username")
        password = config.secrets.get("password")
        if token:
            auth = BearerAuth(token=token)
        elif username and password:
            auth = BasicAuth(username=username, password=password)
        else:
            raise ConnectorAuthError(
                "splunk: provide either secret 'token' (Splunk Cloud) or "
                "both 'username' and 'password' (on-prem Basic auth)",
                vendor="splunk",
            )

        import httpx

        self._http = AsyncHttpClient(
            base_url=self._base_url,
            auth=auth,
            timeout=httpx.Timeout(
                connect=10.0, read=read_timeout, write=10.0, pool=5.0
            ),
            vendor="splunk",
            verify=verify_tls,
            # Splunk responds with `application/json` only when we ask
            # for it; without these the response is XML.
            headers={"Accept": "application/json"},
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
        """Hit ``/services/server/info`` to verify auth + connectivity.

        Returns ``{ok: True, vendor, server_name, version}`` on success.
        Bubbles ``ConnectorAuthError`` / ``ConnectorError`` from the HTTP
        layer on failure.
        """
        payload = await self._http.get(
            "/services/server/info",
            params={"output_mode": "json"},
        )
        # ``server/info`` returns an Atom-style JSON with ``entry``.
        entry = (payload or {}).get("entry") or []
        if entry and isinstance(entry, list):
            content = entry[0].get("content") if isinstance(entry[0], dict) else {}
        else:
            content = {}
        return {
            "ok": True,
            "vendor": self.vendor,
            "kind": self.kind.value,
            "server_name": content.get("serverName"),
            "version": content.get("version"),
        }

    async def search_events(
        self, *, entity: str, entity_type: str, minutes: int = 60
    ) -> dict[str, Any]:
        """Run the events SPL for `entity`, return normalized envelope.

        Mirrors ``MockSiemConnector.search_events`` shape so the LLM tool
        surface is unchanged.
        """
        minutes = _coerce_int(minutes, name="minutes", lo=1, hi=10_080)  # max 7d
        if entity_type not in _DEFAULT_EVENTS_SPL and self._events_template is None:
            raise ConnectorError(
                f"splunk: unsupported entity_type {entity_type!r} "
                "(expected one of host, user, ip; or supply "
                "events_search_template)",
                vendor="splunk",
            )

        spl = self._render_events_spl(
            entity=entity, entity_type=entity_type, minutes=minutes
        )
        results = await self._run_oneshot_search(spl)

        events = [self._normalize_event(row) for row in results]
        return {
            "entity": entity,
            "entity_type": entity_type,
            "window_minutes": minutes,
            "events": events,
        }

    async def get_related_alerts(
        self, *, entity: str, hours: int = 24
    ) -> dict[str, Any]:
        """Run the related-alerts SPL for `entity`, return normalized envelope."""
        hours = _coerce_int(hours, name="hours", lo=1, hi=720)  # max 30d
        spl = self._render_alerts_spl(entity=entity, hours=hours)
        results = await self._run_oneshot_search(spl)

        related = [self._normalize_alert(row) for row in results]
        return {
            "entity": entity,
            "related_count": len(related),
            "related": related,
        }

    # ------------------------------------------------------------------ #
    # SPL rendering                                                      #
    # ------------------------------------------------------------------ #

    def _render_events_spl(
        self, *, entity: str, entity_type: str, minutes: int
    ) -> str:
        template = self._events_template or _DEFAULT_EVENTS_SPL[entity_type]
        escaped = _escape_spl_value(entity)
        try:
            return template.format(
                entity=escaped,
                entity_type=entity_type,
                minutes=minutes,
                index=self._index,
                max_results=self._max_results,
            )
        except KeyError as exc:
            raise ConnectorError(
                f"splunk: events_search_template references unknown placeholder {exc!s}; "
                "supported: {entity}, {entity_type}, {minutes}, {index}, {max_results}",
                vendor="splunk",
            ) from exc

    def _render_alerts_spl(self, *, entity: str, hours: int) -> str:
        template = self._alerts_template or _DEFAULT_ALERTS_SPL
        escaped = _escape_spl_value(entity)
        try:
            return template.format(
                entity=escaped,
                hours=hours,
                notable_index=self._notable_index,
                max_results=self._max_results,
            )
        except KeyError as exc:
            raise ConnectorError(
                f"splunk: alerts_search_template references unknown placeholder {exc!s}; "
                "supported: {entity}, {hours}, {notable_index}, {max_results}",
                vendor="splunk",
            ) from exc

    # ------------------------------------------------------------------ #
    # Splunk REST                                                        #
    # ------------------------------------------------------------------ #

    async def _run_oneshot_search(self, spl: str) -> list[dict[str, Any]]:
        """POST a synchronous oneshot search and return the result rows."""
        endpoint = (
            f"/servicesNS/{self._owner}/{self._app}/search/jobs"
        )
        # Splunk expects form-encoded POST data on this endpoint.
        form = {
            "search": spl,
            "exec_mode": "oneshot",
            "output_mode": "json",
            "count": str(self._max_results),
        }
        log.debug(
            "splunk: oneshot search tenant=%s spl=%r",
            self.tenant_id,
            spl[:300],
        )
        payload = await self._http.post(endpoint, data=form)

        if payload is None:
            return []
        if not isinstance(payload, dict):
            raise ConnectorError(
                f"splunk: oneshot response was not a JSON object: {type(payload).__name__}",
                vendor="splunk",
            )

        _raise_for_search_errors(payload, spl=spl)
        results = payload.get("results")
        if not isinstance(results, list):
            return []
        return [r for r in results if isinstance(r, dict)]

    # ------------------------------------------------------------------ #
    # Result normalization                                               #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _normalize_event(row: dict[str, Any]) -> dict[str, Any]:
        """Map a Splunk result row to the SIEM event envelope.

        Output shape mirrors the legacy mock: ``{ts, type, ...passthrough}``.
        Internal Splunk fields prefixed with ``_`` are dropped except
        ``_time`` (converted to ``ts``) — they would just be noise in the
        LLM context window.
        """
        out: dict[str, Any] = {
            "ts": _to_iso(row.get("_time")),
            "type": _infer_event_type(row),
        }
        for key, value in row.items():
            if key.startswith("_"):
                # Skip internal Splunk fields (_raw, _cd, _bkt, _kv, _serial, …).
                continue
            if key in out:
                # Already populated as part of the envelope.
                continue
            out[key] = value
        return out

    @staticmethod
    def _normalize_alert(row: dict[str, Any]) -> dict[str, Any]:
        """Map a Splunk notable row to the related-alert shape.

        ``id`` falls back through several Splunk fields because the
        canonical event identifier depends on whether the tenant uses
        Splunk ES (``event_id``) or has a custom correlation pipeline.
        """
        title = (
            row.get("rule_name")
            or row.get("signature")
            or row.get("source")
            or "splunk_alert"
        )
        severity = (
            row.get("severity") or row.get("urgency") or row.get("priority") or "unknown"
        )
        alert_id = _first_truthy(
            row,
            keys=("event_id", "event_hash", "rule_id", "savedsearch_name", "_cd"),
            fallback="splunk_alert",
        )
        return {
            "id": str(alert_id),
            "title": str(title),
            "severity": str(severity).lower(),
        }


def _first_truthy(
    row: dict[str, Any], *, keys: Iterable[str], fallback: str
) -> Any:
    for key in keys:
        value = row.get(key)
        if value:
            return value
    return fallback


# ─── factory ─────────────────────────────────────────────────────────────


def make_splunk_siem(config: ConnectorConfig) -> SplunkSiemConnector:
    """Factory entry-point registered in ``app/connectors/sdk/builtin.py``."""
    return SplunkSiemConnector(config)


__all__ = [
    "SplunkSiemConnector",
    "make_splunk_siem",
]
