"""CrowdStrike Falcon EDR connector.

Implements ``BaseEdrConnector`` against the Falcon REST APIs. Falcon
has multiple regional clouds — tenants pick the right ``base_url`` for
their tenant's home cloud:

  * US-1:        ``https://api.crowdstrike.com``
  * US-2:        ``https://api.us-2.crowdstrike.com``
  * EU-1:        ``https://api.eu-1.crowdstrike.com``
  * US-GovCloud: ``https://api.laggar.gcw.crowdstrike.com``

The auth flow is identical across all of them — OAuth 2.0
client_credentials at ``/oauth2/token``. Tokens are short-lived
(~30m); ``OAuthClientCredentials`` caches and refreshes lazily.

API mapping
-----------
Each operation routes to the Falcon REST endpoint that most closely
matches what an analyst would expect from the action verb.

``isolate_host`` / ``release_host``
    POST ``/devices/entities/devices-actions/v2`` with
    ``action_name=contain`` / ``lift_containment``. This is Falcon's
    "Network Containment" feature — the host stays online from the
    sensor's perspective but loses all non-Falcon network access.

``quarantine_file``
    POST ``/iocs/entities/indicators/v1`` (Custom IOC V2 API). Adds
    the SHA-256 to the tenant's custom IOC list with ``action=prevent``
    and ``severity=high``. Falcon Sensor blocks future execution and
    quarantines existing copies on hosts that report the hash.

``get_process_tree``
    Falcon does not have a single "give me a host's full process
    table" REST endpoint — that requires Real-Time Response (RTR) and
    runs a live ``ps`` on the host. For v1, we use the *Detections*
    API: query recent detections for the host, then reconstruct a
    tree from ``behaviors[]`` using ``parent_details.parent_process_id``
    edges. This gives the analyst the tree as Falcon flagged it, which
    is what they're typically asking for during triage. Hosts with no
    detections in the window return an empty tree.

``kill_process``
    Real-Time Response (RTR) admin command. Three-phase: open session,
    issue ``kill {pid}``, poll for completion, close session. RTR
    sessions are billed; we always close them in a ``finally`` block
    even on failure.

FQL injection
-------------
Falcon's filter language (FQL) uses single-quoted string literals.
Entity values (host, process name) reach this connector from alert
payloads and LLM-extracted strings. We defensively:

  1. Reject control characters and NULs in the raw value.
  2. Escape backslashes and single-quotes for safe interpolation.
  3. Always wrap the value in single quotes in the rendered FQL.

Device IDs (AIDs) are 32-char hex; we validate the shape and trust
the value if it matches.

Config (``params``)
-------------------
* ``base_url``                — Falcon cloud URL (HTTPS). Required.
* ``read_timeout_s``          — Per-request read timeout. Default ``60``.
* ``verify_tls``              — Verify TLS certs. Default ``True``.
* ``detection_window_hours``  — How far back to search for detections
                                 when building a process tree. Default
                                 ``24``. Capped at ``720`` (30d).
* ``rtr_poll_timeout_s``      — Max seconds to wait for an RTR command
                                 to complete. Default ``30``.
* ``rtr_poll_interval_s``     — Seconds between RTR poll attempts.
                                 Default ``0.5``.

Config (``secrets``)
--------------------
* ``client_id``     — Falcon API client ID.
* ``client_secret`` — Falcon API client secret.

Required Falcon API scopes (set on the API client in the Falcon
console):
  * Hosts: Read & Write       — isolate / release
  * Detections: Read          — process tree reconstruction
  * IOC Management: Write     — quarantine_file
  * Real-Time Response (Admin): Write — kill_process
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from app.connectors.sdk.base import (
    ConnectorConfig,
    ConnectorError,
    ConnectorTimeoutError,
)
from app.connectors.sdk.http import AsyncHttpClient, OAuthClientCredentials
from app.connectors.sdk.protocols import BaseEdrConnector

log = logging.getLogger(__name__)


# ─── constants ───────────────────────────────────────────────────────────

# Falcon Agent IDs (AIDs) are 32 lowercase hex chars. Most Falcon UIs
# uppercase them in displays, but the REST API stores and returns
# lowercase — we normalise on the way in.
_AID_RE = re.compile(r"^[0-9a-f]{32}$")

# SHA-256: 64 hex chars (case-insensitive).
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Hostnames Falcon accepts are roughly RFC 1123 — letters, digits,
# dots, hyphens, underscores. We're permissive but reject anything
# with control characters or quoting metacharacters.
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x1f\x7f]")


# ─── helpers ─────────────────────────────────────────────────────────────


def _escape_fql_value(value: str, *, field: str) -> str:
    """Escape `value` for safe interpolation into a single-quoted FQL literal.

    FQL string literals use single quotes (e.g. ``hostname:'host01'``).
    Backslash and single-quote are the two metacharacters that need
    escaping. We reject control characters outright rather than try
    to sanitise CR/LF injection.
    """
    if not isinstance(value, str):
        raise ConnectorError(
            f"crowdstrike: {field} must be a string (got {type(value).__name__})",
            vendor="crowdstrike",
        )
    if not value:
        raise ConnectorError(
            f"crowdstrike: empty {field} rejected",
            vendor="crowdstrike",
        )
    if _FORBIDDEN_CHARS.search(value):
        raise ConnectorError(
            f"crowdstrike: {field} {value!r} contains control characters",
            vendor="crowdstrike",
        )
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _coerce_int(value: Any, *, name: str, lo: int, hi: int) -> int:
    """Bound check + cast for integers ingested from external callers."""
    try:
        as_int = int(value)
    except (TypeError, ValueError) as exc:
        raise ConnectorError(
            f"crowdstrike: {name} must be an integer (got {value!r})",
            vendor="crowdstrike",
        ) from exc
    if as_int < lo or as_int > hi:
        raise ConnectorError(
            f"crowdstrike: {name}={as_int} out of range [{lo}, {hi}]",
            vendor="crowdstrike",
        )
    return as_int


def _safe_int(value: Any) -> int | None:
    """Best-effort int conversion. Returns None for unparseable values.

    Falcon sometimes returns PIDs as strings, sometimes as numbers,
    occasionally missing entirely. We surface the parsed int when we
    can; the LLM tolerates ``None`` in tree nodes better than a fake
    zero.
    """
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _raise_for_falcon_errors(
    payload: Any, *, operation: str, host: str | None = None
) -> None:
    """Surface Falcon-style inline errors as typed ``ConnectorError``.

    Falcon REST responses follow a consistent envelope:

        {
          "meta": {...},
          "resources": [...],
          "errors": [{"code": 400, "message": "..."}]
        }

    Some 2xx responses still carry non-empty ``errors`` (e.g. partial
    action failures on multi-target requests). Anything in ``errors``
    is fatal from our perspective — we surface the first message and
    abort.
    """
    if not isinstance(payload, dict):
        return
    errors = payload.get("errors") or []
    if not errors or not isinstance(errors, list):
        return
    first = errors[0] if isinstance(errors[0], dict) else {}
    code = first.get("code")
    message = first.get("message") or str(first) or "unknown falcon error"
    host_part = f" host={host}" if host else ""
    raise ConnectorError(
        f"crowdstrike: {operation} failed (code={code}){host_part}: {message}",
        vendor="crowdstrike",
        status=int(code) if isinstance(code, int) else None,
    )


# ─── connector ───────────────────────────────────────────────────────────


class CrowdStrikeEdrConnector(BaseEdrConnector):
    """CrowdStrike Falcon EDR via Falcon REST + RTR APIs.

    Each instance owns one ``AsyncHttpClient`` against the configured
    Falcon cloud. The OAuth client_credentials token is cached in the
    auth strategy; repeated tool calls for the same tenant reuse one
    HTTP pool and one access token.
    """

    vendor = "crowdstrike"

    def __init__(self, config: ConnectorConfig) -> None:
        super().__init__(config)

        base_url = config.param("base_url")
        if not base_url or not isinstance(base_url, str):
            raise ConnectorError(
                "crowdstrike: missing required param 'base_url' "
                "(e.g. https://api.crowdstrike.com)",
                vendor="crowdstrike",
            )
        # Falcon API is HTTPS only. Refuse plain HTTP early — credentials
        # would otherwise leak in transit.
        if not base_url.startswith("https://"):
            raise ConnectorError(
                f"crowdstrike: base_url must be https (got {base_url!r})",
                vendor="crowdstrike",
            )
        self._base_url = base_url.rstrip("/")

        self._detection_hours = _coerce_int(
            config.param("detection_window_hours") or 24,
            name="detection_window_hours",
            lo=1,
            hi=720,
        )
        self._rtr_poll_timeout = float(
            config.param("rtr_poll_timeout_s") or 30.0
        )
        self._rtr_poll_interval = float(
            config.param("rtr_poll_interval_s") or 0.5
        )
        read_timeout = float(config.param("read_timeout_s") or 60.0)
        verify_tls = bool(config.param("verify_tls", True))

        client_id = config.secret("client_id")
        client_secret = config.secret("client_secret")

        # Falcon's token endpoint accepts only ``grant_type``,
        # ``client_id``, and ``client_secret`` — no scope param.
        auth = OAuthClientCredentials(
            token_url=f"{self._base_url}/oauth2/token",
            client_id=client_id,
            client_secret=client_secret,
        )

        self._http = AsyncHttpClient(
            base_url=self._base_url,
            auth=auth,
            timeout=httpx.Timeout(
                connect=10.0, read=read_timeout, write=10.0, pool=5.0
            ),
            vendor="crowdstrike",
            verify=verify_tls,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )

    # ------------------------------------------------------------------ #
    # Lifecycle                                                          #
    # ------------------------------------------------------------------ #

    async def aclose(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------ #
    # Health                                                             #
    # ------------------------------------------------------------------ #

    async def health_check(self) -> dict[str, Any]:
        """Probe ``/devices/queries/devices/v1`` with limit=1.

        Verifies the OAuth token works and the API client has at
        least Hosts: Read scope. Returns the tenant's visible device
        count for operator sanity-checking.
        """
        payload = await self._http.get(
            "/devices/queries/devices/v1",
            params={"limit": 1},
        )
        _raise_for_falcon_errors(payload, operation="health_check")
        meta = (payload or {}).get("meta") or {}
        pagination = meta.get("pagination") or {}
        return {
            "ok": True,
            "vendor": self.vendor,
            "kind": self.kind.value,
            "devices_total": pagination.get("total"),
        }

    # ------------------------------------------------------------------ #
    # Public protocol surface                                            #
    # ------------------------------------------------------------------ #

    async def get_process_tree(
        self, *, host: str, process_name: str | None = None
    ) -> dict[str, Any]:
        """Reconstruct a process tree from recent detections on `host`.

        We resolve ``host`` → AID, then query the Detections API for
        any detection touching this AID in the configured window.
        Each detection carries one or more ``behaviors[]`` entries
        with ``process_id``, ``parent_details.parent_process_id``,
        and ``filename`` — we link those into a forest of trees.

        ``process_name`` narrows the FQL filter when provided; without
        it we fetch all detection behaviors in the window.

        Empty result on hosts with no detections — that's the honest
        signal, not a failure.
        """
        device_id = await self._resolve_device_id(host)

        # Build FQL. Falcon FQL uses '+' as AND between predicates.
        since = datetime.now(timezone.utc) - timedelta(
            hours=self._detection_hours
        )
        # FQL timestamp form: ISO-8601 UTC with seconds, no microseconds.
        since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        fql_parts = [
            f"device.device_id:'{device_id}'",
            f"behaviors.timestamp:>='{since_iso}'",
        ]
        if process_name:
            pname_esc = _escape_fql_value(process_name, field="process_name")
            # Falcon supports substring match via ``*pattern*``.
            fql_parts.append(f"behaviors.filename:*'{pname_esc}'*")
        fql = "+".join(fql_parts)

        query_resp = await self._http.get(
            "/detects/queries/detects/v1",
            params={"filter": fql, "limit": 50},
        )
        _raise_for_falcon_errors(
            query_resp, operation="get_process_tree.query", host=host
        )
        detection_ids = (query_resp or {}).get("resources") or []
        if not detection_ids:
            return {"host": host, "tree": []}

        summary_resp = await self._http.post(
            "/detects/entities/summaries/GET/v1",
            json={"ids": detection_ids},
        )
        _raise_for_falcon_errors(
            summary_resp, operation="get_process_tree.summaries", host=host
        )
        summaries = (summary_resp or {}).get("resources") or []
        tree = _behaviors_to_tree(summaries)
        return {"host": host, "tree": tree}

    async def isolate_host(self, *, host: str, reason: str) -> dict[str, Any]:
        """Network-contain `host` via Falcon Hosts API.

        Returns the mock-compatible envelope:
        ``{host, isolated: True, reason, ticket}``. ``ticket`` is
        synthesised from Falcon's per-request ``trace_id`` so the audit
        log can be cross-referenced in the Falcon UI.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ConnectorError(
                "crowdstrike: isolate_host requires a non-empty reason",
                vendor="crowdstrike",
            )
        device_id = await self._resolve_device_id(host)
        trace_id = await self._device_action(
            device_id=device_id, action_name="contain", host=host
        )
        return {
            "host": host,
            "isolated": True,
            "reason": reason,
            "ticket": _make_ticket("ISO", trace_id, device_id),
        }

    async def release_host(self, *, host: str) -> dict[str, Any]:
        """Reverse a prior `isolate_host`.

        Falcon's ``lift_containment`` action is the symmetric reverse
        of ``contain``. Returns ``{host, isolated: False, ticket}``.
        """
        device_id = await self._resolve_device_id(host)
        trace_id = await self._device_action(
            device_id=device_id, action_name="lift_containment", host=host
        )
        return {
            "host": host,
            "isolated": False,
            "ticket": _make_ticket("REL", trace_id, device_id),
        }

    async def quarantine_file(self, *, sha256: str) -> dict[str, Any]:
        """Add `sha256` to the tenant's Custom IOC list, action=prevent.

        Falcon Sensor blocks future execution on every host and
        quarantines existing copies on hosts that report the hash via
        telemetry. We don't get an exact "endpoints affected" number
        synchronously — Falcon emits that as detections asynchronously
        — so we report ``quarantined_on_endpoints`` as the count of
        successfully-created IOC records (i.e. ``1`` on success).
        """
        if not isinstance(sha256, str) or not _SHA256_RE.match(sha256):
            raise ConnectorError(
                f"crowdstrike: invalid sha256 {sha256!r} "
                "(expected 64 hex chars)",
                vendor="crowdstrike",
            )
        normalised = sha256.lower()
        body = {
            "indicators": [
                {
                    "type": "sha256",
                    "value": normalised,
                    "action": "prevent",
                    "severity": "high",
                    "platforms": ["windows", "mac", "linux"],
                    "applied_globally": True,
                    "source": "cyble-aisoc",
                }
            ]
        }
        resp = await self._http.post(
            "/iocs/entities/indicators/v1",
            json=body,
        )
        _raise_for_falcon_errors(resp, operation="quarantine_file")
        resources = (resp or {}).get("resources") or []
        # The IOC API returns one resource per submitted indicator on
        # success. Failed indicators show up in `errors` (already
        # surfaced above).
        created = len(resources) if isinstance(resources, list) else 0
        ioc_id = ""
        if created and isinstance(resources[0], dict):
            ioc_id = str(resources[0].get("id") or "")
        return {
            "sha256": normalised,
            "quarantined_on_endpoints": created,
            "ticket": f"QUA-{(ioc_id or normalised)[:8]}",
        }

    async def kill_process(self, *, host: str, pid: int) -> dict[str, Any]:
        """Terminate `pid` on `host` via Real-Time Response.

        Three-phase RTR flow: init session, issue admin ``kill`` command,
        poll for completion. The session is always closed in a
        ``finally`` block — RTR sessions are billed and orphaned
        sessions consume per-tenant capacity.
        """
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            raise ConnectorError(
                f"crowdstrike: pid must be a positive integer (got {pid!r})",
                vendor="crowdstrike",
            )
        device_id = await self._resolve_device_id(host)

        session_resp = await self._http.post(
            "/real-time-response/entities/sessions/v1",
            json={"device_id": device_id},
        )
        _raise_for_falcon_errors(
            session_resp, operation="kill_process.session_init", host=host
        )
        session_resources = (session_resp or {}).get("resources") or []
        if not session_resources or not isinstance(session_resources[0], dict):
            raise ConnectorError(
                f"crowdstrike: RTR session init returned no resources for {host}",
                vendor="crowdstrike",
            )
        session_id = session_resources[0].get("session_id")
        if not session_id:
            raise ConnectorError(
                "crowdstrike: RTR session_id missing in init response",
                vendor="crowdstrike",
            )

        try:
            cmd_resp = await self._http.post(
                "/real-time-response/entities/admin-command/v1",
                json={
                    "base_command": "kill",
                    "command_string": f"kill {pid}",
                    "session_id": session_id,
                },
            )
            _raise_for_falcon_errors(
                cmd_resp, operation="kill_process.command", host=host
            )
            cmd_resources = (cmd_resp or {}).get("resources") or []
            if not cmd_resources or not isinstance(cmd_resources[0], dict):
                raise ConnectorError(
                    "crowdstrike: RTR kill returned no resources",
                    vendor="crowdstrike",
                )
            cloud_request_id = cmd_resources[0].get("cloud_request_id")
            if not cloud_request_id:
                raise ConnectorError(
                    "crowdstrike: RTR cloud_request_id missing in command response",
                    vendor="crowdstrike",
                )

            poll_started = time.monotonic()
            while True:
                poll = await self._http.get(
                    "/real-time-response/entities/admin-command/v1",
                    params={
                        "cloud_request_id": cloud_request_id,
                        "sequence_id": 0,
                    },
                )
                _raise_for_falcon_errors(
                    poll, operation="kill_process.poll", host=host
                )
                presources = (poll or {}).get("resources") or []
                if presources and isinstance(presources[0], dict):
                    if presources[0].get("complete"):
                        stderr = (presources[0].get("stderr") or "").strip()
                        if stderr:
                            raise ConnectorError(
                                f"crowdstrike: RTR kill stderr for {host} "
                                f"pid={pid}: {stderr[:200]}",
                                vendor="crowdstrike",
                            )
                        return {"host": host, "pid": pid, "terminated": True}
                if time.monotonic() - poll_started >= self._rtr_poll_timeout:
                    raise ConnectorTimeoutError(
                        f"crowdstrike: RTR kill timed out after "
                        f"{self._rtr_poll_timeout}s "
                        f"(host={host} pid={pid})",
                        vendor="crowdstrike",
                    )
                await asyncio.sleep(self._rtr_poll_interval)
        finally:
            # Best-effort session close. We swallow errors here because
            # the kill outcome is what the caller cares about; an
            # orphaned session will be reaped by Falcon after its TTL.
            try:
                await self._http.delete(
                    "/real-time-response/entities/sessions/v1",
                    params={"session_id": session_id},
                )
            except Exception:  # pragma: no cover - best-effort cleanup
                log.debug(
                    "crowdstrike: RTR session close failed for %s",
                    session_id,
                    exc_info=True,
                )

    # ------------------------------------------------------------------ #
    # Internal helpers                                                   #
    # ------------------------------------------------------------------ #

    async def _resolve_device_id(self, host: str) -> str:
        """Resolve `host` (hostname or AID) to a Falcon AID.

        AIDs are 32-char lowercase hex. If `host` already matches that
        shape, we trust it without a round-trip; otherwise we query
        ``/devices/queries/devices/v1`` with a hostname filter.

        Raises ``ConnectorError`` if the host is unknown — better to
        surface "not found" early than to invoke an action against a
        ghost AID.
        """
        if not isinstance(host, str) or not host:
            raise ConnectorError(
                "crowdstrike: host must be a non-empty string",
                vendor="crowdstrike",
            )
        lowered = host.lower()
        if _AID_RE.match(lowered):
            return lowered
        escaped = _escape_fql_value(host, field="host")
        fql = f"hostname:'{escaped}'"
        payload = await self._http.get(
            "/devices/queries/devices/v1",
            params={"filter": fql, "limit": 1},
        )
        _raise_for_falcon_errors(
            payload, operation="resolve_device_id", host=host
        )
        resources = (payload or {}).get("resources") or []
        if not resources:
            raise ConnectorError(
                f"crowdstrike: host {host!r} not found in Falcon",
                vendor="crowdstrike",
                status=404,
            )
        aid = resources[0] if isinstance(resources[0], str) else None
        if not aid or not _AID_RE.match(aid):
            raise ConnectorError(
                f"crowdstrike: malformed AID in resolve response: {aid!r}",
                vendor="crowdstrike",
            )
        return aid

    async def _device_action(
        self, *, device_id: str, action_name: str, host: str
    ) -> str:
        """Run a Falcon device action (contain / lift_containment).

        Returns the response trace_id which we surface in the synthetic
        ticket value. Falcon emits one ``resources`` entry per device
        on success; failures show up in ``errors``.
        """
        resp = await self._http.post(
            "/devices/entities/devices-actions/v2",
            params={"action_name": action_name},
            json={"ids": [device_id]},
        )
        _raise_for_falcon_errors(resp, operation=action_name, host=host)
        meta = (resp or {}).get("meta") or {}
        trace_id = meta.get("trace_id") or ""
        return str(trace_id)


# ─── tree reconstruction ────────────────────────────────────────────────


def _behaviors_to_tree(
    summaries: list[Any],
) -> list[dict[str, Any]]:
    """Flatten detection summaries into a parent-linked process forest.

    Falcon's ``behaviors[]`` array on a detection summary has the
    following shape (abbreviated):

        {
          "behavior_id": "...",
          "process_id": "12345",
          "filename": "powershell.exe",
          "cmdline": "powershell -EncodedCommand ...",
          "user_name": "tina.lee",
          "parent_details": {"parent_process_id": "5240", ...},
        }

    We:
      1. Build a flat dict keyed by ``process_id``.
      2. Link children to parents via ``parent_details.parent_process_id``.
      3. Return the roots (processes whose parent is not in the set).

    Falcon may surface the same ``process_id`` across multiple
    detections; we keep the first occurrence to avoid duplicates.
    """
    nodes: dict[str, dict[str, Any]] = {}
    parent_of: dict[str, str] = {}

    for det in summaries:
        if not isinstance(det, dict):
            continue
        behaviors = det.get("behaviors") or []
        if not isinstance(behaviors, list):
            continue
        for beh in behaviors:
            if not isinstance(beh, dict):
                continue
            pid_str = str(beh.get("process_id") or "").strip()
            if not pid_str or pid_str in nodes:
                continue
            parent_details = beh.get("parent_details") or {}
            parent_pid_str = (
                str(parent_details.get("parent_process_id") or "").strip()
                if isinstance(parent_details, dict)
                else ""
            )
            node: dict[str, Any] = {
                "pid": _safe_int(beh.get("process_id")),
                "name": str(beh.get("filename") or "unknown"),
                "cmdline": str(beh.get("cmdline") or ""),
                "user": str(beh.get("user_name") or ""),
                # Behaviors only fire on detection — by definition the
                # process showed up in a detection, so we flag it
                # suspicious. Analysts see this lit up in narratives.
                "suspicious": True,
                "children": [],
            }
            nodes[pid_str] = node
            if parent_pid_str:
                parent_of[pid_str] = parent_pid_str

    roots: list[dict[str, Any]] = []
    for pid_str, node in nodes.items():
        parent_pid = parent_of.get(pid_str)
        if parent_pid and parent_pid in nodes:
            nodes[parent_pid]["children"].append(node)
        else:
            roots.append(node)
    return roots


def _make_ticket(prefix: str, trace_id: str, device_id: str) -> str:
    """Synthesise an opaque ticket id for audit trails.

    Falcon's per-request ``trace_id`` is the highest-quality
    cross-reference for the audit log — analysts can paste it into
    Falcon support. We fall back to a slice of the AID when Falcon
    doesn't return a trace_id (test transports, very old API versions).
    """
    fragment = (trace_id or "").replace("-", "")[:8] or device_id[:8] or "unknown"
    return f"{prefix}-{fragment}"


# ─── factory ─────────────────────────────────────────────────────────────


def make_crowdstrike_edr(config: ConnectorConfig) -> CrowdStrikeEdrConnector:
    """Factory entry-point registered in ``app/connectors/sdk/builtin.py``."""
    return CrowdStrikeEdrConnector(config)


__all__ = [
    "CrowdStrikeEdrConnector",
    "make_crowdstrike_edr",
]
