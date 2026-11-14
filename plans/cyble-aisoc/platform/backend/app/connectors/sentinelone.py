"""SentinelOne EDR connector.

Implements ``BaseEdrConnector`` against the SentinelOne Management API
(``v2.1``). SentinelOne tenants live in regional management consoles —
the customer supplies their management URL as ``base_url``:

  * US:           ``https://usea1-partners.sentinelone.net``
  * EU:           ``https://eu1-018.sentinelone.net``
  * Multi-tenant: ``https://<tenant>.sentinelone.net``

Auth
----
SentinelOne uses a long-lived **API token** (created in the Mgmt
console under ``Settings → Users → API Token``). The token is sent as
``Authorization: ApiToken <token>`` on every request — there is no
OAuth refresh flow. We use the SDK's ``ApiKeyAuth`` for this.

The token is scoped to the issuing user's roles; the tenant operator
should provision a service-account user with at minimum:

  * Agents: View, Disconnect, Connect
  * Threats: View, Mitigate (Kill)
  * Restrictions (Blacklist): View, Manage

API mapping
-----------
Each operation routes to the SentinelOne endpoint that most closely
matches what an analyst expects from the action verb.

``isolate_host`` / ``release_host``
    POST ``/web/api/v2.1/agents/actions/disconnect`` /
    ``…/connect``. This is SentinelOne's "Disconnect from Network"
    feature — the agent stays online from S1's perspective but loses
    all non-S1 network access. Same envelope shape as ``contain`` /
    ``lift_containment`` in CrowdStrike.

``quarantine_file``
    POST ``/web/api/v2.1/restrictions``. Adds the SHA-256 hash to the
    tenant-wide blacklist with ``type=black_hash`` for each requested
    OS type. SentinelOne blocks future execution and quarantines
    existing copies on every connected agent. SentinelOne historically
    used SHA-1 for blacklists; modern consoles (≥4.x) accept SHA-256
    natively. We always submit SHA-256 — operators on legacy consoles
    will surface a per-request error from the API, which we forward
    verbatim.

``get_process_tree``
    SentinelOne does not expose a generic "give me a host's full
    process table" endpoint — that requires the Deep Visibility query
    API (a paid SKU). For v1, we use the *Threats* API: query recent
    threats for the agent and reconstruct a tree from each threat's
    ``threatInfo`` block using
    ``originatingProcessId`` + ``parentProcessName`` /
    ``parentProcessUniqueKey`` edges. This gives the analyst the tree
    as SentinelOne flagged it — what they typically want during
    triage. Hosts with no threats in the window return an empty tree.

``kill_process``
    SentinelOne's Mgmt API does **not** support arbitrary PID kill in
    the way CrowdStrike RTR does — kill is always scoped to a
    detected threat. We look up unmitigated threats on the host that
    reference ``pid`` (via ``threatInfo.processId`` or
    ``threatInfo.originatingProcessId``) and call
    ``/web/api/v2.1/threats/mitigate/kill`` against the matching
    threat ids. If no associated threat exists, we surface
    ``ConnectorError`` rather than silently no-oping — operators
    should escalate to a manual RTR command via the SentinelOne
    Console for that case.

Query parameter hygiene
-----------------------
SentinelOne uses standard HTTP query params (no FQL-style DSL), so
the injection surface is small — the API itself takes care of
escaping. We still:

  1. Reject control characters in entity values (hostname, paths) —
     the API would tolerate them but they break logs.
  2. Validate AID format (numeric string, 18+ chars) before trusting
     "looks-like-an-AID" inputs.
  3. Bound numeric inputs (pid, window hours) to plausible ranges.

Config (``params``)
-------------------
* ``base_url``                 — S1 mgmt URL (HTTPS). Required.
* ``read_timeout_s``           — Per-request read timeout. Default ``60``.
* ``verify_tls``               — Verify TLS certs. Default ``True``.
* ``threat_window_hours``      — Lookback for threats when building a
                                  process tree or finding a kill
                                  target. Default ``24``. Capped at
                                  ``720`` (30d).
* ``site_ids``                 — Optional comma-separated S1 site IDs
                                  to scope queries. Useful for MSSPs
                                  with multi-site tenants.
* ``account_ids``              — Optional comma-separated S1 account
                                  IDs. Same purpose, broader scope.
* ``quarantine_os_types``      — OS types to blacklist on. Default
                                  ``["windows", "macos", "linux"]``.

Config (``secrets``)
--------------------
* ``api_token``                — SentinelOne API user token.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import httpx

from app.connectors.sdk.base import (
    ConnectorConfig,
    ConnectorError,
)
from app.connectors.sdk.http import ApiKeyAuth, AsyncHttpClient
from app.connectors.sdk.protocols import BaseEdrConnector

log = logging.getLogger(__name__)


# ─── constants ───────────────────────────────────────────────────────────

# SentinelOne agent IDs are large numeric strings (typically 18-19
# digits, e.g. ``"987432129573467890"``). We accept ``8..32`` digits
# defensively; the API itself will reject malformed IDs.
_AID_RE = re.compile(r"^[0-9]{8,32}$")

# SHA-256: 64 hex chars (case-insensitive).
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# SentinelOne threat IDs are alphanumeric (Mongo-style). Keep
# permissive — 12..40 chars, no separators we'd care about.
_THREAT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")

# Control characters in entity values are rejected outright to keep
# log lines and audit trails legible.
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x1f\x7f]")

# OS types accepted by the S1 blacklist API.
_VALID_OS_TYPES = frozenset({"windows", "macos", "linux"})


# ─── helpers ─────────────────────────────────────────────────────────────


def _check_entity_value(value: str, *, field: str) -> str:
    """Reject empty / non-str / control-char values used in query params.

    Returns ``value`` unchanged on success — purely a validation hook.
    SentinelOne's HTTP layer handles standard URL escaping; we don't
    need to do FQL-style quote escaping like CrowdStrike.
    """
    if not isinstance(value, str):
        raise ConnectorError(
            f"sentinelone: {field} must be a string "
            f"(got {type(value).__name__})",
            vendor="sentinelone",
        )
    if not value.strip():
        raise ConnectorError(
            f"sentinelone: empty {field} rejected",
            vendor="sentinelone",
        )
    if _FORBIDDEN_CHARS.search(value):
        raise ConnectorError(
            f"sentinelone: {field} {value!r} contains control characters",
            vendor="sentinelone",
        )
    return value


def _coerce_int(value: Any, *, name: str, lo: int, hi: int) -> int:
    """Bound check + cast for integers ingested from external callers."""
    try:
        as_int = int(value)
    except (TypeError, ValueError) as exc:
        raise ConnectorError(
            f"sentinelone: {name} must be an integer (got {value!r})",
            vendor="sentinelone",
        ) from exc
    if as_int < lo or as_int > hi:
        raise ConnectorError(
            f"sentinelone: {name}={as_int} out of range [{lo}, {hi}]",
            vendor="sentinelone",
        )
    return as_int


def _safe_int(value: Any) -> int | None:
    """Best-effort int conversion. Returns None for unparseable values.

    SentinelOne's threat payloads sometimes serialise PIDs as strings,
    sometimes as numbers. ``None`` is the honest signal when a field
    is genuinely absent — the LLM tolerates ``None`` in tree nodes
    better than a synthetic zero.
    """
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _raise_for_s1_errors(
    payload: Any, *, operation: str, host: str | None = None
) -> None:
    """Surface inline ``errors[]`` entries as typed ``ConnectorError``.

    SentinelOne 2xx responses normally have shape::

        {"data": ..., "pagination": {...}}

    Failures show up either as non-2xx (handled by ``AsyncHttpClient``)
    or as a 2xx with::

        {"errors": [{"code": "...", "detail": "...", "title": "..."}]}

    The second form is what we guard against here — partial successes
    on multi-target actions land in this bucket.
    """
    if not isinstance(payload, dict):
        return
    errors = payload.get("errors") or []
    if not errors or not isinstance(errors, list):
        return
    first = errors[0] if isinstance(errors[0], dict) else {}
    code = first.get("code")
    message = (
        first.get("detail")
        or first.get("title")
        or first.get("message")
        or str(first)
        or "unknown sentinelone error"
    )
    host_part = f" host={host}" if host else ""
    raise ConnectorError(
        f"sentinelone: {operation} failed (code={code}){host_part}: "
        f"{message}",
        vendor="sentinelone",
        status=int(code) if isinstance(code, int) else None,
    )


def _normalise_os_types(raw: Any) -> list[str]:
    """Coerce ``quarantine_os_types`` config into a validated list.

    Defaults to all three platforms. Strings get split on commas so
    operators can paste ``"windows,macos"`` straight into config.
    """
    if raw is None:
        return ["windows", "macos", "linux"]
    if isinstance(raw, str):
        items = [s.strip() for s in raw.split(",") if s.strip()]
    elif isinstance(raw, (list, tuple)):
        items = [str(s).strip() for s in raw if str(s).strip()]
    else:
        raise ConnectorError(
            f"sentinelone: quarantine_os_types must be a list or "
            f"comma-string (got {type(raw).__name__})",
            vendor="sentinelone",
        )
    if not items:
        return ["windows", "macos", "linux"]
    lowered = [s.lower() for s in items]
    invalid = [s for s in lowered if s not in _VALID_OS_TYPES]
    if invalid:
        raise ConnectorError(
            f"sentinelone: invalid quarantine_os_types {invalid!r} "
            f"(allowed: {sorted(_VALID_OS_TYPES)})",
            vendor="sentinelone",
        )
    # De-dupe while preserving order.
    seen: set[str] = set()
    return [s for s in lowered if not (s in seen or seen.add(s))]


def _csv_param(raw: Any) -> str | None:
    """Normalise a ``site_ids``/``account_ids`` param to a CSV string.

    Accepts a list or a string; returns ``None`` when unconfigured so
    callers can decide whether to attach the query param at all.
    """
    if raw is None or raw == "":
        return None
    if isinstance(raw, (list, tuple)):
        items = [str(s).strip() for s in raw if str(s).strip()]
    else:
        items = [s.strip() for s in str(raw).split(",") if s.strip()]
    if not items:
        return None
    for item in items:
        if not _AID_RE.match(item):
            raise ConnectorError(
                f"sentinelone: scope id {item!r} must be numeric "
                f"(8..32 digits)",
                vendor="sentinelone",
            )
    return ",".join(items)


# ─── connector ───────────────────────────────────────────────────────────


class SentinelOneEdrConnector(BaseEdrConnector):
    """SentinelOne EDR via the Management API.

    Each instance owns one ``AsyncHttpClient`` against the configured
    S1 management host. The API token is sent as a static
    ``Authorization: ApiToken <token>`` header — no refresh required.
    Repeated tool calls for the same tenant reuse one HTTP pool.
    """

    vendor = "sentinelone"

    def __init__(self, config: ConnectorConfig) -> None:
        super().__init__(config)

        base_url = config.param("base_url")
        if not base_url or not isinstance(base_url, str):
            raise ConnectorError(
                "sentinelone: missing required param 'base_url' "
                "(e.g. https://usea1-partners.sentinelone.net)",
                vendor="sentinelone",
            )
        if not base_url.startswith("https://"):
            raise ConnectorError(
                f"sentinelone: base_url must be https (got {base_url!r})",
                vendor="sentinelone",
            )
        self._base_url = base_url.rstrip("/")

        self._threat_hours = _coerce_int(
            config.param("threat_window_hours") or 24,
            name="threat_window_hours",
            lo=1,
            hi=720,
        )
        self._site_ids = _csv_param(config.param("site_ids"))
        self._account_ids = _csv_param(config.param("account_ids"))
        self._os_types = _normalise_os_types(
            config.param("quarantine_os_types")
        )

        read_timeout = float(config.param("read_timeout_s") or 60.0)
        verify_tls = bool(config.param("verify_tls", True))

        api_token = config.secret("api_token")

        # SentinelOne uses ``Authorization: ApiToken <token>`` — the
        # token is a long-lived bearer-style credential. ``ApiKeyAuth``
        # is the right strategy here (vs ``BearerAuth``) because the
        # scheme prefix differs from the standard ``Bearer ...``.
        auth = ApiKeyAuth(
            header="Authorization",
            value=f"ApiToken {api_token}",
        )

        self._http = AsyncHttpClient(
            base_url=self._base_url,
            auth=auth,
            timeout=httpx.Timeout(
                connect=10.0, read=read_timeout, write=10.0, pool=5.0
            ),
            vendor="sentinelone",
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
        """Probe ``/web/api/v2.1/system/info``.

        ``/system/info`` requires only a valid token and the lowest
        possible role, so it's the canonical "is the token alive"
        endpoint. Falls back to ``/web/api/v2.1/agents/count`` if the
        operator's token can't see ``system/info`` (rare but happens
        with heavily-restricted Site-scoped tokens).
        """
        try:
            payload = await self._http.get("/web/api/v2.1/system/info")
            _raise_for_s1_errors(payload, operation="health_check")
            data = (payload or {}).get("data") or {}
            return {
                "ok": True,
                "vendor": self.vendor,
                "kind": self.kind.value,
                "console_version": data.get("latestAgentVersion") or
                data.get("version"),
            }
        except ConnectorError:
            # Fall back to a smaller-scope probe before declaring
            # failure — Site-scoped tokens can hit /agents/count but
            # not /system/info.
            params: dict[str, Any] = {"limit": 1}
            self._attach_scope(params)
            payload = await self._http.get(
                "/web/api/v2.1/agents", params=params
            )
            _raise_for_s1_errors(
                payload, operation="health_check.fallback"
            )
            pagination = (payload or {}).get("pagination") or {}
            return {
                "ok": True,
                "vendor": self.vendor,
                "kind": self.kind.value,
                "agents_visible": pagination.get("totalItems"),
            }

    # ------------------------------------------------------------------ #
    # Public protocol surface                                            #
    # ------------------------------------------------------------------ #

    async def get_process_tree(
        self, *, host: str, process_name: str | None = None
    ) -> dict[str, Any]:
        """Reconstruct a process tree from recent threats on `host`.

        We resolve ``host`` → agent_id, then list threats for that
        agent in the configured window. Each threat carries a
        ``threatInfo`` block with the originating process, its parent,
        cmdline, and user — we link those into a forest of trees.

        ``process_name`` filters threats by ``threatInfo.processName``
        substring (case-insensitive, applied client-side after the
        Threats query since S1's API does an exact match).

        Empty result on hosts with no recent threats — that's the
        honest signal, not a failure.
        """
        _check_entity_value(host, field="host")
        if process_name is not None:
            _check_entity_value(process_name, field="process_name")

        agent_id = await self._resolve_agent_id(host)

        since = datetime.now(timezone.utc) - timedelta(
            hours=self._threat_hours
        )
        # SentinelOne expects ISO-8601 with milliseconds and a literal
        # 'Z' for UTC. ``isoformat`` would emit ``+00:00`` which the
        # API rejects; we render it manually.
        since_iso = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        params: dict[str, Any] = {
            "agentIds": agent_id,
            "createdAt__gte": since_iso,
            "limit": 100,
        }
        self._attach_scope(params)

        payload = await self._http.get(
            "/web/api/v2.1/threats", params=params
        )
        _raise_for_s1_errors(
            payload, operation="get_process_tree", host=host
        )
        threats = (payload or {}).get("data") or []
        if not isinstance(threats, list):
            threats = []

        if process_name:
            needle = process_name.lower()
            threats = [
                t for t in threats if _threat_matches_name(t, needle)
            ]

        tree = _threats_to_tree(threats)
        return {"host": host, "tree": tree}

    async def isolate_host(self, *, host: str, reason: str) -> dict[str, Any]:
        """Network-disconnect `host` via Agents Actions API.

        Returns the mock-compatible envelope:
        ``{host, isolated: True, reason, ticket}``. SentinelOne does
        not return a trace_id; we synthesise the ticket from the
        affected count + agent id so the audit log can be
        cross-referenced against the SentinelOne action history.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ConnectorError(
                "sentinelone: isolate_host requires a non-empty reason",
                vendor="sentinelone",
            )
        agent_id = await self._resolve_agent_id(host)
        affected = await self._agent_action(
            agent_id=agent_id,
            action_path="disconnect",
            host=host,
        )
        return {
            "host": host,
            "isolated": True,
            "reason": reason,
            "ticket": _make_ticket("ISO", agent_id, affected),
        }

    async def release_host(self, *, host: str) -> dict[str, Any]:
        """Reverse a prior `isolate_host`.

        SentinelOne's ``connect`` action is the symmetric reverse of
        ``disconnect``. Returns ``{host, isolated: False, ticket}``.
        """
        agent_id = await self._resolve_agent_id(host)
        affected = await self._agent_action(
            agent_id=agent_id,
            action_path="connect",
            host=host,
        )
        return {
            "host": host,
            "isolated": False,
            "ticket": _make_ticket("REL", agent_id, affected),
        }

    async def quarantine_file(self, *, sha256: str) -> dict[str, Any]:
        """Add `sha256` to the tenant-wide blacklist (Restrictions API).

        We submit one ``black_hash`` restriction per configured OS
        type (``windows``, ``macos``, ``linux`` by default). The
        SentinelOne agent blocks future execution on every endpoint
        and quarantines existing copies on hosts that observe the
        hash via telemetry. The exact "endpoints affected" count is
        emitted as threats asynchronously, so we report
        ``quarantined_on_endpoints`` as the number of
        restriction records successfully created (one per OS type on
        full success).
        """
        if not isinstance(sha256, str) or not _SHA256_RE.match(sha256):
            raise ConnectorError(
                f"sentinelone: invalid sha256 {sha256!r} "
                "(expected 64 hex chars)",
                vendor="sentinelone",
            )
        normalised = sha256.lower()

        created_ids: list[str] = []
        for os_type in self._os_types:
            body = {
                "filter": {"tenant": True},
                "data": {
                    "value": normalised,
                    "type": "black_hash",
                    "osType": os_type,
                    "description": "cyble-aisoc: quarantine_file",
                    "source": "cyble-aisoc",
                },
            }
            resp = await self._http.post(
                "/web/api/v2.1/restrictions", json=body
            )
            _raise_for_s1_errors(
                resp, operation=f"quarantine_file.{os_type}"
            )
            resources = (resp or {}).get("data") or []
            if isinstance(resources, list):
                for r in resources:
                    if isinstance(r, dict) and r.get("id"):
                        created_ids.append(str(r["id"]))

        return {
            "sha256": normalised,
            "quarantined_on_endpoints": len(created_ids),
            "ticket": (
                f"QUA-{(created_ids[0] if created_ids else normalised)[:8]}"
            ),
        }

    async def kill_process(self, *, host: str, pid: int) -> dict[str, Any]:
        """Terminate `pid` on `host` via threat mitigation kill.

        SentinelOne's Mgmt API does not expose arbitrary PID
        termination — kill is always scoped to a *detected threat*.
        We look up unmitigated threats on the host that reference
        ``pid`` (via ``threatInfo.processId`` or
        ``threatInfo.originatingProcessId``) and call
        ``/web/api/v2.1/threats/mitigate/kill`` against the matching
        threat ids.

        If no associated threat exists, we raise ``ConnectorError``
        — operators should escalate to a manual ``rm-kill`` RTR
        command via the SentinelOne Console for ad-hoc PIDs. This is
        an honest "vendor capability mismatch" surface, not a silent
        no-op.
        """
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            raise ConnectorError(
                f"sentinelone: pid must be a positive integer "
                f"(got {pid!r})",
                vendor="sentinelone",
            )
        agent_id = await self._resolve_agent_id(host)

        # Query a wider window than ``threat_window_hours`` here on
        # purpose: kill targets are by definition open threats, and
        # operators occasionally hit this hours after the original
        # detection window. We cap at 30d (the S1 retention default
        # for free-tier accounts).
        since = datetime.now(timezone.utc) - timedelta(days=30)
        since_iso = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        params: dict[str, Any] = {
            "agentIds": agent_id,
            "createdAt__gte": since_iso,
            "limit": 100,
            # Only consider not-yet-mitigated kills — once a threat is
            # killed the API will respond with ``affected=0`` and we'd
            # surface that as a confusing failure.
            "mitigationStatuses": "not_mitigated,marked_as_benign,pending",
        }
        self._attach_scope(params)

        threats_resp = await self._http.get(
            "/web/api/v2.1/threats", params=params
        )
        _raise_for_s1_errors(
            threats_resp, operation="kill_process.query", host=host
        )
        threats = (threats_resp or {}).get("data") or []
        if not isinstance(threats, list):
            threats = []

        matched_ids = _threats_matching_pid(threats, pid)
        if not matched_ids:
            raise ConnectorError(
                f"sentinelone: no open threat references pid={pid} on "
                f"{host!r} — SentinelOne's Mgmt API can only kill "
                "processes associated with a detected threat. "
                "Escalate to a manual RTR 'kill' via the S1 Console.",
                vendor="sentinelone",
                status=404,
            )

        mit_body = {
            "filter": {"ids": matched_ids},
            "data": {},
        }
        mit_resp = await self._http.post(
            "/web/api/v2.1/threats/mitigate/kill", json=mit_body
        )
        _raise_for_s1_errors(
            mit_resp, operation="kill_process.mitigate", host=host
        )
        data = (mit_resp or {}).get("data") or {}
        affected = _safe_int(data.get("affected")) or 0
        if affected <= 0:
            raise ConnectorError(
                f"sentinelone: mitigate/kill affected=0 for host={host} "
                f"pid={pid} threats={matched_ids!r} — threat may have "
                "already been mitigated.",
                vendor="sentinelone",
            )
        return {"host": host, "pid": pid, "terminated": True}

    # ------------------------------------------------------------------ #
    # Internal helpers                                                   #
    # ------------------------------------------------------------------ #

    async def _resolve_agent_id(self, host: str) -> str:
        """Resolve `host` (hostname or agent id) to a SentinelOne agent id.

        Agent ids are numeric strings (8..32 digits). If `host`
        already matches that shape, we trust it without a round-trip;
        otherwise we query ``/web/api/v2.1/agents`` with
        ``computerName=<host>``.

        Raises ``ConnectorError`` if the host is unknown — better to
        surface "not found" early than to invoke an action against an
        agent that does not exist.
        """
        _check_entity_value(host, field="host")
        if _AID_RE.match(host):
            return host
        params: dict[str, Any] = {
            "computerName": host,
            "limit": 1,
        }
        self._attach_scope(params)
        payload = await self._http.get(
            "/web/api/v2.1/agents", params=params
        )
        _raise_for_s1_errors(
            payload, operation="resolve_agent_id", host=host
        )
        data = (payload or {}).get("data") or []
        if not isinstance(data, list) or not data:
            raise ConnectorError(
                f"sentinelone: host {host!r} not found in SentinelOne",
                vendor="sentinelone",
                status=404,
            )
        first = data[0] if isinstance(data[0], dict) else {}
        agent_id = str(first.get("id") or "").strip()
        if not _AID_RE.match(agent_id):
            raise ConnectorError(
                f"sentinelone: malformed agent id in resolve response: "
                f"{agent_id!r}",
                vendor="sentinelone",
            )
        return agent_id

    async def _agent_action(
        self, *, agent_id: str, action_path: str, host: str
    ) -> int:
        """Run an agents/actions/<action_path> call against `agent_id`.

        Returns the API's reported ``affected`` count so callers can
        embed it in the synthetic ticket. SentinelOne returns
        ``affected=1`` on success for a single-id filter; ``affected=0``
        means the action was a no-op (already in the target state) —
        we treat that as a soft success for ``connect``/``disconnect``
        because the operator's intent (host in desired state) is met.
        """
        body = {
            "filter": {"ids": agent_id},
            "data": {},
        }
        resp = await self._http.post(
            f"/web/api/v2.1/agents/actions/{action_path}", json=body
        )
        _raise_for_s1_errors(resp, operation=action_path, host=host)
        data = (resp or {}).get("data") or {}
        return _safe_int(data.get("affected")) or 0

    def _attach_scope(self, params: dict[str, Any]) -> None:
        """Append optional ``siteIds``/``accountIds`` filters in place.

        These are tenant-level scoping params that MSSPs / multi-site
        SentinelOne deployments use to constrain queries. When
        unconfigured we omit them entirely so the token's own scope
        (set in the S1 console) governs visibility.
        """
        if self._site_ids:
            params["siteIds"] = self._site_ids
        if self._account_ids:
            params["accountIds"] = self._account_ids


# ─── threat → tree helpers ───────────────────────────────────────────────


def _threat_matches_name(threat: Any, needle_lower: str) -> bool:
    """Substring filter for ``threatInfo.processName``.

    SentinelOne's threats API supports an exact-match
    ``threatInfo.processName`` query param, but operators typically
    supply a partial name (``"powershell"``). We filter client-side
    instead, after the agent-scoped list comes back.
    """
    if not isinstance(threat, dict):
        return False
    info = threat.get("threatInfo") or {}
    if not isinstance(info, dict):
        return False
    candidates: list[str] = []
    for key in ("processName", "originatingProcessName", "fileName"):
        val = info.get(key)
        if isinstance(val, str):
            candidates.append(val.lower())
    return any(needle_lower in c for c in candidates)


def _threats_matching_pid(threats: Iterable[Any], pid: int) -> list[str]:
    """Return threat ids whose ``threatInfo`` references `pid`.

    SentinelOne emits the originating process id under one of several
    keys depending on threat type (``processId``,
    ``originatingProcessId``). We check both. Threat ids are surfaced
    at the top-level ``id`` field.
    """
    matched: list[str] = []
    for threat in threats:
        if not isinstance(threat, dict):
            continue
        threat_id = str(threat.get("id") or "").strip()
        if not threat_id or not _THREAT_ID_RE.match(threat_id):
            continue
        info = threat.get("threatInfo") or {}
        if not isinstance(info, dict):
            continue
        candidate_pids = [
            _safe_int(info.get("processId")),
            _safe_int(info.get("originatingProcessId")),
            # Some S1 schema versions nest the pid one level deeper.
            _safe_int(
                (info.get("processInfo") or {}).get("pid")
                if isinstance(info.get("processInfo"), dict)
                else None
            ),
        ]
        if pid in [p for p in candidate_pids if p is not None]:
            matched.append(threat_id)
    return matched


def _threats_to_tree(
    threats: list[Any],
) -> list[dict[str, Any]]:
    """Flatten SentinelOne threats into a parent-linked process forest.

    A SentinelOne threat carries a ``threatInfo`` block with
    (abbreviated)::

        {
          "processName": "powershell.exe",
          "originatingProcessId": 6014,
          "parentProcessName": "winword.exe",
          # parent pid is sometimes "parentProcessUniqueKey"
          # (a fingerprint, not a numeric pid) — we don't link by it.
          "commandLine": "powershell -EncodedCommand <REDACTED>",
          "processUser": "tina.lee",
          "signature": {"signedStatus": "signed"},
          "confidenceLevel": "malicious",
        }

    We:
      1. Build a flat dict keyed by the originating ``pid``.
      2. Synthesise a parent node from ``parentProcessName`` when we
         have a name but no parent pid — keeps the tree readable
         even when S1 doesn't report a numeric parent pid.
      3. Return the roots (processes whose parent is not a real pid
         in the set).

    Multiple threats may reference the same originating process; we
    keep the first occurrence to avoid duplicating nodes.
    """
    nodes: dict[int, dict[str, Any]] = {}
    parent_pid_of: dict[int, int] = {}
    parent_name_of: dict[int, str] = {}

    for threat in threats:
        if not isinstance(threat, dict):
            continue
        info = threat.get("threatInfo") or {}
        if not isinstance(info, dict):
            continue
        pid = _safe_int(
            info.get("originatingProcessId") or info.get("processId")
        )
        if pid is None or pid in nodes:
            continue
        parent_pid = _safe_int(
            info.get("parentProcessId")
            or info.get("originatingProcessParentId")
        )
        parent_name = info.get("parentProcessName")
        sig = info.get("signature") or {}
        if not isinstance(sig, dict):
            sig = {}
        node: dict[str, Any] = {
            "pid": pid,
            "name": str(
                info.get("processName")
                or info.get("originatingProcessName")
                or info.get("fileName")
                or "unknown"
            ),
            "cmdline": str(info.get("commandLine") or ""),
            "user": str(
                info.get("processUser") or info.get("userName") or ""
            ),
            "signed": _coerce_signed(sig.get("signedStatus")),
            # Threats by definition fire on suspicious activity.
            "suspicious": True,
            "children": [],
        }
        nodes[pid] = node
        if parent_pid and parent_pid != pid:
            parent_pid_of[pid] = parent_pid
        if isinstance(parent_name, str) and parent_name:
            parent_name_of[pid] = parent_name

    # Attach children to their parents when we have a real numeric
    # parent pid that's also in the node set. Synthesise parent stub
    # nodes for parents that S1 named but didn't number — keeps the
    # tree readable instead of orphaning the children.
    synth_pid_counter = -1
    name_to_synth_pid: dict[str, int] = {}
    roots: list[dict[str, Any]] = []
    for pid, node in list(nodes.items()):
        parent_pid = parent_pid_of.get(pid)
        if parent_pid and parent_pid in nodes:
            nodes[parent_pid]["children"].append(node)
            continue
        parent_name = parent_name_of.get(pid)
        if parent_name:
            synth_pid = name_to_synth_pid.get(parent_name)
            if synth_pid is None:
                synth_pid = synth_pid_counter
                synth_pid_counter -= 1
                stub = {
                    "pid": None,  # we don't know the real parent pid
                    "name": parent_name,
                    "cmdline": "",
                    "user": "",
                    "suspicious": False,
                    "children": [],
                }
                nodes[synth_pid] = stub
                name_to_synth_pid[parent_name] = synth_pid
                roots.append(stub)
            nodes[synth_pid]["children"].append(node)
        else:
            roots.append(node)
    return roots


def _coerce_signed(raw: Any) -> bool | None:
    """Map SentinelOne ``signedStatus`` strings to a tristate bool."""
    if not isinstance(raw, str):
        return None
    lowered = raw.strip().lower()
    if lowered == "signed":
        return True
    if lowered in {"unsigned", "not_signed", "invalid"}:
        return False
    return None


def _make_ticket(prefix: str, agent_id: str, affected: int) -> str:
    """Synthesise an opaque ticket id for audit trails.

    SentinelOne doesn't emit a per-request trace id like CrowdStrike,
    so we derive a stable-ish fragment from the agent id + a single
    base36 hint about whether the action was a no-op (affected=0)
    vs a state change (affected=1). Operators searching the S1
    activity log by agent id will land on the right entry.
    """
    fragment = (agent_id or "unknown")[:8]
    suffix = "x" if affected <= 0 else "1"
    return f"{prefix}-{fragment}{suffix}"


# ─── factory ─────────────────────────────────────────────────────────────


def make_sentinelone_edr(config: ConnectorConfig) -> SentinelOneEdrConnector:
    """Factory entry-point registered in ``app/connectors/sdk/builtin.py``."""
    return SentinelOneEdrConnector(config)


__all__ = [
    "SentinelOneEdrConnector",
    "make_sentinelone_edr",
]
