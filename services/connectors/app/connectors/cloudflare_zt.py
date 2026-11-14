"""
Cloudflare WAF + Zero Trust events connector.

Distinct from the existing ``cloudflare`` connector (account audit log):
this one pulls *data-plane* events from two streams and folds them into
the same normalised shape:

  * **WAF / firewall events** — the ``firewallEventsAdaptive`` dataset on
    ``POST /graphql``. Per-zone request-level decisions: block, challenge,
    log, skip. Rows carry ``action``, ``ruleId``, ``clientIP``,
    ``clientCountryName``, ``clientRequestHTTPHost`` and ``rayName``.
  * **Zero Trust (Access) audit** — ``GET /accounts/{account_id}/access/logs/access_requests``.
    Application access decisions: who tried to reach which Access app,
    were they allowed, and why. Carries email, ip, app_uid, decision.

Why WAF events come over GraphQL and not REST
---------------------------------------------
This connector used to poll ``GET /zones/{zone_id}/security/events``,
described here as a mid-2024 replacement for ``firewall/events``. No such
route exists. Cloudflare answers it — and the ``firewall/events`` it was
said to replace — with **HTTP 404, error code 10404 "No route for that
URI"**, for any zone id and with or without a token, so WAF mode could
never have returned an event on any deployment (reported as issue #1686).
Measured against the live API: the two firewall paths return 10404 while
``/accounts/{id}/access/logs/access_requests`` and an unrelated zone route
both answer **9106 "Missing ... Authorization headers"** — an *auth*
refusal, which is what an existing route returns. Access mode was and is
unaffected.

Cloudflare exposes firewall events two ways: the GraphQL Analytics API
(dataset ``firewallEventsAdaptive``) and Logpush (Enterprise). Logpush is
a push pipeline with an Enterprise floor, so the pull connector uses
GraphQL.

GraphQL has no cursor on this dataset. Paging is by time: ask for rows
ordered by ``datetime`` ascending, then move the lower bound to the last
row seen. Rows sharing a timestamp would otherwise repeat across pages, so
emitted ``rayName`` values are remembered for the duration of the poll and
a repeat is dropped rather than re-emitted.

A single ``mode`` field on the connector selects which stream is active
for a given instance — operators add one Cloudflare account-id + token,
then instantiate the connector twice (once per stream) rather than us
multiplexing both into one polling job and tangling the rate limits.

Auth is one API token. Access mode needs ``Account: Access: Audit Logs:
Read``; WAF mode needs ``Zone: Analytics: Read``, which is what the
GraphQL Analytics API reads — *not* the ``Zone: Firewall Services: Read``
this connector and its documentation asked for, which governs rule
management rather than the analytics dataset. Bearer-token model only —
the legacy global-key path is not supported.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


def _parse_iso(value: str) -> datetime | None:
    """Cloudflare's ``datetime`` as an aware UTC moment, or ``None``.

    The dataset returns RFC 3339 with a ``Z``; ``fromisoformat`` only learned
    that spelling in 3.11, and a value it cannot read must not become
    ``now()`` — that would silently narrow the next page's window to nothing.
    """
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


_BASE = "https://api.cloudflare.com/client/v4"
_GRAPHQL = f"{_BASE}/graphql"
_PER_PAGE = 100
_MAX_PAGES = 20

#: ``firewallEventsAdaptive`` rows for one zone and time window.
#:
#: Ordered ascending so the last row of a page is the next page's lower
#: bound; ``datetime_geq``/``datetime_leq`` are the only paging controls the
#: dataset offers. The field list is the subset :meth:`_normalize_waf` reads
#: — asking for columns nothing renders costs the operator's rate limit and
#: widens what a GraphQL error can echo back.
_WAF_QUERY = """
query AiSOCFirewallEvents($zoneTag: String!, $since: Time!, $until: Time!, $limit: Int!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      firewallEventsAdaptive(
        filter: { datetime_geq: $since, datetime_leq: $until }
        limit: $limit
        orderBy: [datetime_ASC]
      ) {
        action
        clientAsn
        clientCountryName
        clientIP
        clientRequestHTTPHost
        clientRequestHTTPMethodName
        clientRequestPath
        datetime
        rayName
        ruleId
        source
        userAgent
      }
    }
  }
}
""".strip()


#: Spellings of ``mode`` that are not the canonical one, mapped to it.
#:
#: The canonical values have always been ``waf`` / ``access``, and three
#: surfaces published ``zero_trust`` instead: the documentation page, the
#: marketplace manifest's ``enum``, and the setup walkthrough. Anyone who
#: followed any of them got ``unknown mode 'zero_trust'``. All three are
#: corrected, and the spelling they published is accepted here so a cached
#: manifest or a copied config keeps working rather than failing on a word.
_MODE_ALIASES = {"zero_trust": "access", "zerotrust": "access", "zt": "access"}


class CloudflareZTConnector(BaseConnector):
    """Cloudflare WAF + Zero Trust events."""

    connector_id = "cloudflare_zt"
    connector_name = "Cloudflare WAF + Zero Trust"
    connector_category = "network"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Cloudflare data-plane events: WAF / firewall decisions "
                "(per-zone, via the GraphQL firewallEventsAdaptive dataset) "
                "and Zero Trust Access audit log (per-account). Auth is an "
                "API token with Zone:Analytics:Read and Account:Access "
                "Audit Logs:Read."
            ),
            docs_url="/docs/connectors/cloudflare_zt",
            fields=[
                Field(
                    "mode",
                    "select",
                    "Event stream",
                    options=[
                        {"value": "waf", "label": "WAF / firewall events"},
                        {"value": "access", "label": "Zero Trust Access audit"},
                    ],
                    help_text=("Pick which stream this instance pulls. Run two instances side-by-side for full coverage."),
                ),
                Field(
                    "account_id",
                    "string",
                    "Account ID",
                    placeholder="abc123def456",
                    help_text="Cloudflare account ID, found in the dashboard right pane.",
                ),
                Field(
                    "zone_id",
                    "string",
                    "Zone ID (WAF mode only)",
                    placeholder="zone-uuid",
                    required=False,
                    help_text="Required when mode=waf. Leave empty for Access mode.",
                ),
                Field(
                    "api_token",
                    "secret",
                    "API Token",
                    help_text=(
                        "Token with Zone:Analytics:Read (WAF — this is what the GraphQL analytics "
                        "dataset reads, not Firewall Services:Read) AND Account:Access Audit Logs:Read (Zero Trust)."
                    ),
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.PULL_AUDIT,
            Capability.READ_AUDIT_TRAIL,
        )

    def __init__(
        self,
        mode: str,
        account_id: str,
        api_token: str,
        zone_id: str | None = None,
    ):
        mode = _MODE_ALIASES.get((mode or "").strip().lower(), (mode or "").strip().lower())
        if mode not in ("waf", "access"):
            raise ValueError(f"cloudflare_zt: unknown mode '{mode}' (need 'waf' or 'access')")
        if mode == "waf" and not zone_id:
            raise ValueError("cloudflare_zt: zone_id is required when mode='waf'")
        self._mode = mode
        self._account_id = account_id
        self._zone_id = zone_id
        self._api_token = api_token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_token}",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # Token health first — gives a clean signal that auth is OK.
                resp = await client.get(
                    f"{_BASE}/user/tokens/verify",
                    headers=self._headers(),
                )
                if resp.status_code != 200:
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": f"token verify HTTP {resp.status_code}",
                    }
                status = (resp.json() or {}).get("result", {}).get("status")
                if status != "active":
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": f"token status: {status}",
                    }

                # Then probe the active mode's endpoint with limit=1 so an
                # ill-scoped token surfaces a useful "missing permission" hint
                # rather than just "auth ok, no data".
                if self._mode == "waf":
                    # A GraphQL scope failure is a 200 carrying `errors` and a
                    # null `data`. Reading that as "no events" would report a
                    # token that cannot see the dataset as a healthy, quiet
                    # zone — so the probe is only a pass when rows parse.
                    until = datetime.now(UTC)
                    probe = await client.post(
                        _GRAPHQL,
                        headers=self._headers(),
                        json=self._waf_payload(
                            since=until - timedelta(minutes=5),
                            until=until,
                            limit=1,
                        ),
                    )
                    if probe.status_code != 200:
                        return {
                            "success": False,
                            "connector": self.connector_id,
                            "error": (f"token verified but waf probe HTTP {probe.status_code}: {probe.text[:200]}"),
                        }
                    try:
                        self._waf_rows(probe.json() or {})
                    except RuntimeError as exc:
                        return {
                            "success": False,
                            "connector": self.connector_id,
                            "error": str(exc),
                        }
                else:
                    probe = await client.get(
                        self._endpoint(),
                        headers=self._headers(),
                        params=self._params(since_iso=None, per_page=1),
                    )
                    if probe.status_code != 200:
                        return {
                            "success": False,
                            "connector": self.connector_id,
                            "error": (f"token verified but {self._mode} probe HTTP {probe.status_code}: {probe.text[:200]}"),
                        }
            return {
                "success": True,
                "connector": self.connector_id,
                "mode": self._mode,
                "account_id": self._account_id,
            }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    def _endpoint(self) -> str:
        """The REST endpoint for Access mode.

        WAF mode has no REST endpoint — see the module docstring — and goes
        through :data:`_GRAPHQL` instead.
        """
        return f"{_BASE}/accounts/{self._account_id}/access/logs/access_requests"

    def _params(self, since_iso: str | None, per_page: int = _PER_PAGE) -> dict[str, Any]:
        params: dict[str, Any] = {"per_page": per_page, "limit": per_page}
        if since_iso:
            params["since"] = since_iso
        return params

    @staticmethod
    def _iso(moment: datetime) -> str:
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _waf_payload(self, *, since: datetime, until: datetime, limit: int) -> dict[str, Any]:
        return {
            "query": _WAF_QUERY,
            "variables": {
                "zoneTag": self._zone_id,
                "since": self._iso(since),
                "until": self._iso(until),
                "limit": limit,
            },
        }

    @staticmethod
    def _waf_rows(body: dict[str, Any]) -> list[dict[str, Any]]:
        """Rows out of a GraphQL response, or raise with the reason.

        A missing scope is a **200** carrying ``errors`` and a null ``data``.
        Returning ``[]`` for that would turn "this token cannot read the
        firewall dataset" into "your zone saw no attacks", which is the
        substitution this codebase keeps having to un-make.
        """
        errors = body.get("errors")
        if errors:
            first = errors[0] if isinstance(errors, list) and errors else errors
            message = first.get("message") if isinstance(first, dict) else str(first)
            raise RuntimeError(f"cloudflare_zt graphql error: {str(message)[:200]}")
        zones = (((body.get("data") or {}).get("viewer") or {}).get("zones")) or []
        if not zones:
            # No zone matched the tag. Distinct from "the zone is quiet", and
            # worth saying so: the usual cause is a zone id that belongs to a
            # different account than the token is scoped to.
            raise RuntimeError("cloudflare_zt: the token sees no zone with that id (check zone_id and the token's zone scope)")
        return list(zones[0].get("firewallEventsAdaptive") or [])

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        if self._mode == "waf":
            return await self._fetch_waf(since_seconds)
        return await self._fetch_access(since_seconds)

    async def _fetch_waf(self, since_seconds: int) -> list[dict[str, Any]]:
        until = datetime.now(UTC)
        since = until - timedelta(seconds=since_seconds)
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        async with httpx.AsyncClient(timeout=30.0) as client:
            for _ in range(_MAX_PAGES):
                resp = await client.post(
                    _GRAPHQL,
                    headers=self._headers(),
                    json=self._waf_payload(since=since, until=until, limit=_PER_PAGE),
                )
                if resp.status_code != 200:
                    logger.warning(
                        "cloudflare_zt.fetch_failed",
                        mode=self._mode,
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    break
                try:
                    rows = self._waf_rows(resp.json() or {})
                except RuntimeError as exc:
                    logger.warning("cloudflare_zt.fetch_failed", mode=self._mode, error=str(exc))
                    break
                # Check-and-add in one pass. Filtering against a snapshot of
                # `seen` and adding afterwards lets a ray repeated *within* a
                # page through, which is the same duplicate the boundary row
                # produces and has to be dropped the same way.
                fresh = 0
                for row in rows:
                    ray = row.get("rayName") or ""
                    if ray:
                        if ray in seen:
                            continue
                        seen.add(ray)
                    fresh += 1
                    out.append(self.normalize(row))
                if len(rows) < _PER_PAGE:
                    break
                # No cursor on this dataset: the next window starts at the
                # last row's timestamp. `datetime_geq` is inclusive, so the
                # boundary row comes back again and `seen` drops it. A page
                # whose rows all share one timestamp cannot advance, and
                # would otherwise spin until `_MAX_PAGES`.
                last = (rows[-1] or {}).get("datetime")
                if not last or not fresh:
                    break
                since = _parse_iso(last) or since
        return out

    async def _fetch_access(self, since_seconds: int) -> list[dict[str, Any]]:
        since = self._iso(datetime.now(UTC) - timedelta(seconds=since_seconds))
        out: list[dict[str, Any]] = []
        cursor: str | None = None
        async with httpx.AsyncClient(timeout=30.0) as client:
            for _ in range(_MAX_PAGES):
                params = self._params(since_iso=since)
                if cursor:
                    params["cursor"] = cursor
                resp = await client.get(self._endpoint(), headers=self._headers(), params=params)
                if resp.status_code != 200:
                    logger.warning(
                        "cloudflare_zt.fetch_failed",
                        mode=self._mode,
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    break
                body = resp.json() or {}
                events = body.get("result") or []
                for ev in events:
                    out.append(self.normalize(ev))
                # Cloudflare returns ``result_info.cursor`` for keyset paging
                # on the Access audit endpoint. When the cursor is present the
                # server is telling us there is more — trust it even if this
                # page came back short. The cursor going empty is the
                # authoritative end-of-stream signal.
                info = body.get("result_info") or {}
                cursor = info.get("cursor") or info.get("next_cursor")
                if not cursor:
                    break
        return out

    # ----------------------- normalize --------------------------

    # WAF actions where the request was actively prevented — these are the
    # ones a SOC actually wants surfaced. ``log`` and ``allow`` flow through
    # as ``info``.
    _WAF_BLOCKING_ACTIONS = ("block", "drop", "managed_challenge", "jschallenge", "challenge")
    # Access decisions that indicate a denied / non-allowed access attempt.
    _ACCESS_DENY_DECISIONS = ("non_identity", "denied", "blocked", "non-identity")

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        if self._mode == "waf":
            return self._normalize_waf(raw)
        return self._normalize_access(raw)

    def _normalize_waf(self, raw: dict[str, Any]) -> dict[str, Any]:
        # `firewallEventsAdaptive` names its columns in camelCase. The
        # snake_case alternatives are kept as a second reading because the
        # REST shapes this connector used to claim are still what a hand-made
        # fixture or an operator's recorded sample looks like.
        action = (raw.get("action") or "").lower()
        rule_id = raw.get("ruleId") or raw.get("rule_id")
        client_ip = raw.get("clientIP") or raw.get("client_ip")
        host = raw.get("clientRequestHTTPHost") or raw.get("host")
        country = raw.get("clientCountryName") or raw.get("country")
        severity = "info"
        if action in self._WAF_BLOCKING_ACTIONS:
            severity = "medium"
        if action == "block" and rule_id and "owasp" in str(rule_id).lower():
            severity = "high"
        return {
            "source": self.connector_id,
            "stream": "waf",
            "external_id": raw.get("rayName") or raw.get("ray_id") or raw.get("id") or "",
            "title": f"Cloudflare WAF {action or 'event'}",
            "description": (f"action={action}; rule_id={rule_id}; host={host}; client_ip={client_ip}; country={country}"),
            "severity": severity,
            "src_ip": client_ip,
            "actor": client_ip,
            "event_type": f"cloudflare_zt.waf.{action or 'event'}",
            "raw_event": raw,
            "created_at": raw.get("datetime") or raw.get("occurred_at"),
        }

    def _normalize_access(self, raw: dict[str, Any]) -> dict[str, Any]:
        action = (raw.get("action") or raw.get("decision") or "").lower()
        allowed = raw.get("allowed")
        severity = "info"
        if allowed is False or action in self._ACCESS_DENY_DECISIONS:
            severity = "medium"
        if action in ("blocked",):
            severity = "high"
        email = raw.get("user_email") or raw.get("email")
        return {
            "source": self.connector_id,
            "stream": "access",
            "external_id": raw.get("ray_id") or raw.get("id") or "",
            "title": f"Cloudflare Access {action or 'request'}",
            "description": (
                f"decision={action}; user={email}; "
                f"app={raw.get('app_uid') or raw.get('app_name')}; "
                f"ip={raw.get('ip_address') or raw.get('ip')}; "
                f"country={raw.get('country')}"
            ),
            "severity": severity,
            "src_ip": raw.get("ip_address") or raw.get("ip"),
            "actor": email,
            "actor_email": email,
            "event_type": f"cloudflare_zt.access.{action or 'request'}",
            "raw_event": raw,
            "created_at": raw.get("created_at") or raw.get("datetime"),
        }
