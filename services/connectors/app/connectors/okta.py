"""
Okta connector.
Fetches system log events (suspicious activity, failed logins, MFA push spam).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors._paging import read_link_header_pages
from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()


#: Okta event types whose SUCCESS means a second factor was actually
#: verified. Listed rather than inferred from a substring, because
#: `user.authentication.auth_via_mfa` and `user.mfa.factor.deactivate` both
#: contain "mfa" and only one of them is a satisfied challenge.
_MFA_SATISFIED_EVENTS: frozenset[str] = frozenset(
    {
        "user.authentication.auth_via_mfa",
        "user.authentication.verify",
        "user.mfa.okta_verify.deny_push",
        "user.mfa.attempt_bypass",
    }
)

#: The subset of the above that means the challenge *passed*. A denied push
#: and a bypass attempt are MFA events and emphatically not satisfied ones,
#: and folding them in would make `mfa_satisfied` true for the exact
#: sequence an MFA-fatigue rule is looking for.
_MFA_DENIED_EVENTS: frozenset[str] = frozenset({"user.mfa.okta_verify.deny_push", "user.mfa.attempt_bypass"})


def _mfa_satisfied(raw: dict[str, Any], result: str) -> bool | None:
    """Did this event record a second factor being verified?

    Three-valued on purpose. ``None`` means "this event says nothing about
    MFA", which is most of them, and a detection that treats that as
    ``False`` would fire on every directory read. Only an event type that
    records a factor check answers True or False at all -- the same shape as
    the ``not_evaluated`` third value in sender authentication, and for the
    same reason: silence is not a negative result.
    """
    event_type = str(raw.get("eventType") or "")
    if event_type in _MFA_DENIED_EVENTS:
        return False
    if event_type in _MFA_SATISFIED_EVENTS:
        return result == "SUCCESS"
    # A session start carries the factor it was satisfied with in debugData
    # when the policy required one. Absent that, the sign-in was
    # single-factor and this says so rather than staying silent, because a
    # session that never met a challenge is the baseline an AiTM detection
    # compares against.
    if event_type == "user.session.start" and result == "SUCCESS":
        debug = (raw.get("debugContext") or {}).get("debugData") or {}
        factor = str(debug.get("factor") or debug.get("factorUsed") or "")
        return bool(factor)
    return None


class OktaConnector(BaseConnector):
    connector_id = "okta"
    connector_name = "Okta Identity"
    connector_category = "iam"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Okta system log events (auth, MFA, account locks, blocked requests).",
            docs_url="/docs/connectors/okta",
            fields=[
                Field(
                    "domain",
                    "string",
                    "Okta Domain",
                    placeholder="https://yourorg.okta.com",
                ),
                Field("api_token", "secret", "API Token"),
            ],
            # Hosted OAuth (Workstream 2): Okta supports OIDC + OAuth 2.0
            # for service apps. The {domain} placeholder is rewritten in
            # /api/v1/oauth/start using the per-instance ``domain`` field
            # (or the OAuth app credential's authorize_url override for
            # custom auth servers).
            oauth=OAuthHints(
                supported_in_hosted=True,
                authorize_url="{domain}/oauth2/v1/authorize",
                token_url="{domain}/oauth2/v1/token",
                scopes=[
                    "okta.logs.read",
                    "okta.users.read",
                    "okta.groups.read",
                    "offline_access",
                ],
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Okta System Log streams identity audit events (logins, MFA, admin actions).
        # WS-E3: Live Okta Management API response actions now wired
        # via services/actions/app/clients/okta_client.py
        return (
            Capability.PULL_AUDIT,
            Capability.DISABLE_USER,
            Capability.RESET_PASSWORD,
            Capability.SUSPEND_SESSION,
            Capability.FORCE_MFA,
            Capability.REVOKE_SESSION,
        )

    #: Ingest cursor (10b). Okta System Log events carry `published` and a
    #: `uuid`; normalize() already reads both (created_at / external_id).
    checkpoint_time_field = ("published",)
    checkpoint_id_field = ("uuid",)

    def __init__(self, domain: str, api_token: str):
        self._domain = domain.rstrip("/")
        self._api_token = api_token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"SSWS {self._api_token}",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(
                    f"{self._domain}/api/v1/org",
                    headers=self._headers(),
                )
                resp.raise_for_status()
                data = resp.json()
                return {"success": True, "connector": self.connector_id, "org": data.get("name")}
            except Exception as exc:
                return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        # Focus on security-relevant event types
        security_events = [
            "user.authentication.auth_via_mfa",
            "user.session.start",
            "policy.evaluate_sign_on",
            "user.account.lock",
            "security.request.blocked",
        ]

        events: list[dict] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            for event_type in security_events:
                resp = await client.get(
                    f"{self._domain}/api/v1/logs",
                    headers=self._headers(),
                    params={
                        "since": since,
                        "eventType": event_type,
                        # Okta's documented maximum. Each page spends a request
                        # from the org's System Log rate limit, so a burst is
                        # read in the fewest of them.
                        "limit": 1000,
                    },
                )
                if resp.status_code == 200:
                    events.extend(await read_link_header_pages(client, resp, headers=self._headers(), feed=f"okta.{event_type}"))

        return [self.normalize(e) for e in self.apply_checkpoint(events)]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        outcome = raw.get("outcome", {})
        result = outcome.get("result", "SUCCESS")
        severity = "info"
        if result in ("FAILURE", "DENY"):
            severity = "medium"
        if raw.get("eventType") in ("user.account.lock", "security.request.blocked"):
            severity = "high"

        actor = raw.get("actor", {})
        client_info = raw.get("client", {})
        auth_context = raw.get("authenticationContext") or {}
        security_context = raw.get("securityContext") or {}
        user_agent = client_info.get("userAgent") or {}
        geo = client_info.get("geographicalContext") or {}

        return {
            "source": self.connector_id,
            "external_id": raw.get("uuid", ""),
            "title": raw.get("displayMessage", "Okta Event"),
            "description": f"{raw.get('eventType')} - {outcome.get('reason', result)}",
            "severity": severity,
            "src_ip": client_info.get("ipAddress"),
            "actor": actor.get("displayName"),
            "actor_email": actor.get("alternateId"),
            "event_type": raw.get("eventType"),
            # Okta carries the result inside an `outcome` *object*. `result`
            # was read here only to pick a severity and then thrown away,
            # which made every identity rule that matches on it unreachable
            # (issue #1279).
            #
            # The detection engine flattens `raw_event` one level, so the
            # matcher saw `outcome` as the dict `{"result": "FAILURE",
            # "reason": ...}` and compared it to the string `"FAILURE"`.
            # Seven shipped Okta rules clause on that value — the two
            # windowed brute-force/password-spray rules on `FAILURE`, four
            # native identity rules on `SUCCESS` — so none of them could
            # ever fire, which is why a default install looks as though it
            # has no identity detections rather than unreachable ones.
            #
            # Hoisted here rather than taught to the engine, following the
            # Windows `CommandLine`/`Image` fix: the matcher and both
            # engines stay byte-identical, so the blast radius is one
            # connector and is provable by replay.
            "outcome": result,
            "outcome_reason": outcome.get("reason"),
            # Depth 7.3 — adversary-in-the-middle session reuse.
            #
            # Same class of fix as `outcome` above and for the same reason:
            # the engine flattens `raw_event` exactly one level, so
            # `authenticationContext` arrives as a dict and a rule clausing
            # on a session id compares a string against `{...}`. Okta carries
            # every field an AiTM detection needs and `normalize()` emitted
            # none of them, so the family had nothing to group by.
            #
            # `session_id` is the one that matters. An AiTM proxy relays the
            # victim's credentials *and* their MFA response, so the sign-in
            # itself is legitimate by every check Okta makes; what gives the
            # attacker away is the stolen session cookie being replayed from
            # somewhere else. That is only visible if the session identity
            # survives normalization.
            "session_id": auth_context.get("externalSessionId"),
            "authentication_step": auth_context.get("authenticationStep"),
            # The network the request came from. `src_ip` alone cannot
            # express "a different network": a residential ISP rotates
            # addresses within one ASN all day, and an AiTM replay from a
            # hosting provider is a different ASN entirely.
            "src_asn": security_context.get("asNumber"),
            "src_asn_org": security_context.get("asOrg"),
            "src_isp": security_context.get("isp"),
            "is_proxy": security_context.get("isProxy"),
            "src_country": geo.get("country"),
            # The client family. A session that was established in Chrome on
            # Windows and is next used by a bare HTTP client is the second
            # half of the same signal.
            "user_agent": user_agent.get("rawUserAgent"),
            "client_browser": user_agent.get("browser"),
            "client_os": user_agent.get("os"),
            # Whether this sign-in actually satisfied MFA. `authnRequestId`
            # and the factor live in debugData; the step-up itself is a
            # distinct event type, so this reads the outcome of the one Okta
            # recorded rather than inferring it.
            "mfa_satisfied": _mfa_satisfied(raw, result),
            "raw_event": raw,
            "created_at": raw.get("published"),
        }

    # T1.2 — config snapshots
    #
    # Okta exposes group, app, and policy versions via the "list policies"
    # / "get group" / "get app" endpoints. There's no first-class history
    # API so we return the *current* config and tag the response with
    # ``snapshot_freshness="live"`` so downstream consumers know the
    # snapshot was taken at lookup time, not at event time.
    #
    # ``resource_id`` is the Okta entity id; we infer the entity type from
    # the prefix (the audit log uses canonical id prefixes:
    # ``00g*`` group, ``0oa*`` app, ``00p*`` policy, ``00u*`` user).
    async def get_resource_config(self, resource_id: str, at_ts: str | None = None) -> dict[str, Any]:
        if not resource_id:
            return {}
        prefix = resource_id[:3]
        path = None
        if prefix == "00g":
            path = f"/api/v1/groups/{resource_id}"
        elif prefix == "0oa":
            path = f"/api/v1/apps/{resource_id}"
        elif prefix == "00p":
            path = f"/api/v1/policies/{resource_id}"
        elif prefix == "00u":
            path = f"/api/v1/users/{resource_id}"
        else:
            return {"error": f"unsupported resource id prefix '{prefix}'"}

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(
                    f"{self._domain}{path}",
                    headers=self._headers(),
                )
                if resp.status_code != 200:
                    return {
                        "error": f"HTTP {resp.status_code}",
                        "snapshot_freshness": "unavailable",
                    }
                payload = resp.json()
            except Exception as exc:  # noqa: BLE001
                return {"error": str(exc), "snapshot_freshness": "unavailable"}

        # Map Okta's nested shape into a stable v1.0 schema for the graph
        # writer. The raw payload lives under ``raw`` for forensic depth;
        # the top-level fields are what most queries will hit.
        kind = {
            "00g": "okta.Group",
            "0oa": "okta.Application",
            "00p": "okta.Policy",
            "00u": "okta.User",
        }[prefix]
        return {
            "resource_type": kind,
            "resource_id": resource_id,
            "name": payload.get("name") or payload.get("label") or payload.get("profile", {}).get("login"),
            "status": payload.get("status"),
            "settings": payload.get("settings"),
            "policy_type": payload.get("type"),
            "version": payload.get("version"),
            "last_updated": payload.get("lastUpdated"),
            "snapshot_freshness": "live",
            "snapshot_taken_at": at_ts,
            "raw": payload,
        }
