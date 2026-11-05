"""
Azure Entra ID (formerly Azure AD) connector.

Pulls directory audit logs and risky sign-in events via Microsoft Graph.
This is the identity-plane counterpart to ``azure_activity`` (control plane)
and ``azure_defender`` (security plane).

Auth model: Azure AD app registration with the following Microsoft Graph
*application* permissions granted with admin consent:

    AuditLog.Read.All
    Directory.Read.All
    IdentityRiskyUser.Read.All  (only if you want risky-user signals)

We use the OAuth2 client-credentials flow, scoped to ``.default`` so the
token reflects exactly the consented permissions — that way the connector
fails closed if an operator forgets to grant a scope.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints
from app.connectors.posture import POSTURE_SNAPSHOT_ID
from app.connectors.posture import azure as azure_posture

logger = structlog.get_logger()

_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# Microsoft Graph caps `$top` at 1000 for these collections; 200 keeps each
# round-trip fast and rate-limit friendly while still covering normal volume.
_PAGE_SIZE = 200
# Bounds one feed's read in a single poll; reaching it is logged.
_MAX_PAGES = 25


def _unquote(value: Any) -> str:
    """A modified-property value with Graph's JSON encoding removed.

    Graph JSON-encodes these, so `"Global Administrator"` arrives with its
    quotes. Stripping them is what lets a rule compare against the role name
    a reader would write.
    """
    return str(value or "").strip('"')


def _targets_of_type(targets: list[dict[str, Any]], wanted: str) -> dict[str, Any] | None:
    """The first target whose `type` is `wanted`, searched for by name."""
    for target in targets:
        if str(target.get("type") or "").casefold() == wanted:
            return target
    return None


def _target_fields(targets: Any) -> dict[str, Any]:
    """Every target resource of a directory-audit event, flattened by name.

    Graph puts the objects an administrator acted on inside
    `targetResources`, a list, with the properties that changed nested one
    level deeper again under `modifiedProperties`. The engine flattens
    `raw_event` exactly one level, so a rule asking "which role was granted,
    and to whom" had nothing to read.

    This lifted the first target and its first modified property only, on the
    reasoning that almost every audit event has exactly one and that
    inventing `target_user_2` would give rules a field they cannot rely on
    being present. The hazard is real and is why nothing below is keyed by
    index; the premise was not. Issue #1718 measured ten alerts from a real
    tenant: a group-membership event carries the member *and* the group as
    two targets as a matter of course, and a device update's first modified
    property is the empty `Included Updated Properties` marker, so a device's
    id, OS and trust type were lost on every device event.

    What makes `target_user_2` unreliable is **position**, not plurality.
    Position is not semantics, so a rule written against index 2 passes a
    fixture where the group happened to be second and misses the event where
    it is first. So `targets` and `modified_properties` are keyed by what a
    thing *is* — its type, its property name — and every flat field derived
    from them is found by searching for that meaning rather than by counting:
    `target_group_name` looks for the group, `target_hostname` looks for the
    device. A rule clausing on one of those is making a claim about the
    event's semantics, which holds wherever in the list Graph put it.

    `modified_properties` maps a property name to its **new** value, which is
    what a reader of a change record wants. Anything that needs the previous
    value, or needs to know which target carried the change, reads `targets`,
    where every property keeps both halves.

    The original flat fields — `target_type`, `target_user`, `target_name`,
    `target_id`, `modified_property`, `old_value`, `new_value` — still
    describe `targetResources[0]` and its `modifiedProperties[0]` exactly as
    before, so every rule written against them is unaffected.
    """
    if not isinstance(targets, list) or not targets:
        return {}
    resources = [t for t in targets if isinstance(t, dict)]
    if not resources:
        return {}

    first = resources[0]
    out: dict[str, Any] = {
        "target_type": first.get("type"),
        "target_user": first.get("userPrincipalName"),
        "target_name": first.get("displayName"),
        "target_id": first.get("id"),
        "target_count": len(resources),
        "targets": [
            {
                "type": target.get("type"),
                "id": target.get("id"),
                "user_principal_name": target.get("userPrincipalName"),
                "display_name": target.get("displayName"),
                "modified_properties": [
                    {
                        "name": change.get("displayName"),
                        "old_value": _unquote(change.get("oldValue")),
                        "new_value": _unquote(change.get("newValue")),
                    }
                    for change in (target.get("modifiedProperties") or [])
                    if isinstance(change, dict)
                ],
            }
            for target in resources
        ],
    }

    modified = first.get("modifiedProperties")
    if isinstance(modified, list) and modified and isinstance(modified[0], dict):
        change = modified[0]
        out["modified_property"] = change.get("displayName")
        out["old_value"] = _unquote(change.get("oldValue"))
        out["new_value"] = _unquote(change.get("newValue"))

    # One map across every target. A property name repeated on two targets
    # keeps its first occurrence, which is the same precedence the flat
    # fields give `targetResources[0]`; both values are still in `targets`.
    properties: dict[str, str] = {}
    for target in out["targets"]:
        for change in target["modified_properties"]:
            name = change["name"]
            if isinstance(name, str) and name and name not in properties:
                properties[name] = change["new_value"]
    out["modified_properties"] = properties

    group = _targets_of_type(resources, "group")
    group_name = properties.get("Group.DisplayName") or (group or {}).get("displayName")
    group_id = properties.get("Group.ObjectID") or (group or {}).get("id")
    if group_name:
        out["target_group_name"] = group_name
    if group_id:
        out["target_group_id"] = group_id

    # A device target is a host, and saying so here is what lets it become
    # one: the ingest normalizer fills OCSF `device.name` from this, so the
    # alert row's `affected_hosts` and its correlation entity become the
    # device that changed rather than the Intune client that changed it.
    device = _targets_of_type(resources, "device")
    if device and device.get("displayName"):
        out["target_hostname"] = device["displayName"]
    device_id = properties.get("DeviceId") or (device or {}).get("id")
    if device_id:
        out["target_device_id"] = device_id
    if properties.get("DeviceOSType"):
        out["target_device_os"] = properties["DeviceOSType"]
    if properties.get("DeviceTrustType"):
        out["target_device_trust_type"] = properties["DeviceTrustType"]

    # Graph reports `result: success` for a directory call that completed and
    # changed nothing — adding a member who was already in the group returns
    # `DirectoryValueExistsException` in a modified property while the event
    # itself stays successful. The vendor's own verdict is reported as the
    # vendor wrote it; this names the execution result beside it so a reader
    # or a rule can tell a real add from a no-op, which is a distinction
    # neither field makes alone. Graph spells the key with a trailing dot.
    execution = properties.get("MethodExecutionResult.") or properties.get("MethodExecutionResult")
    if execution:
        out["method_execution_result"] = execution

    return out


class AzureEntraConnector(BaseConnector):
    """Microsoft Entra ID directory audits + risky sign-ins."""

    connector_id = "azure_entra"
    connector_name = "Microsoft Entra ID"
    connector_category = "iam"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Microsoft Entra ID (Azure AD) directory audits and risky "
                "sign-ins via Microsoft Graph. Requires AuditLog.Read.All "
                "and Directory.Read.All application permissions."
            ),
            docs_url="/docs/connectors/azure-entra",
            fields=[
                Field("tenant_id", "string", "Tenant ID", placeholder="00000000-0000-0000-0000-000000000000"),
                Field("client_id", "string", "Application (Client) ID"),
                Field("client_secret", "secret", "Client Secret"),
            ],
            oauth=OAuthHints(
                supported_in_hosted=True,
                authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
                scopes=[
                    "https://graph.microsoft.com/AuditLog.Read.All",
                    "https://graph.microsoft.com/Directory.Read.All",
                ],
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Entra ID surfaces both directory audits and risky sign-ins.
        return (Capability.PULL_AUDIT, Capability.PULL_ALERTS)

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._access_token: str | None = None

    # --------------------------- auth ---------------------------

    async def _authenticate(self) -> str:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                _TOKEN_URL.format(tenant_id=self._tenant_id),
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
            resp.raise_for_status()
            self._access_token = resp.json()["access_token"]
            return self._access_token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._access_token}",
            "Accept": "application/json",
        }

    # ------------------------- contract -------------------------

    async def test_connection(self) -> dict[str, Any]:
        try:
            await self._authenticate()
            # Hit a cheap Graph endpoint to confirm the token can actually
            # reach the directory; the token call alone doesn't verify scopes.
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{_GRAPH_BASE}/organization?$select=id,displayName",
                    headers=self._headers(),
                )
                resp.raise_for_status()
                orgs = resp.json().get("value", [])
            return {
                "success": True,
                "connector": self.connector_id,
                "tenant_id": self._tenant_id,
                "organization": orgs[0].get("displayName") if orgs else None,
            }
        except httpx.HTTPStatusError as exc:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": f"HTTP {exc.response.status_code}: {exc.response.text[:300]}",
            }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        if not self._access_token:
            await self._authenticate()

        # Graph wants ISO 8601 with milliseconds, e.g. ``2024-01-01T00:00:00.000Z``.
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        events: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Directory audits — admin/role/policy/group changes etc.
            audit_params = {
                "$filter": f"activityDateTime ge {since}",
                "$top": _PAGE_SIZE,
                "$orderby": "activityDateTime desc",
            }
            audit_resp = await client.get(
                f"{_GRAPH_BASE}/auditLogs/directoryAudits",
                headers=self._headers(),
                params=audit_params,
            )
            if audit_resp.status_code == 401:
                await self._authenticate()
                audit_resp = await client.get(
                    f"{_GRAPH_BASE}/auditLogs/directoryAudits",
                    headers=self._headers(),
                    params=audit_params,
                )
            if audit_resp.status_code == 200:
                for raw in await self._read_pages(client, audit_resp, "directory_audits"):
                    raw["_aisoc_event_kind"] = "directoryAudit"
                    events.append(raw)
            else:
                logger.warning(
                    "azure_entra.directory_audits.fetch_failed",
                    status=audit_resp.status_code,
                    body=audit_resp.text[:300],
                )

            # Risky sign-ins — these are higher-signal than every signIn.
            signin_params = {
                "$filter": (f"createdDateTime ge {since} and riskLevelAggregated ne 'none'"),
                "$top": _PAGE_SIZE,
                "$orderby": "createdDateTime desc",
            }
            signin_resp = await client.get(
                f"{_GRAPH_BASE}/auditLogs/signIns",
                headers=self._headers(),
                params=signin_params,
            )
            if signin_resp.status_code == 200:
                for raw in await self._read_pages(client, signin_resp, "risky_signins"):
                    raw["_aisoc_event_kind"] = "riskySignIn"
                    events.append(raw)
            else:
                logger.warning(
                    "azure_entra.risky_signins.fetch_failed",
                    status=signin_resp.status_code,
                    body=signin_resp.text[:300],
                )

        return [self.normalize(e) for e in events]

    async def _read_pages(self, client: httpx.AsyncClient, first: httpx.Response, feed: str) -> list[dict[str, Any]]:
        """Every entry of a Graph collection, starting from its first page.

        Graph returns ``$top`` entries and an ``@odata.nextLink`` while more
        remain. Reading only the first page kept the newest 200 entries of the
        window and dropped the rest; the next poll's window starts later, so
        they were never read. The link already carries the filter, ordering
        and skip token, so it is requested as-is. A failed later page keeps
        what was already read.
        """
        body = first.json()
        entries: list[dict[str, Any]] = list(body.get("value", []))
        for _ in range(_MAX_PAGES - 1):
            next_link = body.get("@odata.nextLink")
            if not next_link:
                return entries
            resp = await client.get(next_link, headers=self._headers())
            if resp.status_code != 200:
                logger.warning("azure_entra.next_page_failed", feed=feed, status=resp.status_code, body=resp.text[:300])
                return entries
            body = resp.json()
            entries.extend(body.get("value", []))
        if body.get("@odata.nextLink"):
            logger.warning("azure_entra.fetch_page_cap_reached", feed=feed, pages=_MAX_PAGES, entries=len(entries))
        return entries

    # ------------------------- posture --------------------------

    async def get_resource_config(self, resource_id: str, at_ts: str | None = None) -> dict[str, Any]:
        """Return the directory posture snapshot for the sentinel id.

        This connector models the identity plane, so the only resource it can
        describe is the directory itself. Any other id raises rather than
        returning ``{}``, because a caller asking for a resource that was
        never collectable should see that, not an empty config that reads as
        "this resource has no settings".
        """
        if resource_id != POSTURE_SNAPSHOT_ID:
            raise NotImplementedError(
                f"{self.connector_id} describes the directory, not individual resources; the only id it answers is {POSTURE_SNAPSHOT_ID!r}"
            )
        await self._authenticate()
        async with httpx.AsyncClient(timeout=30.0) as client:
            collected = await azure_posture.collect(client, self._headers(), tenant_id=self._tenant_id)
        return collected.to_resource_config()

    # ----------------------- normalize --------------------------

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        kind = raw.get("_aisoc_event_kind", "directoryAudit")

        if kind == "riskySignIn":
            risk = (raw.get("riskLevelAggregated") or "low").lower()
            severity = {
                "none": "info",
                "low": "low",
                "medium": "medium",
                "high": "high",
            }.get(risk, "medium")
            device = raw.get("deviceDetail") or {}
            location = raw.get("location") or {}
            return {
                "source": self.connector_id,
                "external_id": raw.get("id", ""),
                "title": f"Risky sign-in: {raw.get('userPrincipalName', 'unknown user')}",
                "description": (
                    f"riskLevel={risk}; "
                    f"riskState={raw.get('riskState')}; "
                    f"riskEventTypes={raw.get('riskEventTypes_v2', raw.get('riskEventTypes', []))}"
                ),
                "severity": severity,
                "src_ip": raw.get("ipAddress"),
                "actor": raw.get("userDisplayName"),
                "actor_email": raw.get("userPrincipalName"),
                "event_type": "azure.entra.signin.risky",
                # Depth 7.3 — adversary-in-the-middle session reuse. Graph's
                # `signIn` resource carries all of this and `normalize()`
                # emitted none of it, so a rule grouping by session or
                # comparing networks had nothing to read: the engine
                # flattens `raw_event` one level and `deviceDetail` arrives
                # as a dict.
                #
                # `sessionId` is read first and `correlationId` is **not** a
                # fallback for it. They mean different things: a correlation
                # id identifies one sign-in request, a session id identifies
                # the session the sign-in established. Substituting one for
                # the other would make every sign-in its own session and the
                # reuse detection could never fire, while looking like it
                # worked. Both are emitted under their own names and the
                # detection names the one it needs.
                "session_id": raw.get("sessionId"),
                "correlation_id": raw.get("correlationId"),
                "src_asn": raw.get("autonomousSystemNumber"),
                "src_country": location.get("countryOrRegion"),
                "user_agent": raw.get("userAgent"),
                "client_browser": device.get("browser"),
                "client_os": device.get("operatingSystem"),
                "client_app": raw.get("clientAppUsed"),
                "device_id": device.get("deviceId"),
                "device_compliant": device.get("isCompliant"),
                # Graph states this directly, so there is nothing to infer.
                # `None` when the field is absent, which is not the same as
                # single-factor: an older API version that does not return
                # it must not make every sign-in look unchallenged.
                "mfa_satisfied": (
                    None
                    if raw.get("authenticationRequirement") is None
                    else raw.get("authenticationRequirement") == "multiFactorAuthentication"
                ),
                "authentication_requirement": raw.get("authenticationRequirement"),
                "incoming_token_type": raw.get("incomingTokenType"),
                "raw_event": raw,
                "created_at": raw.get("createdDateTime"),
            }

        # directoryAudit
        result = (raw.get("result") or "").lower()
        category = raw.get("category", "")
        # Failed admin actions or anything in the AuthenticationMethod /
        # RoleManagement category gets bumped to medium since those are
        # the high-blast-radius levers.
        severity = "info"
        if result == "failure":
            severity = "medium"
        if category in ("RoleManagement", "AuthenticationMethod", "ConditionalAccess"):
            severity = "medium" if severity == "info" else severity
        if category == "RoleManagement" and result == "success":
            # role assignments are always worth surfacing
            severity = "high"

        initiator = raw.get("initiatedBy", {}) or {}
        user_part = initiator.get("user", {}) or {}
        app_part = initiator.get("app", {}) or {}

        # Issue #1718. Graph records a user acting through a first-party
        # client by putting the *client* in `user.displayName` and the person
        # in `user.userPrincipalName`, so preferring the display name named
        # "Microsoft Teams Services" as the actor on an event a person
        # performed. The principal name leads because it is the one field
        # that is a person whenever it is present at all. The display name is
        # not discarded, it is carried under its own name: nothing downstream
        # can tell from the value alone whether that slot held a person or a
        # client, so the connector states which is which instead of leaving a
        # reader to guess.
        actor_upn = user_part.get("userPrincipalName")
        actor_app = app_part.get("displayName")

        # Which kind of principal Graph recorded. Decided on whether a human
        # principal name initiated the change, not on which JSON slot
        # Microsoft used: a service initiator appears under `app` in some
        # categories and under `user` with no principal name in others, and a
        # detection separating an administrator's action from a self-service
        # one has to hold across both. Always a string so a clause on it
        # cannot silently stop matching, and "unknown" rather than a guess
        # when there is a principal with no name to judge by.
        if actor_upn:
            initiator_type = "user"
        elif app_part:
            initiator_type = "app"
        else:
            initiator_type = "unknown"

        return {
            "source": self.connector_id,
            "external_id": raw.get("id", ""),
            "title": raw.get("activityDisplayName", "Entra Directory Audit"),
            "description": (f"category={category}; result={raw.get('result')}; resultReason={raw.get('resultReason', '')}"),
            "severity": severity,
            "actor": actor_upn or user_part.get("displayName") or actor_app,
            "actor_email": actor_upn,
            "actor_app": actor_app,
            "actor_display_name": user_part.get("displayName"),
            "initiator_type": initiator_type,
            "src_ip": user_part.get("ipAddress"),
            "event_type": f"azure.entra.audit.{category.lower() or 'unknown'}",
            # `event_type` carries the *category*, which is far too coarse to
            # clause on: every role grant, removal and eligibility change in
            # the tenant shares `azure.entra.audit.rolemanagement`. The
            # activity is the thing a detection is about, so it is lifted
            # under its own name alongside a normalised form that survives
            # Graph's capitalisation.
            "activity": raw.get("activityDisplayName"),
            "activity_key": str(raw.get("activityDisplayName") or "").strip().lower().replace(" ", "_"),
            "operation_type": raw.get("operationType"),
            "audit_category": category,
            "audit_result": result,
            # `targetResources` is a list, and the engine flattens
            # `raw_event` one level — so the account a role was granted to,
            # and the role itself, were both invisible. A role-grant rule
            # could name the category and nothing about what was granted.
            **_target_fields(raw.get("targetResources")),
            "raw_event": raw,
            "created_at": raw.get("activityDateTime"),
        }
