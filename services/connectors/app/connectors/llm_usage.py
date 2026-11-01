"""AI / LLM provider audit connector.

Pulls **organization-level audit logs** from the places an enterprise's AI
activity is actually recorded, and folds each into the common AiSOC alert
shape. This is the governance surface for AI adoption: who created an API
key, who was granted owner, was audit logging or MFA turned off, who turned
a repository's agent loose, who consented an AI application into a mailbox.

It pairs with the `llm-*` and `ai-*` detection rules, which fire on the
emitted `event_type` (e.g. `openai.api_key.created`,
`github_copilot.copilot.swe_agent_mcp_config_updated`).

Providers and their references
------------------------------
Every endpoint, query parameter and event name below was read from the
vendor's current public reference before it was written. Nothing here is
inferred from another vendor's shape.

``openai``
    Organization audit logs. ``GET /v1/organization/audit_logs``.
``anthropic``
    Organization audit logs. ``GET /v1/organizations/audit_logs``.
``google_gemini``
    Gemini in Workspace apps, through the Admin SDK Reports API
    ``applicationName=gemini_in_workspace_apps``. Event names ``ai_usage_event``
    and ``feature_utilization``:
    https://developers.google.com/workspace/admin/reports/v1/appendix/activity/gemini-in-workspace-apps
``github_copilot``
    Organization audit log, filtered server-side to the ``copilot`` action
    namespace (``copilot.swe_agent_mcp_config_updated``,
    ``copilot.content_exclusion_changed``, ``copilot.custom_instructions_updated``
    and the seat/plan actions):
    https://docs.github.com/en/rest/orgs/orgs
``microsoft_copilot``
    Office 365 Management Activity API, content type ``Audit.General``.
    ``RecordType`` 261 ``CopilotInteraction`` and 284 ``AIAppInteraction`` are
    the two AI record types in the published schema:
    https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference
``entra_consent``
    Microsoft Graph ``auditLogs/directoryAudits``, for consent grants handing
    an AI application a scope:
    https://learn.microsoft.com/en-us/graph/api/directoryaudit-list

Why one connector with a selector rather than five connectors
-------------------------------------------------------------
Because the question an analyst asks is "what happened in our AI providers",
not "what happened in Gemini". One `event_type` namespace, one severity
ladder and one set of rules cover all of them; five connectors would mean
five profiles, five rule families and five places for the severity map to
drift. The cost is a constructor that validates per provider, which is why
each provider declares the fields it requires rather than every field being
required of every provider.

Why Workspace OAuth token grants are *not* here
-----------------------------------------------
`google_workspace` already polls the `token` application and emits those
activities. Adding a second reader for the same endpoint would double-count
every grant. What was missing was not collection but classification, and
that lives in the AI-asset recorder.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_LIMIT = 100

_OPENAI_BASE = "https://api.openai.com/v1/organization/audit_logs"
_ANTHROPIC_BASE = "https://api.anthropic.com/v1/organizations/audit_logs"
_GEMINI_BASE = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/gemini_in_workspace_apps"
_GITHUB_AUDIT_BASE = "https://api.github.com/orgs/{org}/audit-log"
_M365_BASE = "https://manage.office.com/api/v1.0/{tenant}/activity/feed/subscriptions/content"
_ENTRA_BASE = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"

#: The two AI record types in the Office 365 Management Activity API schema.
#: The same ``Audit.General`` feed carries the whole general audit, so a
#: reader that forwarded everything would turn the AI feed into the general
#: feed. Numeric because that is what the vendor emits; the names are carried
#: alongside for the event_type.
_M365_AI_RECORD_TYPES: dict[int, str] = {261: "CopilotInteraction", 284: "AIAppInteraction"}

#: Entra directory-audit activities that represent an application being
#: granted a scope. Matched case-insensitively on `activityDisplayName`,
#: which is the field the vendor populates for the portal's own label.
_ENTRA_CONSENT_ACTIVITIES = (
    "consent to application",
    "add delegated permission grant",
    "add app role assignment grant to user",
)

# event_type fragment -> severity floor.
_HIGH = (
    "api_key.created",
    "member.added",
    "invite",
    "service_account.created",
    # An agent's MCP server list and its network allowlist are the two
    # controls that decide what a hosted coding agent can reach. A change to
    # either is a scope change, not a settings change.
    "swe_agent_mcp_config_updated",
    "swe_agent_firewall_allowlist_updated",
    "consent_to_application",
)
_CRITICAL = ("logging", "mfa", "content_exclusion_changed")


class LlmUsageConnector(BaseConnector):
    """AI provider organization audit logs."""

    connector_id = "llm_usage"
    connector_name = "AI / LLM Usage Audit"
    connector_category = "saas"

    #: Declared once so the schema's select options and the constructor's
    #: accepted set cannot drift. A provider offered in the console wizard
    #: that the constructor rejects is a connector a tenant can save and
    #: never poll, which reads as a credential fault rather than a bug.
    PROVIDERS: tuple[str, ...] = (
        "openai",
        "anthropic",
        "google_gemini",
        "github_copilot",
        "microsoft_copilot",
        "entra_consent",
    )

    #: Extra field each provider needs beyond the key, and why. Enforced at
    #: construction: a missing scope-narrowing field has no URL to call, and
    #: the honest failure is a refusal rather than a 404 at poll time.
    _REQUIRES: dict[str, str] = {
        "github_copilot": "organization",
        "microsoft_copilot": "tenant",
    }

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Pull organization audit logs from an AI provider — API key "
                "creation, role grants, logging/MFA changes, Copilot agent "
                "and content-exclusion settings, and consent grants to AI "
                "applications. Pairs with the llm-* and ai-* detection "
                "rules. Auth is an admin/audit-scoped token."
            ),
            docs_url="/docs/connectors/llm_usage",
            fields=[
                Field(
                    "provider",
                    "select",
                    "Provider",
                    options=[
                        {"value": "openai", "label": "OpenAI"},
                        {"value": "anthropic", "label": "Anthropic"},
                        {"value": "google_gemini", "label": "Gemini in Google Workspace"},
                        {"value": "github_copilot", "label": "GitHub Copilot"},
                        {"value": "microsoft_copilot", "label": "Microsoft 365 Copilot"},
                        {"value": "entra_consent", "label": "Microsoft Entra AI app consent"},
                    ],
                ),
                Field("api_key", "secret", "Admin / Audit API Key"),
                Field(
                    "organization",
                    "string",
                    "GitHub organization",
                    required=False,
                    placeholder="acme",
                    help_text="Required for GitHub Copilot: the audit-log endpoint is organization-scoped.",
                ),
                Field(
                    "tenant",
                    "string",
                    "Microsoft tenant id",
                    required=False,
                    placeholder="00000000-0000-0000-0000-000000000000",
                    help_text="Required for Microsoft 365 Copilot: the Management Activity API path is tenant-scoped.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_AUDIT, Capability.READ_AUDIT_TRAIL)

    def __init__(
        self,
        provider: str,
        api_key: str,
        organization: str | None = None,
        tenant: str | None = None,
    ) -> None:
        provider = (provider or "").lower()
        if provider not in self.PROVIDERS:
            raise ValueError(f"llm_usage: unknown provider '{provider}' (need one of {', '.join(self.PROVIDERS)})")
        required = self._REQUIRES.get(provider)
        if required and not (organization if required == "organization" else tenant):
            raise ValueError(f"llm_usage: provider '{provider}' requires '{required}'")
        self._provider = provider
        self._api_key = api_key
        self._organization = organization
        self._tenant = tenant

    # ------------------------------------------------------------------
    # transport

    def _endpoint(self) -> str:
        if self._provider == "openai":
            return _OPENAI_BASE
        if self._provider == "anthropic":
            return _ANTHROPIC_BASE
        if self._provider == "google_gemini":
            return _GEMINI_BASE
        if self._provider == "github_copilot":
            return _GITHUB_AUDIT_BASE.format(org=self._organization)
        if self._provider == "microsoft_copilot":
            return _M365_BASE.format(tenant=self._tenant)
        return _ENTRA_BASE

    def _headers(self) -> dict[str, str]:
        if self._provider == "anthropic":
            return {"x-api-key": self._api_key, "anthropic-version": "2023-06-01", "Accept": "application/json"}
        if self._provider == "github_copilot":
            return {
                "Authorization": f"Bearer {self._api_key}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        return {"Authorization": f"Bearer {self._api_key}", "Accept": "application/json"}

    def _probe_params(self) -> dict[str, Any]:
        """Smallest request each provider accepts, for `test_connection`."""
        if self._provider == "google_gemini":
            return {"maxResults": 1}
        if self._provider == "github_copilot":
            return {"per_page": 1, "phrase": "action:copilot"}
        if self._provider == "microsoft_copilot":
            return {"contentType": "Audit.General"}
        if self._provider == "entra_consent":
            return {"$top": 1}
        return {"limit": 1}

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(self._endpoint(), headers=self._headers(), params=self._probe_params())
            if resp.status_code == 200:
                return {"success": True, "connector": self.connector_id, "provider": self._provider}
            return {"success": False, "connector": self.connector_id, "error": f"HTTP {resp.status_code}"}
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    def _fetch_params(self, since: int) -> dict[str, Any]:
        """Server-side filters, which are not an optimisation.

        Asking a provider for everything and discarding client-side pulls an
        organisation's entire audit stream through this process on every
        poll. For GitHub it is also the only way to stay inside the
        audit-log API's rate budget on a busy org.
        """
        if self._provider == "openai":
            return {"limit": _LIMIT, "effective_at[gte]": since}
        if self._provider == "anthropic":
            return {"limit": _LIMIT}
        if self._provider == "google_gemini":
            return {"maxResults": _LIMIT, "startTime": _rfc3339(since)}
        if self._provider == "github_copilot":
            return {"per_page": _LIMIT, "phrase": f"action:copilot created:>={_date(since)}"}
        if self._provider == "microsoft_copilot":
            return {"contentType": "Audit.General", "startTime": _iso_naive(since)}
        return {
            "$top": _LIMIT,
            "$filter": f"activityDateTime ge {_rfc3339(since)}",
        }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        since = int(time.time() - since_seconds)
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(self._endpoint(), headers=self._headers(), params=self._fetch_params(since))
                if resp.status_code != 200:
                    logger.warning("llm_usage.fetch_failed", provider=self._provider, status=resp.status_code)
                    return out
                body = resp.json()
                for record in await self._records(client, body):
                    if not self.is_ai_record(record):
                        continue
                    out.append(self.normalize(record))
        except Exception as exc:  # noqa: BLE001
            logger.warning("llm_usage.fetch_error", provider=self._provider, error=str(exc))
        return out

    async def _records(self, client: httpx.AsyncClient, body: Any) -> list[dict[str, Any]]:
        """Unwrap each provider's envelope into a flat record list.

        M365 is the one that needs a second request: the subscription
        endpoint returns *blob references*, not content, so a reader that
        stopped at the first response would poll successfully forever and
        emit nothing — the quietest possible failure.
        """
        if self._provider == "microsoft_copilot":
            records: list[dict[str, Any]] = []
            for blob in body if isinstance(body, list) else []:
                uri = (blob or {}).get("contentUri")
                if not uri:
                    continue
                blob_resp = await client.get(uri, headers=self._headers())
                if blob_resp.status_code != 200:
                    logger.warning("llm_usage.blob_failed", status=blob_resp.status_code)
                    continue
                payload = blob_resp.json()
                records.extend(r for r in (payload if isinstance(payload, list) else []) if isinstance(r, dict))
            return records
        if isinstance(body, list):
            return [r for r in body if isinstance(r, dict)]
        if not isinstance(body, dict):
            return []
        for key in ("data", "items", "value"):
            rows = body.get(key)
            if isinstance(rows, list):
                return [r for r in rows if isinstance(r, dict)]
        return []

    # ------------------------------------------------------------------
    # normalization

    def is_ai_record(self, raw: dict[str, Any]) -> bool:
        """Whether this record is AI activity at all.

        A separate predicate rather than a `None` return from `normalize`,
        for two reasons. `normalize` has one contract across 87 connectors
        and widening its return type here would weaken it everywhere. And
        the filter is a different question from the mapping: it is the one
        that keeps an AI feed an AI feed, so it deserves to be callable and
        tested on its own.

        The two providers that need it are Microsoft 365, whose
        `Audit.General` content type is the entire general audit, and
        Entra, whose directory audit is every directory change. For the
        other four the vendor filters server-side and every record returned
        is in scope.
        """
        if self._provider == "microsoft_copilot":
            record_type = raw.get("RecordType")
            return isinstance(record_type, int) and record_type in _M365_AI_RECORD_TYPES
        if self._provider == "entra_consent":
            return str(raw.get("activityDisplayName") or "").lower() in _ENTRA_CONSENT_ACTIVITIES
        return True

    def _event_type(self, raw: dict[str, Any]) -> str:
        """Dotted, provider-prefixed event type.

        Callers reach this only for records `is_ai_record` accepted, so the
        Microsoft 365 branch can rely on the record type being one of the
        two AI types.
        """
        if self._provider == "google_gemini":
            events = raw.get("events")
            first = events[0] if isinstance(events, list) and events and isinstance(events[0], dict) else {}
            vendor_type = str(first.get("type") or "ai_usage_event")
            name = str(first.get("name") or "")
            return f"{self._provider}.{vendor_type}.{name}" if name else f"{self._provider}.{vendor_type}"
        if self._provider == "github_copilot":
            return f"{self._provider}.{raw.get('action') or 'copilot.event'}"
        if self._provider == "microsoft_copilot":
            record_type = raw.get("RecordType")
            name = _M365_AI_RECORD_TYPES.get(record_type if isinstance(record_type, int) else -1, "AIRecord")
            return f"{self._provider}.{name}"
        if self._provider == "entra_consent":
            activity = str(raw.get("activityDisplayName") or "")
            return f"{self._provider}.{activity.lower().replace(' ', '_')}"
        vendor_type = str(raw.get("type") or raw.get("action") or raw.get("event_type") or "event")
        return f"{self._provider}.{vendor_type}"

    def _actor(self, raw: dict[str, Any]) -> str | None:
        if self._provider == "google_gemini":
            actor = raw.get("actor")
            return (actor or {}).get("email") if isinstance(actor, dict) else None
        if self._provider == "github_copilot":
            return _text(raw.get("actor"))
        if self._provider == "microsoft_copilot":
            return _text(raw.get("UserId"))
        if self._provider == "entra_consent":
            initiated = raw.get("initiatedBy")
            user = (initiated or {}).get("user") if isinstance(initiated, dict) else None
            return (user or {}).get("userPrincipalName") if isinstance(user, dict) else None
        actor = raw.get("actor") or {}
        return (actor.get("email") if isinstance(actor, dict) else None) or raw.get("actor_email")

    def _timestamp(self, raw: dict[str, Any]) -> Any:
        if self._provider == "google_gemini":
            ident = raw.get("id")
            return (ident or {}).get("time") if isinstance(ident, dict) else None
        if self._provider == "github_copilot":
            return raw.get("created_at")
        if self._provider == "microsoft_copilot":
            return raw.get("CreationTime")
        if self._provider == "entra_consent":
            return raw.get("activityDateTime")
        return raw.get("effective_at") or raw.get("occurred_at") or raw.get("timestamp")

    def _external_id(self, raw: dict[str, Any]) -> str:
        if self._provider == "google_gemini":
            ident = raw.get("id")
            return str((ident or {}).get("uniqueQualifier") or "") if isinstance(ident, dict) else ""
        if self._provider == "github_copilot":
            return str(raw.get("_document_id") or "")
        if self._provider == "microsoft_copilot":
            return str(raw.get("Id") or "")
        if self._provider == "entra_consent":
            return str(raw.get("id") or "")
        return str(raw.get("id") or "")

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """One vendor record as the common alert shape.

        Call `is_ai_record` first on the providers whose feed carries more
        than AI traffic; `fetch_alerts` does.
        """
        event_type = self._event_type(raw)
        low = event_type.lower()
        severity = "info"
        if any(h in low for h in _HIGH):
            severity = "high"
        if any(c in low for c in _CRITICAL):
            severity = "critical"
        actor_email = self._actor(raw)

        # The envelope the engine flattens one level. Enriched fields are
        # merged into it rather than left in a nested vendor structure the
        # matcher cannot reach: a field the connector reads and discards is
        # invisible to every rule that clauses on it.
        envelope = dict(raw)
        enrichment = self._enrich(raw)
        envelope.update(enrichment)

        event: dict[str, Any] = {
            "source": self.connector_id,
            "category": self.connector_category,
            "severity": severity,
            "title": f"{_label(self._provider)} audit: {event_type.split('.', 1)[-1]}",
            "description": f"provider={self._provider}; event_type={event_type}; actor={actor_email}",
            "external_id": self._external_id(raw),
            # Emit the dotted event_type at the TOP LEVEL so the llm-* and
            # ai-* detection rules (which match on `event_type`) fire.
            "event_type": event_type,
            "provider": self._provider,
            "actor": actor_email,
            "actor_email": actor_email,
            "created_at": self._timestamp(raw),
            # `raw_event`, not `raw`. The Go normalizer's isCanonicalEnvelope
            # check looks for `raw_event` + `source`; emitting `raw` missed
            # it, so these events fell through to the lenient fallback,
            # borrowed the splunk_enterprise profile, and were stamped Splunk
            # / Network Activity (class_uid 4001). Category 4 is not a
            # finding, so the promoter never turned any of them into an
            # alert. The key name is also what DetectionEngine._raw_fields
            # merges into the match namespace.
            "raw_event": envelope,
        }
        # Lift the enriched discriminators to the top level too, so a rule
        # can clause on them without depending on the one-level flatten.
        event.update(enrichment)
        return event

    def _enrich(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Vendor fields lifted into names a rule and the AI estate can read.

        Every value here comes from the record; nothing is derived from a
        name. The scope list in particular is what makes a consent grant
        scoreable — `score_risk` compares it against BROAD_OAUTH_SCOPES, and
        a grant whose scopes stayed buried in `modifiedProperties` would
        score as an unlinked grant with no scope at all.
        """
        if self._provider == "entra_consent":
            out: dict[str, Any] = {}
            targets = raw.get("targetResources")
            target = targets[0] if isinstance(targets, list) and targets and isinstance(targets[0], dict) else {}
            app_name = _text(target.get("displayName"))
            if app_name:
                out["application_name"] = app_name
            app_id = _text(target.get("id"))
            if app_id:
                out["application_id"] = app_id
            scopes = _entra_scopes(target)
            if scopes:
                # `granted_scopes`, not `scopes`. A consent grant's scopes
                # and a GitHub token's scopes are different things that
                # happen to share a word, and the detection-field gate
                # judges reachability against the **union** of every
                # connector's namespace — so emitting a bare `scopes` here
                # made a retired GitHub PAT rule look resolvable when
                # nothing had changed for GitHub at all. A precise name
                # costs nothing and does not lie to a gate.
                out["granted_scopes"] = scopes
            return out
        if self._provider == "google_gemini":
            events = raw.get("events")
            first = events[0] if isinstance(events, list) and events and isinstance(events[0], dict) else {}
            params = first.get("parameters")
            gemini: dict[str, Any] = {}
            for param in params if isinstance(params, list) else []:
                if isinstance(param, dict) and param.get("name"):
                    value = param.get("value", param.get("boolValue", param.get("intValue")))
                    if value is not None:
                        gemini[str(param["name"])] = value
            return gemini
        if self._provider == "microsoft_copilot":
            data = raw.get("CopilotEventData")
            if not isinstance(data, dict):
                return {}
            copilot: dict[str, Any] = {}
            host = _text(data.get("AppHost"))
            if host:
                copilot["app_host"] = host
            resources = data.get("AccessedResources")
            if isinstance(resources, list) and resources:
                copilot["accessed_resource_count"] = len(resources)
                labels = sorted(
                    {str(r.get("SensitivityLabelId")) for r in resources if isinstance(r, dict) and r.get("SensitivityLabelId")}
                )
                if labels:
                    copilot["sensitivity_labels"] = labels
            return copilot
        return {}


def _entra_scopes(target: dict[str, Any]) -> list[str]:
    """Scopes out of a consent grant's `modifiedProperties`.

    Graph records the granted permissions as a free-text `newValue` on a
    property named `ConsentAction.Permissions`, shaped `Scope: a b c`. The
    quotes Graph sometimes wraps the value in are stripped, and the result
    is sorted so two reads of the same grant produce the same list.
    """
    props = target.get("modifiedProperties")
    scopes: set[str] = set()
    for prop in props if isinstance(props, list) else []:
        if not isinstance(prop, dict):
            continue
        if str(prop.get("displayName") or "") != "ConsentAction.Permissions":
            continue
        value = str(prop.get("newValue") or "").strip().strip('"')
        _, _, tail = value.partition("Scope:")
        for token in (tail or value).replace(",", " ").split():
            token = token.strip().strip('"')
            if token:
                scopes.add(token)
    return sorted(scopes)


def _label(provider: str) -> str:
    return {
        "openai": "OpenAI",
        "anthropic": "Anthropic",
        "google_gemini": "Gemini",
        "github_copilot": "GitHub Copilot",
        "microsoft_copilot": "Microsoft 365 Copilot",
        "entra_consent": "Entra consent",
    }.get(provider, provider.capitalize())


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _rfc3339(epoch: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _iso_naive(epoch: int) -> str:
    """The Management Activity API takes a naive UTC datetime, no `Z`."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(epoch))


def _date(epoch: int) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(epoch))
