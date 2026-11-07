"""
GitLab group audit events + vulnerability findings connector.

Pulls two distinct streams in a single connector, mirroring the GitHub
connector pattern:

1. **Audit events** — ``GET /api/v4/groups/{group_id}/audit_events`` covers
   every group-level audit action: member adds, role changes, project
   creation/deletion, deploy-token edits, two-factor changes, etc.
   Requires a Personal Access Token with the ``api`` scope and the
   authenticating user must be an Owner of the group. On the SaaS plan
   audit events are available for Premium + Ultimate groups; on
   self-managed installations they ship from Premium up.

2. **Vulnerabilities** — the ``vulnerabilities`` connection on ``Group`` in
   GitLab's GraphQL API (``POST /api/graphql``). Surfaces Container
   Scanning, SAST, DAST, Secret Detection and Dependency Scanning results
   across every project in the group. Requires the ``api`` scope and a
   GitLab tier that exposes the Security Dashboard (Ultimate today).

Why the second stream is GraphQL and not REST
---------------------------------------------
This connector used to poll ``GET /groups/{id}/security/vulnerability_findings``.
No such route exists. GitLab answers it with **404 and Grape's
route-not-found body** ``{"error":"404 Not Found"}`` — byte-identical to the
answer for a path invented on the spot — while the sibling
``/groups/{id}/audit_events`` answers ``403 {"message":"403 Forbidden"}`` and
the one documented findings route, ``/projects/{id}/vulnerability_findings``,
answers ``401 {"message":"401 Unauthorized"}``. An existing route refuses
you by `message`; a route that was never served says `error`. So that stream
could not have returned a row on any deployment, and the connector reported
the 404 as a tier limitation, which is how it stayed invisible (issue #1754).

The documented REST route is project-scoped, and this connector is
configured with a group. Reaching it would mean enumerating the group's
projects and polling each: ``gitlab-org`` has **3,810 projects** with
subgroups, so one poll becomes thousands of requests every five minutes,
and a bound on that number silently stops scanning the rest of the group —
the same unread-window defect the paging work exists to prevent. The
endpoint also takes no time filter, returns no ``created_at`` to window on
client-side, defaults ``scope`` to ``dismissed``, and GitLab says of it:
"This API is in the process of being deprecated and considered unstable…
Use the GraphQL API instead."

``Group.vulnerabilities`` has none of those problems. It is group-scoped, so
there is nothing to enumerate and no bound to get wrong; it sorts
``detected_desc`` and every node carries ``detectedAt``, so the read stops at
the window rather than at an arbitrary count; and it pages with a real Relay
cursor. The exact query below was sent to ``https://gitlab.com/api/graphql``
and answered 200 with a live ``endCursor``.

Auth: Personal Access Token. We accept the token directly; OAuth is
deferred to Workstream 2 (the schema advertises the endpoints). Self-
managed installs work too — operators set the ``gitlab_url`` field to
the base URL of their instance.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx
import structlog

from app.connectors._paging import read_link_header_pages, read_token_pages
from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

_DEFAULT_BASE = "https://gitlab.com"
_PER_PAGE = 100

#: ``Group.vulnerabilities``, newest first. Every field here was checked
#: against the live schema by introspection and the whole query was then
#: executed against ``gitlab.com/api/graphql``; GitLab answered 200 with a
#: real ``endCursor``, which is the contract the old REST route never had.
#:
#: ``sort: detected_desc`` plus ``detectedAt`` is what makes a clock-derived
#: poll window readable here: the connection has no time argument, so the
#: read walks from the newest vulnerability until one falls below the start
#: of the window and then stops.
_VULNERABILITIES_QUERY = """
query($fullPath: ID!, $after: String, $first: Int!) {
  group(fullPath: $fullPath) {
    vulnerabilities(sort: detected_desc, first: $first, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes {
        id
        uuid
        title
        description
        severity
        state
        reportType
        detectedAt
        webUrl
        project { id name fullPath }
        scanner { id name vendor }
        identifiers { externalType externalId name url }
      }
    }
  }
}
"""

_VULN_NODES = "data.group.vulnerabilities.nodes"
_VULN_CURSOR = "data.group.vulnerabilities.pageInfo.endCursor"


def _detected_before(node: dict[str, Any], start: datetime) -> bool:
    """Was this vulnerability detected before the window opened?

    A node with no usable ``detectedAt`` answers False, so it is kept and
    the read continues. Dropping it would be the quieter of the two wrong
    answers and the worse one: this is the only field that windows the
    stream, and a parse that silently fails would empty the feed.
    """
    value = node.get("detectedAt")
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")) < start
    except ValueError:
        return False


class GitLabConnector(BaseConnector):
    """GitLab group audit events + vulnerability findings."""

    connector_id = "gitlab"
    connector_name = "GitLab"
    connector_category = "vcs"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "GitLab group audit events and security vulnerabilities. "
                "Requires a Personal Access Token with the 'api' scope; the "
                "authenticating user must own the group. Vulnerabilities are "
                "read from the group security dashboard and need Ultimate — "
                "without it you get audit events only. Self-managed GitLab "
                "works too — set gitlab_url to your instance base URL."
            ),
            docs_url="/docs/connectors/gitlab",
            fields=[
                Field(
                    "gitlab_url",
                    "string",
                    "GitLab base URL",
                    placeholder=_DEFAULT_BASE,
                    help_text=(
                        "Leave default for gitlab.com. For self-managed "
                        "installations, paste the URL operators use to "
                        "reach the web UI (no trailing slash)."
                    ),
                ),
                Field(
                    "group",
                    "string",
                    "Group path or numeric ID",
                    placeholder="my-org or 1234567",
                ),
                Field(
                    "token",
                    "secret",
                    "Personal Access Token (scope: api)",
                    help_text=(
                        "PAT with the 'api' scope. The authenticating "
                        "user must be a group Owner to read audit "
                        "events. Vulnerabilities additionally require "
                        "Ultimate; on any lower plan the connector still "
                        "polls audit events and says so in its logs."
                    ),
                ),
            ],
            # Workstream 2 — hosted OAuth. GitLab supports OAuth 2.0 PKCE
            # for both gitlab.com and self-managed instances; the
            # authorize/token URLs below are gitlab.com defaults that the
            # router rewrites per-tenant if a custom gitlab_url is set.
            oauth=OAuthHints(
                supported_in_hosted=True,
                authorize_url=f"{_DEFAULT_BASE}/oauth/authorize",
                token_url=f"{_DEFAULT_BASE}/oauth/token",
                scopes=["api", "read_api"],
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # GitLab group audit log + security vulnerability findings.
        return (Capability.PULL_AUDIT, Capability.PULL_ALERTS)

    def __init__(
        self,
        group: str,
        token: str,
        gitlab_url: str | None = None,
    ):
        self._group = group
        self._token = token
        self._base = (gitlab_url or _DEFAULT_BASE).rstrip("/")

    # --------------------------- auth ---------------------------

    def _headers(self) -> dict[str, str]:
        return {
            # GitLab accepts both Bearer and PRIVATE-TOKEN; PRIVATE-TOKEN
            # is the historical PAT header and works on every plan.
            "PRIVATE-TOKEN": self._token,
            "Accept": "application/json",
        }

    @property
    def _group_path(self) -> str:
        """URL-encoded group slug.

        GitLab's API accepts either a numeric ID or a URL-encoded full
        path. The user supplies one of those forms; we encode it here so
        slashes inside nested-group paths (``parent/child``) survive.
        """
        return quote(str(self._group), safe="")

    # ------------------------- contract -------------------------

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # ``/groups/{id}`` is cheap and returns 200 for any
                # authenticated token that can read the group; 401 / 403
                # is the canonical "bad token or missing access" signal,
                # 404 means the group path is wrong.
                resp = await client.get(
                    f"{self._base}/api/v4/groups/{self._group_path}",
                    headers=self._headers(),
                )
                if resp.status_code != 200:
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
                    }

                # Audit-events probe — confirms the token has the right
                # tier + ownership for the audit stream. 200+[] on a quiet
                # group, 403 if the user isn't an owner or the plan does not
                # include audit events. A 404 cannot reach here: the line
                # above already proved the group resolves, and this route
                # exists on every instance.
                audit_resp = await client.get(
                    f"{self._base}/api/v4/groups/{self._group_path}/audit_events",
                    headers=self._headers(),
                    params={"per_page": 1},
                )
                if audit_resp.status_code not in (200, 403):
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": (f"Group reachable but audit-events probe failed: HTTP {audit_resp.status_code}: {audit_resp.text[:200]}"),
                    }
                audit_available = audit_resp.status_code == 200

            return {
                "success": True,
                "connector": self.connector_id,
                "group": self._group,
                "gitlab_url": self._base,
                "audit_events_available": audit_available,
            }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        # Audit events take ``created_after`` on the endpoint and page
        # through the ``Link`` header. The vulnerabilities connection has no
        # time argument at all, so that half sorts newest-first and stops
        # client-side at the window, paging on its Relay cursor instead.
        start = datetime.now(UTC) - timedelta(seconds=since_seconds)
        start_iso = start.strftime("%Y-%m-%dT%H:%M:%SZ")

        events: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            # 1) audit events
            audit_resp = await client.get(
                f"{self._base}/api/v4/groups/{self._group_path}/audit_events",
                headers=self._headers(),
                params={
                    "created_after": start_iso,
                    "per_page": _PER_PAGE,
                    # Offset pagination on this endpoint is deprecated. These
                    # are the only ordering values it allows under keyset.
                    "pagination": "keyset",
                    "order_by": "id",
                    "sort": "desc",
                },
            )
            if audit_resp.status_code == 200:
                for entry in await read_link_header_pages(client, audit_resp, headers=self._headers(), feed="gitlab.audit_events"):
                    entry["_aisoc_stream"] = "audit_events"
                    events.append(entry)
            elif audit_resp.status_code == 403:
                # The route exists and refused us: the token is not a group
                # Owner, or the group's tier does not include audit events.
                # A real operator condition, and nothing here can fix it.
                logger.info(
                    "gitlab.audit_events_forbidden",
                    group=self._group,
                    detail="the token is not a group Owner, or this group's plan does not include audit events",
                )
            elif audit_resp.status_code == 404:
                # Deliberately not the same branch as 403. The audit-events
                # route exists — gitlab.com answers it 403 for a caller who
                # may not read it — so a 404 is about the *group*: the
                # configured path is wrong, or this token cannot see it and
                # GitLab is 404ing rather than confirming it exists. Saying
                # "tier or ownership missing" sends the operator to the
                # wrong setting, which is how #1754 hid for as long as it did.
                logger.warning(
                    "gitlab.group_not_found",
                    group=self._group,
                    gitlab_url=self._base,
                    detail="no group at this path on this instance, or the token cannot see it — check the group field",
                )
            else:
                logger.warning(
                    "gitlab.audit_events_failed",
                    status=audit_resp.status_code,
                    body=audit_resp.text[:300],
                )

            # 2) vulnerabilities, over GraphQL. Ultimate-tier only; a group
            # without it answers with the field absent rather than an error.
            for node in await self._fetch_vulnerabilities(client, start):
                node["_aisoc_stream"] = "vulnerability_finding"
                events.append(node)

        return [self.normalize(e) for e in events]

    async def _fetch_vulnerabilities(self, client: httpx.AsyncClient, start: datetime) -> list[dict[str, Any]]:
        """Group vulnerabilities detected inside the poll window, newest first.

        GraphQL answers 200 for everything, so the three outcomes that are
        not data have to be told apart here rather than by a status code —
        and this is the same distinction the REST side of this file now
        makes, for the same reason. ``errors`` means the query is wrong,
        which is *our* defect and must never read as a quiet estate; a null
        ``group`` means the path is wrong or invisible to this token; a null
        ``vulnerabilities`` means the tier does not expose the field. Only
        the last of those is a plan limitation.

        Whatever went wrong, the pages already read are kept — the same
        property the shared readers in ``_paging.py`` hold, because turning a
        vendor hiccup on page four into zero rows is the data loss this
        family of code exists to prevent.
        """

        async def page(cursor: str | None) -> httpx.Response:
            resp = await client.post(
                f"{self._base}/api/graphql",
                headers={**self._headers(), "Content-Type": "application/json"},
                json={
                    "query": _VULNERABILITIES_QUERY,
                    "variables": {"fullPath": str(self._group), "after": cursor, "first": _PER_PAGE},
                },
            )
            if resp.status_code != 200:
                return resp
            try:
                body = resp.json()
            except ValueError:
                return resp
            if not isinstance(body, dict):
                # Not a GraphQL envelope at all. Something is answering this
                # URL that is not GitLab; the helper will find no rows, so
                # the one thing that must not happen is doing it silently.
                logger.warning(
                    "gitlab.vulnerabilities_response_unrecognised",
                    group=self._group,
                    gitlab_url=self._base,
                    body=resp.text[:200],
                )
                return resp
            if body.get("errors"):
                logger.warning(
                    "gitlab.vulnerabilities_query_rejected",
                    group=self._group,
                    errors=[str(e.get("message"))[:200] for e in body["errors"][:3]],
                    detail="GitLab refused this query — a schema change on our side, not a tenant configuration",
                )
            elif (body.get("data") or {}).get("group") is None:
                logger.warning(
                    "gitlab.group_not_found",
                    group=self._group,
                    gitlab_url=self._base,
                    detail="no group at this path on this instance, or the token cannot see it — check the group field",
                )
            elif ((body.get("data") or {}).get("group") or {}).get("vulnerabilities") is None:
                logger.info(
                    "gitlab.vulnerabilities_unavailable",
                    group=self._group,
                    detail="this group's plan does not expose the security dashboard; audit events are unaffected",
                )
            return resp

        nodes = await read_token_pages(
            request=page,
            items_field=_VULN_NODES,
            token_field=_VULN_CURSOR,
            feed="gitlab.vulnerabilities",
            # Sorted newest-first with no server-side time filter, so the
            # page whose *last* node predates the window is the last page
            # worth asking for.
            stop_when=lambda nodes: _detected_before(nodes[-1], start),
        )
        return [node for node in nodes if not _detected_before(node, start)]

    # ----------------------- normalize --------------------------

    # GitLab ``action_name`` strings that we always treat as high.
    # Maintained from the public docs (gitlab.com/help/administration/
    # audit_event_streaming/audit_event_types).
    _HIGH_RISK_ACTIONS = (
        # group membership / ownership
        "user_add",
        "user_remove",
        "change_role",
        "transfer_ownership",
        # access tokens / SSH / OAuth
        "personal_access_token_create",
        "personal_access_token_revoke",
        "group_access_token_create",
        "project_access_token_create",
        "ssh_key_add",
        "two_factor_authentication_disabled",
        # branch / project protection bypass
        "remove_protected_branch",
        "remove_protected_tag",
        # project / group destruction
        "project_destroyed",
        "group_destroyed",
        "project_transfer",
        # security feature tampering
        "security_dashboard_disabled",
        "container_scanning_disabled",
        "sast_disabled",
        "secret_detection_disabled",
        # CI/CD risky surface
        "ci_cd_settings_changed",
        "runner_registered",
    )

    def _normalize_audit(self, raw: dict[str, Any]) -> dict[str, Any]:
        # ``details`` is a nested dict with the human-readable change; the
        # action key sits inside it.
        details = raw.get("details") or {}
        action = details.get("custom_message") or details.get("action") or details.get("event_name") or details.get("change") or ""
        # Best-effort actor extraction — GitLab places the user name in
        # ``author_name`` (or ``details.author_name`` on streamed events).
        actor = raw.get("author_name") or details.get("author_name") or "unknown"

        action_lower = action.lower()
        if any(h in action_lower for h in self._HIGH_RISK_ACTIONS):
            severity = "high"
        elif "destroy" in action_lower or "delete" in action_lower or "remove" in action_lower:
            severity = "medium"
        else:
            severity = "info"

        return {
            "source": self.connector_id,
            "external_id": str(raw.get("id") or ""),
            "title": action or "GitLab audit event",
            "description": (
                f"actor={actor}; action={action}; entity_type={raw.get('entity_type', '')}; entity_id={raw.get('entity_id', '')}"
            ),
            "severity": severity,
            "actor": actor,
            "actor_email": details.get("author_email"),
            "src_ip": details.get("ip_address"),
            "event_type": f"gitlab.{action_lower or 'audit'}",
            # `details` is a dict and the engine flattens `raw_event` one
            # level, so the object an audit event acted on -- the key that
            # was added, the member whose access changed -- was invisible.
            # `event_type` is built from GitLab's free-text `custom_message`
            # and therefore carries spaces ("gitlab.added deploy key"), so a
            # stable underscored key is lifted beside it for rules to clause
            # on; the original stays for anyone reading an alert.
            "action_key": (action_lower or "audit").replace(" ", "_"),
            "target_type": details.get("target_type"),
            "target_details": details.get("target_details"),
            "target_id": details.get("target_id"),
            "entity_type": raw.get("entity_type"),
            "entity_path": raw.get("entity_path"),
            "raw_event": raw,
            "created_at": raw.get("created_at"),
        }

    # GraphQL returns the severity as an upper-case enum member
    # (``CRITICAL``/``HIGH``/…/``UNKNOWN``); it is lower-cased before the
    # lookup. AiSOC's 5-tier ladder (info | low | medium | high | critical)
    # preserves the critical tier end-to-end so Ultimate-tier SAST/DAST P1s
    # keep their priority.
    _FINDING_SEVERITY_MAP = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "unknown": "info",
    }

    def _normalize_finding(self, raw: dict[str, Any]) -> dict[str, Any]:
        """One ``Group.vulnerabilities`` node.

        The engine flattens ``raw_event`` exactly one level, so the project
        and scanner names and the primary identifier are lifted to the top
        level here — a rule clausing on a nested key would compare a dict
        and could never fire.
        """
        gl_severity = (raw.get("severity") or "").lower()
        severity = self._FINDING_SEVERITY_MAP.get(gl_severity, "info")

        scanner = (raw.get("scanner") or {}).get("name") or ""
        project_block = raw.get("project") or {}
        project = project_block.get("name") or ""
        identifiers = raw.get("identifiers")
        first = identifiers[0] if isinstance(identifiers, list) and identifiers else None
        identifier_value = (first.get("name") or first.get("externalId") or "") if isinstance(first, dict) else ""
        state = (raw.get("state") or "").lower()
        report_type = (raw.get("reportType") or "").lower()

        return {
            "source": self.connector_id,
            "external_id": f"finding-{raw.get('uuid') or raw.get('id') or ''}",
            "title": raw.get("title") or f"GitLab vulnerability ({scanner})",
            "description": (f"project={project}; scanner={scanner}; identifier={identifier_value}; state={state}"),
            "severity": severity,
            "actor": "gitlab-security",
            "actor_email": None,
            "src_ip": None,
            "event_type": f"gitlab.security.{scanner}" if scanner else "gitlab.security",
            "finding_state": state,
            "report_type": report_type,
            "scanner_name": scanner,
            "project_name": project,
            "project_path": project_block.get("fullPath"),
            "identifier": identifier_value,
            "url": raw.get("webUrl"),
            "raw_event": raw,
            "created_at": raw.get("detectedAt"),
        }

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        stream = raw.get("_aisoc_stream", "audit_events")
        if stream == "vulnerability_finding":
            return self._normalize_finding(raw)
        return self._normalize_audit(raw)
