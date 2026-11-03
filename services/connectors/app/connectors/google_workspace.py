"""
Google Workspace audit logs connector.

Pulls activity events for the high-signal Workspace apps (login, admin,
drive, token, mobile) via the Reports API. Auth uses a service account JSON
key with domain-wide delegation, plus an admin email to impersonate — that's
the model Google requires for org-wide audit log access.

Reuses the manual JWT signing pattern from the GCP connectors. The crucial
difference is that Workspace requires the JWT ``sub`` claim to be set to the
admin user being impersonated; without that, the token endpoint returns
``invalid_grant`` even when the service account is otherwise correct.

ApplicationName values monitored by default:
    login   - all login activity (success + failure + suspicious)
    admin   - super-admin / delegated-admin operations (high blast radius)
    drive   - file shares, ACL changes, external shares
    token   - OAuth token grants (consent screen activity, app authorization)
    mobile  - device events (lost device, wipe, jailbreak detection)
"""

from __future__ import annotations

import base64
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints
from app.connectors.posture import POSTURE_SNAPSHOT_ID, Collected
from app.connectors.posture import gws as gws_posture

logger = structlog.get_logger()

_TOKEN_URL = "https://oauth2.googleapis.com/token"
_REPORTS_BASE = "https://admin.googleapis.com/admin/reports/v1/activity"
_SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"

# Posture collection reads the directory, which the audit-log scope above
# does not cover. These are requested as a separate token so an operator who
# has only authorised the reports scope keeps working alert polling and sees
# a clear failure on the posture call alone.
_DIRECTORY_SCOPE = " ".join(
    (
        "https://www.googleapis.com/auth/admin.directory.user.readonly",
        "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
        "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
    )
)

_DEFAULT_APPS = ("login", "admin", "drive", "token", "mobile")
_PAGE_SIZE = 500


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class GoogleWorkspaceConnector(BaseConnector):
    """Google Workspace (Admin SDK Reports API) audit log connector."""

    connector_id = "google_workspace"
    connector_name = "Google Workspace"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Google Workspace audit logs (login, admin, drive, token, "
                "mobile) via the Admin SDK Reports API. Requires a service "
                "account with domain-wide delegation and an admin email to "
                "impersonate."
            ),
            docs_url="/docs/connectors/google-workspace",
            fields=[
                Field(
                    "admin_email",
                    "string",
                    "Super-admin email",
                    placeholder="audit-bot@example.com",
                    help_text=(
                        "The Google Workspace super-admin to impersonate via "
                        "domain-wide delegation. The service account's "
                        "client_id must be authorized in the Admin Console "
                        "with the admin.reports.audit.readonly scope."
                    ),
                ),
                Field(
                    "service_account_json",
                    "secret",
                    "Service account JSON key",
                    help_text=("Paste the full JSON key file. Encrypted at rest by the credential vault."),
                ),
            ],
            oauth=OAuthHints(
                supported_in_hosted=False,
                authorize_url=None,
                token_url=_TOKEN_URL,
                scopes=[_SCOPE],
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Google Workspace Reports API — admin/login/drive/etc. audit activities.
        return (Capability.PULL_AUDIT,)

    def __init__(self, admin_email: str, service_account_json: str):
        self._admin_email = admin_email
        self._sa_info = self._parse_sa(service_account_json)
        # Keyed by scope: audit-log polling and posture collection need
        # different Google scopes, and a domain-wide-delegation token request
        # fails outright for any scope the operator has not authorised. One
        # shared token would therefore make posture collection able to break
        # alert polling, so each scope holds its own.
        self._tokens: dict[str, tuple[str, float]] = {}

    # --------------------------- auth ---------------------------

    @staticmethod
    def _parse_sa(blob: str) -> dict[str, Any]:
        try:
            sa = json.loads(blob)
        except json.JSONDecodeError as exc:
            raise ValueError("service_account_json is not valid JSON. Paste the entire key file contents.") from exc
        for required in ("client_email", "private_key", "token_uri"):
            if required not in sa:
                raise ValueError(f"service_account_json missing required field: {required}")
        return sa

    def _build_jwt(self, scope: str = _SCOPE) -> str:
        """Build a JWT with the ``sub`` claim set to the impersonated admin —
        this is what makes domain-wide delegation actually work."""
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": self._sa_info["client_email"],
            "scope": scope,
            "aud": self._sa_info.get("token_uri", _TOKEN_URL),
            "iat": now,
            "exp": now + 3600,
            # The "act on behalf of" admin user. Without this, Google
            # rejects the token even when DWD is correctly configured.
            "sub": self._admin_email,
        }
        signing_input = (
            _b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + _b64url(json.dumps(claims, separators=(",", ":")).encode())
        ).encode("ascii")
        private_key = serialization.load_pem_private_key(
            self._sa_info["private_key"].encode("utf-8"),
            password=None,
        )
        signature = private_key.sign(  # type: ignore[union-attr]
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return signing_input.decode("ascii") + "." + _b64url(signature)

    async def _authenticate(self, scope: str = _SCOPE) -> str:
        cached = self._tokens.get(scope)
        if cached and time.time() < cached[1] - 60:
            return cached[0]
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                self._sa_info.get("token_uri", _TOKEN_URL),
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": self._build_jwt(scope),
                },
            )
            resp.raise_for_status()
            payload = resp.json()
            token = payload["access_token"]
            self._tokens[scope] = (token, time.time() + int(payload.get("expires_in", 3600)))
            return token

    def _invalidate(self, scope: str = _SCOPE) -> None:
        self._tokens.pop(scope, None)

    def _headers(self, scope: str = _SCOPE) -> dict[str, str]:
        token, _ = self._tokens.get(scope, ("", 0.0))
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    # ------------------------- contract -------------------------

    async def test_connection(self) -> dict[str, Any]:
        try:
            await self._authenticate()
            # Pull a single login event as the cheapest verification: it
            # confirms (a) the token, (b) DWD is configured for our SA,
            # and (c) the admin email exists and has permission.
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{_REPORTS_BASE}/users/all/applications/login",
                    headers=self._headers(),
                    params={"maxResults": 1},
                )
                resp.raise_for_status()
            return {
                "success": True,
                "connector": self.connector_id,
                "admin_email": self._admin_email,
                "service_account": self._sa_info["client_email"],
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
        await self._authenticate()
        start_time = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        events: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            for app_name in _DEFAULT_APPS:
                resp = await client.get(
                    f"{_REPORTS_BASE}/users/all/applications/{app_name}",
                    headers=self._headers(),
                    params={"startTime": start_time, "maxResults": _PAGE_SIZE},
                )
                if resp.status_code == 401:
                    self._invalidate()
                    await self._authenticate()
                    resp = await client.get(
                        f"{_REPORTS_BASE}/users/all/applications/{app_name}",
                        headers=self._headers(),
                        params={"startTime": start_time, "maxResults": _PAGE_SIZE},
                    )
                if resp.status_code != 200:
                    logger.warning(
                        "google_workspace.fetch_failed",
                        application=app_name,
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    continue
                items = resp.json().get("items", [])
                # Tag each item with the app name so normalize() doesn't
                # have to crack open ``id.applicationName`` (which is
                # present, but explicit beats implicit).
                for item in items:
                    item["_aisoc_application"] = app_name
                    events.append(item)

        return [self.normalize(e) for e in events]

    # ------------------------- posture --------------------------

    async def get_resource_config(self, resource_id: str, at_ts: str | None = None) -> dict[str, Any]:
        """Return the Workspace directory posture snapshot for the sentinel id.

        This connector reads the Reports API and the directory, neither of
        which addresses an individual "resource" the way a cloud connector
        does, so any other id raises rather than returning an empty config
        that would read as "this resource has no settings".
        """
        if resource_id != POSTURE_SNAPSHOT_ID:
            raise NotImplementedError(
                f"{self.connector_id} describes the Workspace directory, not individual resources; "
                f"the only id it answers is {POSTURE_SNAPSHOT_ID!r}"
            )
        try:
            await self._authenticate(_DIRECTORY_SCOPE)
        except httpx.HTTPStatusError as exc:
            # Almost always an operator who authorised the reports scope and
            # not the directory ones. Saying which scopes are missing is the
            # difference between a two-minute fix and a support thread.
            collected = Collected(snapshot={})
            collected.note(
                f"could not mint a directory token (HTTP {exc.response.status_code}). The service "
                f"account's domain-wide delegation must also authorise: {_DIRECTORY_SCOPE}"
            )
            return collected.to_resource_config()
        async with httpx.AsyncClient(timeout=60.0) as client:
            collected = await gws_posture.collect(client, self._headers(_DIRECTORY_SCOPE))
        return collected.to_resource_config()

    # ----------------------- normalize --------------------------

    # Workspace event names that we always treat as high-severity. These are
    # all admin-console actions or auth events that materially change the
    # security posture of the org.
    _HIGH_RISK_EVENTS = (
        # admin app
        "GRANT_ADMIN_PRIVILEGE",
        "REVOKE_ADMIN_PRIVILEGE",
        "CREATE_ROLE",
        "DELETE_ROLE",
        "ASSIGN_ROLE",
        "DELEGATE_ADMIN_PRIVILEGES",
        # 2sv / mfa weakening
        "ENFORCE_STRONG_AUTHENTICATION",
        "UNENROLL_USER_FROM_STRONG_AUTH",
        "ALLOW_STRONG_AUTHENTICATION",
        "DISABLE_USER_2SV",
        # password resets and account changes
        "RESET_PASSWORD",
        "CHANGE_PASSWORD",
        "SUSPEND_USER",
        "UNSUSPEND_USER",
        # OAuth grants are the textbook M365 / Workspace BEC vector
        "authorize",
        "activity",
        # mobile
        "DEVICE_COMPROMISED_EVENT",
        "FAILED_PASSWORD_ATTEMPTS_EVENT",
    )

    # login app event names that mean "this auth attempt was suspicious"
    _SUSPICIOUS_LOGIN_EVENTS = (
        "login_failure",
        "suspicious_login",
        "suspicious_login_less_secure_app",
        "suspicious_programmatic_login",
        "gov_attack_warning",
        "login_challenge",
    )

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        application = raw.get("_aisoc_application") or raw.get("id", {}).get("applicationName")
        actor = (raw.get("actor") or {}).get("email", "unknown")
        # The Reports API encodes individual events as a list under each
        # activity. Most activities have a single event; a few bundle
        # multiple. We pick the first to drive severity / title and
        # surface the full list in raw_event.
        events_list = raw.get("events") or []
        primary_event = events_list[0] if events_list else {}
        event_name = primary_event.get("name", "")

        # Severity heuristic mirrors the M365 connector: high-risk admin
        # ops and OAuth grants → high; suspicious login → medium; failed
        # logins → low; everything else → info.
        severity = "info"
        if any(h.lower() in event_name.lower() for h in self._HIGH_RISK_EVENTS):
            severity = "high"
        elif application == "login" and event_name in self._SUSPICIOUS_LOGIN_EVENTS:
            severity = "medium" if event_name != "login_failure" else "low"
        elif application == "drive" and event_name in (
            "change_acl_editors",
            "change_user_access",
            "create_link_sharing",
            "shared_drive_settings_change",
        ):
            severity = "medium"

        # Pull the IP address out of the activity envelope; not all events
        # have it, but login/admin/drive almost always do.
        ip_address = raw.get("ipAddress")

        # The Reports API puts everything that distinguishes one activity
        # from another inside `events[].parameters` — the OAuth scopes a
        # consent granted, the role an admin assigned, the visibility a
        # share opened, the address a forward was pointed at. `events` is a
        # list, so the engine's one-level `raw_event` flatten cannot reach
        # any of it and a rule clausing on a scope or a role read None.
        #
        # Each parameter is lifted under `param_<name lowercased>`, keeping
        # Google's own names rather than inventing a mapping that would have
        # to be maintained against an API that keeps adding activities.
        # `multiValue` and `boolValue` are preserved as a list and a bool so
        # `_has_any` and an equality clause both work.
        params: dict[str, Any] = {}
        for parameter in primary_event.get("parameters") or []:
            if not isinstance(parameter, dict):
                continue
            name = parameter.get("name")
            if not isinstance(name, str) or not name:
                continue
            if "multiValue" in parameter:
                value: Any = parameter.get("multiValue")
            elif "boolValue" in parameter:
                value = parameter.get("boolValue")
            elif "intValue" in parameter:
                value = parameter.get("intValue")
            else:
                value = parameter.get("value")
            params[f"param_{name.lower()}"] = value

        return {
            "source": self.connector_id,
            "external_id": (raw.get("id") or {}).get("uniqueQualifier", ""),
            "title": event_name or f"Workspace {application} event",
            "description": (f"application={application}; event={event_name}; actor={actor}"),
            "severity": severity,
            "actor": actor,
            "actor_email": actor if "@" in actor else None,
            "src_ip": ip_address,
            "application": application,
            "event_name": event_name,
            "event_name_type": primary_event.get("type"),
            "event_type": (f"workspace.{application}.{event_name}".lower() if application and event_name else "workspace.audit"),
            **params,
            "raw_event": raw,
            "created_at": (raw.get("id") or {}).get("time"),
        }
