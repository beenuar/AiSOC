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

from app.connectors.base import BaseConnector, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

_TOKEN_URL = "https://oauth2.googleapis.com/token"
_REPORTS_BASE = "https://admin.googleapis.com/admin/reports/v1/activity"
_SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"

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

    def __init__(self, admin_email: str, service_account_json: str):
        self._admin_email = admin_email
        self._sa_info = self._parse_sa(service_account_json)
        self._access_token: str | None = None
        self._token_expiry: float = 0.0

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

    def _build_jwt(self) -> str:
        """Build a JWT with the ``sub`` claim set to the impersonated admin —
        this is what makes domain-wide delegation actually work."""
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": self._sa_info["client_email"],
            "scope": _SCOPE,
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

    async def _authenticate(self) -> str:
        if self._access_token and time.time() < self._token_expiry - 60:
            return self._access_token
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                self._sa_info.get("token_uri", _TOKEN_URL),
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": self._build_jwt(),
                },
            )
            resp.raise_for_status()
            payload = resp.json()
            self._access_token = payload["access_token"]
            self._token_expiry = time.time() + int(payload.get("expires_in", 3600))
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
                    self._access_token = None
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
            "event_type": (f"workspace.{application}.{event_name}".lower() if application and event_name else "workspace.audit"),
            "raw_event": raw,
            "created_at": (raw.get("id") or {}).get("time"),
        }
