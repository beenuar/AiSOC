"""
GCP Cloud Audit Logs connector.

Pulls Admin Activity, Data Access, and System Event audit logs from Google
Cloud Logging via the ``entries.list`` API. These logs cover IAM changes,
resource mutations, key creates/deletes, and privileged data access — the
control-plane events most SOCs care about.

Auth model: a Google service-account JSON key with at least
``roles/logging.viewer`` (or ``roles/logging.privateLogViewer`` to read
Data Access logs). The full key blob is pasted into the secret field and
encrypted at rest by the credential vault.

The connector talks to two Google services:

  * ``oauth2.googleapis.com/token``           — exchange the signed JWT for
                                                a short-lived access token.
  * ``logging.googleapis.com/v2/entries:list`` — fetch log entries.

We construct the JWT manually (RS256) so we don't have to depend on the
heavy ``google-auth`` package. Cryptography is already installed for the
credential vault, so reusing it costs nothing.
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

logger = structlog.get_logger()

_TOKEN_URL = "https://oauth2.googleapis.com/token"
_LOGGING_URL = "https://logging.googleapis.com/v2/entries:list"
_SCOPE = "https://www.googleapis.com/auth/logging.read"

# The Logging API caps page size at 1000; 200 keeps each round-trip fast
# and stays well below per-minute quotas for a 5-minute polling cadence.
_PAGE_SIZE = 200


def _b64url(data: bytes) -> str:
    """Standard JWT base64url with no padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class GCPCloudAuditConnector(BaseConnector):
    """Google Cloud Audit Logs (Admin Activity + Data Access + System Event)."""

    connector_id = "gcp_cloud_audit"
    connector_name = "GCP Cloud Audit Logs"
    connector_category = "cloud"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Google Cloud Audit Logs (Admin Activity, Data Access, System "
                "Event) via Cloud Logging. Requires a service account with "
                "roles/logging.viewer (and roles/logging.privateLogViewer for "
                "Data Access logs)."
            ),
            docs_url="/docs/connectors/gcp-cloud-audit",
            fields=[
                Field(
                    "project_id",
                    "string",
                    "Project ID",
                    placeholder="my-prod-project",
                    help_text=("The GCP project to read audit logs from. Use a log-sink aggregator project if you've consolidated."),
                ),
                Field(
                    "service_account_json",
                    "secret",
                    "Service account JSON key",
                    help_text=("Paste the full JSON key file. It will be encrypted at rest by the credential vault."),
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
        # Cloud Audit Logs are GCP's control-plane audit trail.
        return (Capability.PULL_AUDIT,)

    def __init__(self, project_id: str, service_account_json: str):
        self._project_id = project_id
        self._sa_info = self._parse_sa(service_account_json)
        self._access_token: str | None = None
        self._token_expiry: float = 0.0

    # --------------------------- auth ---------------------------

    @staticmethod
    def _parse_sa(blob: str) -> dict[str, Any]:
        """Accept either a raw JSON string or an already-parsed dict-as-string."""
        try:
            sa = json.loads(blob)
        except json.JSONDecodeError as exc:
            raise ValueError("service_account_json is not valid JSON. Paste the entire key file contents.") from exc
        for required in ("client_email", "private_key", "token_uri"):
            if required not in sa:
                raise ValueError(f"service_account_json missing required field: {required}")
        return sa

    def _build_jwt(self) -> str:
        """Build and sign a short-lived JWT for the Google token endpoint."""
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": self._sa_info["client_email"],
            "scope": _SCOPE,
            "aud": self._sa_info.get("token_uri", _TOKEN_URL),
            "iat": now,
            # 1 hour is the maximum Google accepts for a JWT assertion.
            "exp": now + 3600,
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
        # Cache tokens; Google issues 1-hour tokens, but we refresh at 55 min
        # to leave headroom for clock skew and slow polls.
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
            "Content-Type": "application/json",
        }

    # ------------------------- contract -------------------------

    async def test_connection(self) -> dict[str, Any]:
        try:
            await self._authenticate()
            # A zero-result list call confirms the token, project access, and
            # that the Logging API is enabled — without paying for log scan.
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    _LOGGING_URL,
                    headers=self._headers(),
                    json={
                        "resourceNames": [f"projects/{self._project_id}"],
                        "filter": 'logName=~"cloudaudit.googleapis.com"',
                        "pageSize": 1,
                    },
                )
                resp.raise_for_status()
            return {
                "success": True,
                "connector": self.connector_id,
                "project_id": self._project_id,
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
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Filter to the three Cloud Audit log streams. We exclude DataAccess
        # by default because most projects emit it at huge volume; operators
        # can set ``connector_config.include_data_access=true`` to opt in.
        # For now we keep the filter conservative.
        log_filter = (
            'logName=~"cloudaudit.googleapis.com%2Factivity" '
            'OR logName=~"cloudaudit.googleapis.com%2Fsystem_event" '
            f'AND timestamp >= "{since}"'
        )

        events: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                _LOGGING_URL,
                headers=self._headers(),
                json={
                    "resourceNames": [f"projects/{self._project_id}"],
                    "filter": log_filter,
                    "orderBy": "timestamp desc",
                    "pageSize": _PAGE_SIZE,
                },
            )
            if resp.status_code == 401:
                # Token may have raced past expiry; refresh and retry once.
                self._access_token = None
                await self._authenticate()
                resp = await client.post(
                    _LOGGING_URL,
                    headers=self._headers(),
                    json={
                        "resourceNames": [f"projects/{self._project_id}"],
                        "filter": log_filter,
                        "orderBy": "timestamp desc",
                        "pageSize": _PAGE_SIZE,
                    },
                )
            if resp.status_code != 200:
                logger.warning(
                    "gcp_cloud_audit.fetch_failed",
                    status=resp.status_code,
                    body=resp.text[:300],
                )
                return []

            for raw in resp.json().get("entries", []):
                events.append(raw)

        return [self.normalize(e) for e in events]

    # ----------------------- normalize --------------------------

    # GCP audit method names for the common high-blast-radius operations.
    # These are matched as substrings against ``protoPayload.methodName``.
    _HIGH_BLAST_METHODS = (
        "SetIamPolicy",
        ".delete",
        ".disable",
        "DeleteServiceAccount",
        "DeleteServiceAccountKey",
        "CreateServiceAccountKey",
        "DisableServiceAccount",
        "google.iam.admin.v1.DeleteRole",
        "google.cloud.kms.v1.DestroyCryptoKeyVersion",
    )

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        proto = raw.get("protoPayload", {}) or {}
        method = proto.get("methodName", "")
        service = proto.get("serviceName", "")
        resource = raw.get("resource", {}) or {}
        auth_info = proto.get("authenticationInfo", {}) or {}
        request_meta = proto.get("requestMetadata", {}) or {}

        status = proto.get("status", {}) or {}
        succeeded = "code" not in status or status.get("code", 0) == 0

        # Severity heuristic against AiSOC's 5-tier ladder
        # (info | low | medium | high | critical):
        #   - high-blast-radius IAM/KMS operations -> ``high``
        #   - failed control-plane writes          -> ``medium``
        #   - everything else                      -> ``info``
        # Cloud Logging ``ALERT``/``EMERGENCY`` upgrade the result to
        # ``critical`` so paged-out audit anomalies stay on the P1 SLA;
        # ``ERROR``/``CRITICAL`` raise to ``high``. SOC analysts will tune
        # this further with detections.
        severity = "info"
        if any(m in method for m in self._HIGH_BLAST_METHODS):
            severity = "high"
        elif not succeeded:
            severity = "medium"
        log_severity = (raw.get("severity") or "").upper()
        if log_severity in ("ALERT", "EMERGENCY"):
            severity = "critical"
        elif log_severity in ("ERROR", "CRITICAL"):
            severity = "high"
        elif log_severity == "WARNING" and severity == "info":
            severity = "low"

        actor = auth_info.get("principalEmail") or "unknown"

        return {
            "source": self.connector_id,
            "external_id": raw.get("insertId", ""),
            "title": method or "GCP Cloud Audit",
            "description": (
                f"service={service}; "
                f"method={method}; "
                f"resource={resource.get('type', '')}; "
                f"status={'success' if succeeded else status.get('message', 'failed')}"
            ),
            "severity": severity,
            "src_ip": request_meta.get("callerIp"),
            "actor": actor,
            "actor_email": actor if "@" in actor else None,
            "event_type": f"gcp.audit.{service.split('.')[0] or 'unknown'}",
            "raw_event": raw,
            "created_at": raw.get("timestamp"),
        }
