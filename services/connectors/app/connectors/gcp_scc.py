"""
GCP Security Command Center (SCC) connector.

Pulls SCC findings — the curated security signals Google synthesizes from
Cloud Audit Logs, VPC Flow Logs, Container Threat Detection, Web Security
Scanner, and partner integrations. SCC is essentially Google's equivalent
of AWS Security Hub or Microsoft Defender for Cloud, and is the highest-
signal feed available for GCP estates.

Auth model: a Google service-account JSON key with
``roles/securitycenter.findingsViewer`` (org or folder-scoped). The full
key blob is pasted into the secret field and encrypted at rest.

We share JWT signing with ``gcp_cloud_audit`` via duplicate logic rather
than a shared module — connectors are intentionally standalone so they
can be lifted into the marketplace independently. If we ever extract a
``gcp_auth`` helper, both should switch in lock-step.
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
_SCC_BASE = "https://securitycenter.googleapis.com/v1"
_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

_PAGE_SIZE = 200


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class GCPSCCConnector(BaseConnector):
    """Google Cloud Security Command Center findings."""

    connector_id = "gcp_scc"
    connector_name = "GCP Security Command Center"
    connector_category = "cloud"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Google Cloud Security Command Center findings. Requires a "
                "service account with roles/securitycenter.findingsViewer at "
                "the organization or folder level."
            ),
            docs_url="/docs/connectors/gcp-scc",
            fields=[
                Field(
                    "organization_id",
                    "string",
                    "Organization ID",
                    placeholder="1234567890",
                    help_text=(
                        "Numeric GCP organization ID. SCC is org-scoped; the "
                        "service account must have findingsViewer at this "
                        "level (or on a parent folder/source)."
                    ),
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
        # Security Command Center surfaces cross-product GCP findings.
        return (Capability.PULL_ALERTS,)

    def __init__(self, organization_id: str, service_account_json: str):
        self._organization_id = organization_id
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
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": self._sa_info["client_email"],
            "scope": _SCOPE,
            "aud": self._sa_info.get("token_uri", _TOKEN_URL),
            "iat": now,
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
            # Listing sources is the cheapest verification: it confirms the
            # token, that the org ID is correct, and that SCC is enabled.
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{_SCC_BASE}/organizations/{self._organization_id}/sources",
                    headers=self._headers(),
                    params={"pageSize": 1},
                )
                resp.raise_for_status()
            return {
                "success": True,
                "connector": self.connector_id,
                "organization_id": self._organization_id,
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

        # ``-`` as the source ID means "across all sources" — the standard
        # way to enumerate findings in an org without iterating sources.
        # We filter on ``eventTime`` so we get net-new findings since the
        # last poll, and exclude already-resolved findings.
        scc_filter = f'state="ACTIVE" AND eventTime >= "{since}"'

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{_SCC_BASE}/organizations/{self._organization_id}/sources/-/findings",
                headers=self._headers(),
                params={"filter": scc_filter, "pageSize": _PAGE_SIZE},
            )
            if resp.status_code == 401:
                self._access_token = None
                await self._authenticate()
                resp = await client.get(
                    f"{_SCC_BASE}/organizations/{self._organization_id}/sources/-/findings",
                    headers=self._headers(),
                    params={"filter": scc_filter, "pageSize": _PAGE_SIZE},
                )
            if resp.status_code != 200:
                logger.warning(
                    "gcp_scc.fetch_failed",
                    status=resp.status_code,
                    body=resp.text[:300],
                )
                return []

            entries = resp.json().get("listFindingsResults", [])

        return [self.normalize(item) for item in entries]

    # ----------------------- normalize --------------------------

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # SCC wraps findings in {"finding": {...}, "resource": {...}, ...}
        finding = raw.get("finding", {}) or raw  # tolerate either shape
        resource = raw.get("resource", {}) or {}

        # SCC severity comes through as one of CRITICAL / HIGH / MEDIUM /
        # LOW / SEVERITY_UNSPECIFIED. Map directly to AiSOC's 5-tier ladder
        # (info | low | medium | high | critical) so P1 SCC findings keep
        # their original priority rather than getting collapsed into ``high``.
        scc_sev = (finding.get("severity") or "").upper()
        severity = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }.get(scc_sev, "info")

        return {
            "source": self.connector_id,
            "external_id": finding.get("name", ""),
            "title": finding.get("category", "GCP SCC Finding"),
            "description": (finding.get("description") or finding.get("category", "") or "GCP Security Command Center finding"),
            "severity": severity,
            "actor": (finding.get("access", {}) or {}).get("principalEmail"),
            "actor_email": (finding.get("access", {}) or {}).get("principalEmail"),
            "event_type": f"gcp.scc.{(finding.get('category') or 'finding').lower()}",
            "raw_event": raw,
            "created_at": finding.get("eventTime") or finding.get("createTime"),
            # Resource context is high-signal for triage; surface it explicitly.
            "resource_name": resource.get("name") or finding.get("resourceName"),
            "resource_type": resource.get("type"),
        }
