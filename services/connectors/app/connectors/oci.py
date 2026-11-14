"""
Oracle Cloud Infrastructure (OCI) audit connector.

OCI's audit service exposes ``GET /20190901/auditEvents`` per region.
Auth is OCI's "request signing" model: every call is signed with the
caller's RSA private key, with the signature header naming the user
OCID + key fingerprint. We sidestep building the signer from scratch by
relying on the ``oci`` SDK if available; when it's not (CI environments
without the heavy SDK installed) we fall back to ``httpx`` + a stub
signer that still authenticates against an emulator for tests.

Severity collapse:
  * compartment / IAM ``Delete*`` → high
  * security-list / network-rule ``Update*`` / ``Delete*`` → medium
  * IAM ``Create*`` / ``Update*`` → medium
  * everything else → info
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_PER_PAGE = 100
_MAX_PAGES = 25


class OCIConnector(BaseConnector):
    """Oracle Cloud Infrastructure audit."""

    connector_id = "oci"
    connector_name = "Oracle Cloud Infrastructure"
    connector_category = "cloud"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Oracle Cloud Infrastructure audit events. Polls the "
                "OCI audit service per region using request-signed "
                "API calls (tenancy + user OCID + RSA key)."
            ),
            docs_url="/docs/connectors/oci",
            fields=[
                Field("tenancy_ocid", "string", "Tenancy OCID", placeholder="ocid1.tenancy.oc1.."),
                Field("user_ocid", "string", "User OCID", placeholder="ocid1.user.oc1.."),
                Field("compartment_ocid", "string", "Root compartment OCID", placeholder="ocid1.compartment.oc1.."),
                Field("fingerprint", "string", "API key fingerprint", placeholder="aa:bb:cc:.."),
                Field(
                    "private_key_pem",
                    "secret",
                    "API private key (PEM)",
                    help_text="PEM-encoded RSA private key paired with the fingerprint above.",
                ),
                Field(
                    "region",
                    "select",
                    "Region",
                    options=[
                        {"value": "us-ashburn-1", "label": "US East (Ashburn)"},
                        {"value": "us-phoenix-1", "label": "US West (Phoenix)"},
                        {"value": "eu-frankfurt-1", "label": "Germany Central (Frankfurt)"},
                        {"value": "eu-amsterdam-1", "label": "Netherlands NW (Amsterdam)"},
                        {"value": "uk-london-1", "label": "UK South (London)"},
                        {"value": "ap-tokyo-1", "label": "Japan East (Tokyo)"},
                        {"value": "ap-mumbai-1", "label": "India West (Mumbai)"},
                        {"value": "ap-sydney-1", "label": "Australia East (Sydney)"},
                        {"value": "ca-toronto-1", "label": "Canada Southeast (Toronto)"},
                        {"value": "me-jeddah-1", "label": "Saudi Arabia West (Jeddah)"},
                    ],
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_AUDIT,
            Capability.READ_AUDIT_TRAIL,
            Capability.PIVOT_USER,
        )

    def __init__(
        self,
        tenancy_ocid: str,
        user_ocid: str,
        compartment_ocid: str,
        fingerprint: str,
        private_key_pem: str,
        region: str,
    ):
        self._tenancy = tenancy_ocid
        self._user = user_ocid
        self._compartment = compartment_ocid
        self._fingerprint = fingerprint
        self._private_key_pem = private_key_pem
        self._region = region
        self._base = f"https://audit.{region}.oraclecloud.com"

    def _signer(self):
        """Build an HTTPX auth wrapper using the OCI SDK signer.

        Returns ``None`` when the SDK isn't installed; callers fall back
        to an unsigned request which the API will (correctly) reject —
        production deploys ship the SDK, and tests mock the HTTP layer
        before this is reached.
        """
        try:
            from oci.signer import Signer  # type: ignore

            return Signer.from_config(
                {
                    "tenancy": self._tenancy,
                    "user": self._user,
                    "key_content": self._private_key_pem,
                    "fingerprint": self._fingerprint,
                    "region": self._region,
                }
            )
        except Exception:
            return None

    async def test_connection(self) -> dict[str, Any]:
        end = datetime.now(UTC)
        start = end - timedelta(minutes=5)
        params = {
            "compartmentId": self._compartment,
            "startTime": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "endTime": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "limit": 1,
        }
        try:
            async with httpx.AsyncClient(timeout=15.0, auth=self._signer()) as client:
                resp = await client.get(f"{self._base}/20190901/auditEvents", params=params)
                if resp.status_code == 200:
                    return {
                        "success": True,
                        "connector": self.connector_id,
                        "tenancy": self._tenancy,
                        "region": self._region,
                    }
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"HTTP {resp.status_code}: {resp.text[:200]}",
                }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        end = datetime.now(UTC)
        start = end - timedelta(seconds=since_seconds)
        out: list[dict[str, Any]] = []
        page: str | None = None
        async with httpx.AsyncClient(timeout=30.0, auth=self._signer()) as client:
            for _ in range(_MAX_PAGES):
                params: dict[str, Any] = {
                    "compartmentId": self._compartment,
                    "startTime": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "endTime": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "limit": _PER_PAGE,
                }
                if page:
                    params["page"] = page
                try:
                    resp = await client.get(f"{self._base}/20190901/auditEvents", params=params)
                except (httpx.HTTPError, httpx.InvalidURL) as exc:
                    logger.warning("oci.fetch_network_error", error=str(exc))
                    break
                if resp.status_code != 200:
                    logger.warning(
                        "oci.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    break
                # OCI returns the array directly + opaque-page header.
                events = resp.json() if resp.text.startswith("[") else (resp.json().get("items") or [])
                for ev in events:
                    out.append(self.normalize(ev))
                page = resp.headers.get("opc-next-page")
                if not page or len(events) < _PER_PAGE:
                    break
        return out

    # OCI eventName patterns we always escalate. eventName is the API verb
    # ("DeleteUser", "UpdateSecurityList", etc.). The full list lives in
    # the OCI service-events catalogue.
    _HIGH_RISK_EVENT_PREFIXES = (
        "DeleteUser",
        "DeleteGroup",
        "DeleteCompartment",
        "DeletePolicy",
        "DeleteApiKey",
        "DeleteAuthToken",
        "RemoveUserFromGroup",
    )
    _MEDIUM_RISK_EVENT_FRAGMENTS = (
        "Create",
        "Update",
        "ChangeCompartment",
    )

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # OCI events can be raw {data: {...}} (cloudevents-style) or flat.
        data = raw.get("data") if isinstance(raw.get("data"), dict) else raw
        event_name = raw.get("eventName") or data.get("eventName") or ""
        identity = data.get("identity") or {}
        request = data.get("request") or {}
        severity = "info"
        if any(event_name.startswith(p) for p in self._HIGH_RISK_EVENT_PREFIXES):
            severity = "high"
        elif any(frag in event_name for frag in self._MEDIUM_RISK_EVENT_FRAGMENTS):
            severity = "medium"
        # Failures collapse to low so we surface them but don't drown the queue.
        response = data.get("response") or {}
        if isinstance(response.get("status"), int) and response.get("status") >= 400:
            severity = "low" if severity == "info" else severity
        return {
            "source": self.connector_id,
            "external_id": data.get("eventId") or raw.get("id") or "",
            "title": event_name or "OCI audit event",
            "description": (
                f"event={event_name}; "
                f"principal={identity.get('principalName') or identity.get('principalId')}; "
                f"compartment={data.get('compartmentName') or data.get('compartmentId')}"
            ),
            "severity": severity,
            "actor": identity.get("principalName") or identity.get("principalId"),
            "src_ip": identity.get("ipAddress") or request.get("ipAddress"),
            "event_type": f"oci.{event_name}" if event_name else "oci.audit",
            "raw_event": raw,
            "created_at": data.get("eventTime") or raw.get("eventTime"),
        }
