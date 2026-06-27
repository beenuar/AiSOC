"""
Abnormal Security email-security connector.

Abnormal exposes ``GET /v1/threats`` and ``GET /v1/cases`` endpoints
returning behavioural-AI-detected threats (BEC, credential phishing,
account takeover, internal compromise) plus their case-ified
aggregations. Auth is a tenant-issued bearer token.

Severity collapse:
  * threatType ``businessEmailCompromise`` / ``credentialPhishing`` /
    ``accountTakeover`` → high
  * ``phishing`` / ``malware`` / ``invoiceFraud`` → high
  * ``spam`` / ``graymail`` / ``promotional`` → low
  * everything else → medium (Abnormal only reports things it considers
    abnormal — there's no "info" floor)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_DEFAULT_BASE = "https://api.abnormalplatform.com"
_PER_PAGE = 100
_MAX_PAGES = 25


class AbnormalSecurityConnector(BaseConnector):
    """Abnormal Security threat events."""

    connector_id = "abnormal_security"
    connector_name = "Abnormal Security"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Abnormal Security behavioural-AI email threat events. "
                "Polls /v1/threats and /v1/cases for BEC, credential "
                "phishing, account takeover, and invoice-fraud "
                "detections."
            ),
            docs_url="/docs/connectors/abnormal_security",
            fields=[
                Field(
                    "base_url",
                    "string",
                    "API base URL",
                    default=_DEFAULT_BASE,
                    required=False,
                ),
                Field(
                    "api_token",
                    "secret",
                    "API token",
                    help_text="Abnormal Console → Settings → Integrations → API → Generate token.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.PIVOT_USER,
            Capability.READ_AUDIT_TRAIL,
        )

    def __init__(self, api_token: str, base_url: str | None = None):
        self._api_token = api_token
        self._base = (base_url or _DEFAULT_BASE).rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_token}",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base}/v1/threats",
                    headers=self._headers(),
                    params={"pageSize": 1},
                )
                if resp.status_code == 200:
                    return {"success": True, "connector": self.connector_id}
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"HTTP {resp.status_code}: {resp.text[:200]}",
                }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        out: list[dict[str, Any]] = []
        for endpoint, kind in (("/v1/threats", "threat"), ("/v1/cases", "case")):
            page_number = 1
            async with httpx.AsyncClient(timeout=30.0) as client:
                for _ in range(_MAX_PAGES):
                    params: dict[str, Any] = {
                        "pageSize": _PER_PAGE,
                        "pageNumber": page_number,
                        "filter": f"receivedTime gte {since}",
                    }
                    try:
                        resp = await client.get(f"{self._base}{endpoint}", headers=self._headers(), params=params)
                    except (httpx.HTTPError, httpx.InvalidURL) as exc:
                        # Network failure (DNS, TLS, timeout) must not abort
                        # the polling loop — log and stop paginating *this*
                        # stream; the next poll cycle gets a fresh attempt.
                        logger.warning(
                            "abnormal_security.fetch_network_error",
                            kind=kind,
                            error=str(exc),
                        )
                        break
                    if resp.status_code != 200:
                        logger.warning(
                            "abnormal_security.fetch_failed",
                            kind=kind,
                            status=resp.status_code,
                            body=resp.text[:300],
                        )
                        break
                    payload = resp.json() or {}
                    items_key = "threats" if kind == "threat" else "cases"
                    items = payload.get(items_key) or payload.get("data") or []
                    for it in items:
                        out.append(self.normalize({"_kind": kind, **it}))
                    next_page = payload.get("nextPageNumber") or payload.get("next")
                    if not next_page or len(items) < _PER_PAGE:
                        break
                    page_number = int(next_page) if isinstance(next_page, int | str) else page_number + 1
        return out

    _HIGH_THREAT_TYPES = (
        "businessemailcompromise",
        "credentialphishing",
        "accounttakeover",
        "phishing",
        "malware",
        "invoicefraud",
        "vendoremailcompromise",
        "extortion",
    )
    _LOW_THREAT_TYPES = ("spam", "graymail", "promotional", "marketing")

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        kind = raw.get("_kind", "threat")
        ttype = (raw.get("threatType") or raw.get("attackType") or "").lower().replace(" ", "")
        severity = "medium"
        if ttype in self._HIGH_THREAT_TYPES:
            severity = "high"
        elif ttype in self._LOW_THREAT_TYPES:
            severity = "low"
        # Cases roll up multiple messages; severity is max of constituents.
        if kind == "case":
            case_severity = (raw.get("severity") or "").lower()
            if case_severity in ("high", "critical"):
                severity = "high"
            elif case_severity == "medium":
                severity = "medium" if severity == "low" else severity
        sender = raw.get("fromAddress") or (raw.get("sender") or {}).get("email")
        recipients = raw.get("toAddresses") or raw.get("recipients") or []
        return {
            "source": self.connector_id,
            "stream": kind,
            "external_id": raw.get("threatId") or raw.get("caseId") or raw.get("id") or "",
            "title": raw.get("subject") or raw.get("title") or f"Abnormal {kind}",
            "description": (
                f"type={ttype}; from={sender}; "
                f"recipients={','.join(r if isinstance(r, str) else (r.get('email') or '') for r in recipients[:5])}"
            ),
            "severity": severity,
            "actor": sender,
            "actor_email": sender,
            "event_type": f"abnormal_security.{kind}.{ttype or 'unknown'}",
            "raw_event": raw,
            "created_at": raw.get("receivedTime") or raw.get("createdTime"),
        }
