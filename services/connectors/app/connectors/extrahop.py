"""ExtraHop RevealX 360 network detections.

Depth plan wave 2, item 8.2.

Vendor reference, verified 2026-11-01 against ExtraHop's current public REST
API guide (`https://docs.extrahop.com/current/rest-api-guide/`) and the
detections overview (`https://docs.extrahop.com/current/detections-overview`):

* **Authentication.** RevealX 360 is OAuth2 client credentials, and an API
  key is explicitly *not* compatible with it: the guide says so twice, for
  both of its example scripts. The documented exchange is

      POST {host}/oauth2/token
      Authorization: Basic base64(id:secret)
      Content-Type: application/x-www-form-urlencoded
      grant_type=client_credentials

  The host is the API Endpoint shown on the RevealX 360 API Access page and
  does not include the `/oauth2/token` suffix.

* **Detections.** `POST /api/v1/detections/search`. `GET /detections` is
  marked Deprecated and replaced by the search operation, so this reads the
  search. The documented body fields used here are `from`, `until`, `limit`,
  `offset`, `filter.risk_score_min` and `sort`; `from` and `until` are
  milliseconds since the epoch, and a negative value is relative to the time
  of the request.

* **Detection object.** `id`, `title`, `description`, `risk_score`,
  `categories`, `type`, `status`, `start_time`, `end_time`, `update_time`,
  `mod_time`, `url`, `participants`, `mitre_tactics`, `mitre_techniques`,
  `assignee`, `resolution`, `ticket_id`.

The severity ladder, and why it stops at `high`
------------------------------------------------
ExtraHop publishes three risk bands and no fourth. From the detections
overview, verbatim: "The icon is color coded by severity as red (80-99),
orange (31-79), or yellow (1-30)." The same page draws the contrast
explicitly, because CrowdStrike detections surfaced in the same view use
red for *Critical* while ExtraHop's red is just 80-99.

So this connector maps 80-99 to `high` and never emits `critical`.
Promoting the top band would assert a severity the vendor does not publish,
which is the same defect as collapsing a vendor's real `critical` into
`high`, in the other direction. Nothing is lost by it: the ingest profile
files these at `class_uid: 2001`, category 2, which the fusion promoter
promotes unconditionally regardless of severity.

A detection with no `risk_score` at all is a performance detection rather
than a security one. It carries no `severity` key, so the ingest profile
leaves `severity_id` at 0 and the category-2 class still promotes it.
Emitting `info` instead would be our judgement standing in for the vendor's
absent one.

Read-only
---------
This connector reads. Nothing here changes vendor state, including the
detection `status` and `assignee` fields the API would allow a PATCH on.
Phase 8 is read-only by the plan's rule, and the write verbs ExtraHop
offers are deliberately not implemented.
"""

from __future__ import annotations

import base64
import time
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

#: The vendor's published risk bands, as (inclusive floor, tier), highest
#: first. Three entries because the vendor publishes three. The absence of a
#: fourth is asserted by a test rather than left to be noticed.
_RISK_BANDS: tuple[tuple[int, str], ...] = ((80, "high"), (31, "medium"), (1, "low"))

#: Hard ceiling on one poll. The documented maximum for a non-`id_only`
#: search is 20,000; this is far below it because a poll that returns twenty
#: thousand detections is a misconfiguration and draining it in one request
#: would hold the scheduler's slot for minutes.
_MAX_PER_POLL = 500


class ExtraHopConnector(BaseConnector):
    connector_id = "extrahop"
    connector_name = "ExtraHop RevealX 360"
    connector_category = "ndr"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Network detections from ExtraHop RevealX 360, with the vendor's own risk bands "
                "preserved. Read-only: nothing here changes a detection's status or assignee."
            ),
            docs_url="/docs/connectors/extrahop",
            fields=[
                Field(
                    "api_host",
                    "string",
                    "API endpoint",
                    placeholder="https://example.api.cloud.extrahop.com",
                    help_text=("The API Endpoint shown on the RevealX 360 API Access page. Do not include the /oauth2/token suffix."),
                ),
                Field("client_id", "string", "REST API credential ID"),
                Field(
                    "client_secret",
                    "secret",
                    "REST API credential secret",
                    help_text=(
                        "Generated on the RevealX 360 API Access page. An API key works against a "
                        "sensor or console but is not compatible with the RevealX 360 REST API."
                    ),
                ),
                Field(
                    "risk_score_min",
                    "number",
                    "Minimum risk score",
                    required=False,
                    default=1,
                    help_text=(
                        "Only detections at or above this risk score are pulled. 1 is every scored "
                        "detection; the vendor's bands are 1-30, 31-79 and 80-99."
                    ),
                ),
            ],
            capabilities=cls.capabilities(),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS,)

    def __init__(
        self,
        api_host: str,
        client_id: str,
        client_secret: str,
        risk_score_min: int = 1,
        transport: Any | None = None,
    ) -> None:
        self._host = (api_host or "").strip().rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._risk_score_min = max(0, int(risk_score_min))
        self._transport = transport
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    async def _access_token(self) -> str:
        # A minute of headroom: a token that expires between the check and
        # the call answers 401, which an operator reads as a bad credential.
        if self._token and time.time() < self._token_expires_at - 60:
            return self._token

        basic = base64.b64encode(f"{self._client_id}:{self._client_secret}".encode()).decode()
        async with httpx.AsyncClient(timeout=30.0, transport=self._transport) as client:
            response = await client.post(
                f"{self._host}/oauth2/token",
                headers={
                    "Authorization": f"Basic {basic}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                content="grant_type=client_credentials",
            )
            response.raise_for_status()
            body = response.json()
        self._token = str(body["access_token"])
        self._token_expires_at = time.time() + float(body.get("expires_in") or 3600)
        return self._token

    async def test_connection(self) -> dict[str, Any]:
        try:
            token = await self._access_token()
            async with httpx.AsyncClient(timeout=30.0, transport=self._transport) as client:
                response = await client.post(
                    f"{self._host}/api/v1/detections/search",
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                    json={"from": -300_000, "until": 0, "limit": 1},
                )
                if response.status_code == 403:
                    return {
                        "ok": False,
                        "error": (
                            "RevealX 360 answered 403. The credential is valid but lacks the NDR module "
                            "privilege needed to view security detections."
                        ),
                    }
                response.raise_for_status()
            return {"ok": True, "detail": "detections search readable"}
        except httpx.HTTPError as exc:
            return {"ok": False, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        token = await self._access_token()
        # Negative milliseconds relative to the request, which is the shape
        # the vendor documents for a relative window. Computing an absolute
        # epoch here would drift against the appliance's own clock, and a
        # poller whose window is a few seconds off the source silently loses
        # the detections that land in the gap.
        body = {
            "from": -int(max(1, since_seconds) * 1000),
            "until": 0,
            "limit": _MAX_PER_POLL,
            "filter": {"risk_score_min": self._risk_score_min},
            "sort": [{"field": "mod_time", "direction": "asc"}],
        }
        async with httpx.AsyncClient(timeout=60.0, transport=self._transport) as client:
            response = await client.post(
                f"{self._host}/api/v1/detections/search",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json=body,
            )
            # Raised, not swallowed into an empty list. An empty list means
            # "the network was quiet" and an exception means "we could not
            # look"; the scheduler records the second as a failure and the
            # first as a healthy poll.
            response.raise_for_status()
            detections = response.json()

        if not isinstance(detections, list):
            logger.warning("extrahop.unexpected_response_shape", shape=type(detections).__name__)
            return []
        return [self.normalize(d) for d in detections if isinstance(d, dict)]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Canonical envelope, with the vendor record under `raw_event`.

        The ingest profile's field map reads these lowercase canonical keys,
        not raw vendor field names, so a key missing here is a column the
        profile cannot map and nothing fails loudly when it is absent.
        """
        offender, victim = self._participants(raw)

        event: dict[str, Any] = {
            "source": self.connector_id,
            "external_id": str(raw.get("id") or ""),
            "title": (raw.get("title") or "").strip() or "ExtraHop detection",
            "description": (raw.get("description") or "").strip(),
            "event_type": (raw.get("type") or "").strip() or None,
            "created_at": _epoch_ms_to_iso(raw.get("start_time")),
            "updated_at": _epoch_ms_to_iso(raw.get("update_time") or raw.get("mod_time")),
            "url": raw.get("url"),
            "status": raw.get("status"),
            "categories": [c for c in (raw.get("categories") or []) if isinstance(c, str)][:10],
            "mitre_techniques": _attack_ids(raw.get("mitre_techniques")),
            "mitre_tactics": _attack_ids(raw.get("mitre_tactics")),
            "raw_event": raw,
        }

        severity = self._severity(raw.get("risk_score"))
        if severity is not None:
            event["severity"] = severity
            event["risk_score"] = raw.get("risk_score")

        # The offender is the source and the victim is the host. Reversing
        # them puts the attacker's address in the column an analyst reads as
        # the asset under attack, and containment would then name the wrong
        # machine.
        if offender:
            event["src_ip"] = offender.get("ip")
            if offender.get("hostname"):
                event["src_hostname"] = offender["hostname"]
        if victim:
            event["dst_ip"] = victim.get("ip")
            if victim.get("hostname"):
                event["hostname"] = victim["hostname"]

        return {k: v for k, v in event.items() if v is not None}

    @staticmethod
    def _severity(risk_score: Any) -> str | None:
        """The vendor's band, or None when the vendor set no score."""
        if isinstance(risk_score, bool) or not isinstance(risk_score, (int, float)):
            return None
        score = int(risk_score)
        for floor, tier in _RISK_BANDS:
            if score >= floor:
                return tier
        # Below the vendor's own floor of 1. Treated as unscored rather than
        # as `info`, for the same reason a missing score is.
        return None

    @staticmethod
    def _participants(raw: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Pull the offender and victim out of the participants array.

        The array is a list of objects carrying `role`, `object_type`,
        `object_value` and `hostname`. The roles the vendor documents are
        `offender` and `victim`; anything else is ignored rather than
        guessed into one of them.
        """
        offender: dict[str, Any] | None = None
        victim: dict[str, Any] | None = None
        participants = raw.get("participants")
        if not isinstance(participants, list):
            return None, None

        for entry in participants:
            if not isinstance(entry, dict):
                continue
            projected = {
                "ip": (str(entry.get("object_value") or "").strip() or None),
                "hostname": (str(entry.get("hostname") or "").strip() or None),
            }
            role = str(entry.get("role") or "").strip().lower()
            if role == "offender" and offender is None:
                offender = projected
            elif role == "victim" and victim is None:
                victim = projected
        return offender, victim


def _attack_ids(value: Any) -> list[str]:
    """The technique or tactic ids, shape-checked.

    A well-formed id is carried and anything else is dropped. The shape
    check is tight enough to tell a technique from a tactic, because an
    extractor that accepted `TA0006` as a technique would publish a tactic
    id into the technique column on every event that carried one.
    """
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        identifier = str(entry.get("id") or "").strip().upper()
        if identifier:
            out.append(identifier)
    return out[:20]


def _epoch_ms_to_iso(value: Any) -> str | None:
    """Milliseconds since the epoch as an ISO-8601 instant, or None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        from datetime import UTC, datetime  # noqa: PLC0415

        return datetime.fromtimestamp(value / 1000, tz=UTC).isoformat()
    except (OSError, ValueError, OverflowError):
        return None
