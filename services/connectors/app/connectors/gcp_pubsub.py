"""
GCP Pub/Sub subscription fed by a Cloud Logging sink.

Why this exists beside ``gcp_cloud_audit.py``
---------------------------------------------

``logging.entries.list`` reads an index. It is the right call for a single
project and the wrong one for an organisation: the filter is evaluated
across every log bucket named in ``resourceNames``, the quota is per-minute
rather than per-entry, and an organisation-level read of Data Access logs at
five-minute cadence spends most of its time paging through entries it
already had.

The shape Google designed for continuous export is a **log sink**: a filter
at the organisation, folder or project level that publishes every matching
``LogEntry`` to a Pub/Sub topic as it is written. A subscription on that
topic is a durable, ordered-enough, acknowledged stream, and it carries
whatever the sink's filter selects — audit logs, Data Access logs, VPC flow
logs, firewall logs, GKE audit — rather than only what one connector was
written to ask for.

``gcp_cloud_audit.py`` stays for the single-project case, where standing up
a sink and a topic is more setup than the problem deserves.

Resumption and backpressure
---------------------------

The subscription is the cursor. A message is redelivered until it is
acknowledged, so a restart mid-poll costs a duplicate rather than a gap, and
the declared ``(event_time, record_id)`` checkpoint suppresses that
duplicate downstream. Acknowledgement happens **after** the batch has been
turned into events, never before.

``collection_budget`` bounds the poll, because a subscription holds up to
seven days of retention and a sink on an organisation's Data Access logs
fills that quickly. Unacknowledged messages stay on the subscription and the
next poll pulls them.

A note on ordering: Pub/Sub does not guarantee order unless the topic is
created with message ordering enabled *and* the publisher sets an ordering
key, which Cloud Logging sinks do not. The checkpoint therefore sorts by
``(event_time, record_id)`` within each poll and tolerates a late arrival by
re-reading its own overlap — which is why the cursor is a de-duplicator here
rather than a watermark that may skip.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import structlog

from app.connectors.base import (
    BaseConnector,
    Capability,
    CollectionBudget,
    ConnectorSchema,
    Field,
    OAuthHints,
)
from app.connectors.gcp_service_account import (
    DEFAULT_TOKEN_URL,
    ServiceAccountToken,
    parse_service_account,
)

logger = structlog.get_logger()

_PUBSUB_ROOT = "https://pubsub.googleapis.com/v1"
_SCOPE = "https://www.googleapis.com/auth/pubsub"

#: Pub/Sub caps a synchronous pull at 1000 messages. 250 keeps one round
#: trip inside a few seconds on a sink carrying large audit entries.
_PULL_SIZE = 250

#: Cloud Logging's severity ladder, mapped onto AiSOC's five tiers. GCP
#: publishes three tiers above ERROR and all three mean "a human is being
#: paged", so they map to `critical` rather than being collapsed into
#: `high` — the repository's severity rule, which exists because a vendor's
#: own top tier disappearing is the kind of loss nobody notices.
_SEVERITY: dict[str, str] = {
    "DEFAULT": "info",
    "DEBUG": "info",
    "INFO": "info",
    "NOTICE": "low",
    "WARNING": "medium",
    "ERROR": "high",
    "CRITICAL": "critical",
    "ALERT": "critical",
    "EMERGENCY": "critical",
}


def _as_dict(value: Any) -> dict[str, Any]:
    """``value`` when it is a mapping, an empty dict otherwise.

    Written once because the alternative — ``x.get("k") if isinstance(x.get("k"), dict) else {}``
    at every site — widens to ``Any | dict | None`` for the type checker and
    reads as noise for a human.
    """
    return value if isinstance(value, dict) else {}


def _entry_severity(entry: dict[str, Any]) -> str:
    """Five-tier severity for one ``LogEntry``.

    A denied control-plane call is bumped a tier. GCP writes those at
    ``ERROR`` only sometimes — an IAM denial in an audit log can arrive at
    ``INFO`` with a non-zero ``protoPayload.status.code``, and reading only
    the severity field would file an attacker enumerating permissions at the
    same tier as a successful read.
    """
    base = _SEVERITY.get(str(entry.get("severity") or "DEFAULT").upper(), "info")
    status = _as_dict(_as_dict(entry.get("protoPayload")).get("status"))
    denied = bool(status.get("code"))
    if not denied:
        return base
    return {"info": "low", "low": "medium", "medium": "high", "high": "high", "critical": "critical"}[base]


def _decode(message: dict[str, Any]) -> dict[str, Any]:
    """The ``LogEntry`` carried by one Pub/Sub message.

    A sink publishes the entry as base64 JSON in ``data``. Anything else on
    the topic — a hand-published test message, another producer sharing the
    topic — is returned as ``{"textPayload": ...}`` rather than dropped, so
    a misconfigured sink shows up as readable noise instead of a silent
    zero-row poll.
    """
    raw = message.get("data")
    if not isinstance(raw, str) or not raw:
        return {}
    try:
        body = base64.b64decode(raw)
    except (ValueError, TypeError):
        return {}
    text = body.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return {"textPayload": text}
    return parsed if isinstance(parsed, dict) else {"textPayload": text}


class GCPPubSubConnector(BaseConnector):
    connector_id = "gcp_pubsub"
    connector_name = "GCP Pub/Sub (log sink)"
    connector_category = "cloud"

    checkpoint_time_field = ("event_time",)
    checkpoint_id_field = ("record_id",)

    collection_budget = CollectionBudget(
        max_batches_per_poll=20,
        max_events_per_poll=20_000,
        backlog_stays_on_the_queue=(
            "Only messages whose entries were emitted are acknowledged. Anything the budget stops short of "
            "stays unacknowledged on the subscription and is redelivered on the next poll, so a backlog "
            "drains over several polls rather than in one pass."
        ),
    )

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Google Cloud logs streamed through a Cloud Logging sink onto a Pub/Sub "
                "subscription. Carries whatever the sink's filter selects — audit, Data "
                "Access, VPC flow, firewall, GKE — for a whole organisation, with the "
                "subscription as the cursor."
            ),
            docs_url="/docs/connectors/gcp-pubsub",
            fields=[
                Field(
                    "project_id",
                    "string",
                    "Project ID (of the subscription)",
                    placeholder="my-logging-project",
                    help_text="The project the Pub/Sub subscription lives in, which may differ from the projects the sink reads.",
                ),
                Field(
                    "subscription_id",
                    "string",
                    "Subscription ID",
                    placeholder="aisoc-log-sink-sub",
                    help_text=(
                        "A pull subscription on the topic your log sink publishes to. Push subscriptions are not read by this connector."
                    ),
                ),
                Field(
                    "service_account_json",
                    "secret",
                    "Service account JSON key",
                    help_text=(
                        "Needs roles/pubsub.subscriber on the subscription. Paste the entire key file; "
                        "it is encrypted at rest by the credential vault."
                    ),
                ),
                Field(
                    "ack_deadline_seconds",
                    "number",
                    "Acknowledgement deadline (seconds)",
                    required=False,
                    default=120,
                    help_text=(
                        "Recorded for the setup guide and compared against the subscription at test time. "
                        "A deadline shorter than one poll redelivers messages this connector is still reading."
                    ),
                ),
            ],
            oauth=OAuthHints(supported_in_hosted=False, token_url=DEFAULT_TOKEN_URL, scopes=[_SCOPE]),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_AUDIT, Capability.PULL_LOGS)

    def __init__(
        self,
        project_id: str,
        subscription_id: str,
        service_account_json: str,
        ack_deadline_seconds: int = 120,
    ):
        self._project_id = project_id
        self._subscription_id = subscription_id
        self._ack_deadline = max(10, int(ack_deadline_seconds or 120))
        self._auth = ServiceAccountToken(parse_service_account(service_account_json), _SCOPE)

    @property
    def _subscription_path(self) -> str:
        return f"projects/{self._project_id}/subscriptions/{self._subscription_id}"

    async def test_connection(self) -> dict[str, Any]:
        """Read the subscription's own description.

        Deliberately not a pull: a pull would consume messages that a
        half-finished setup then loses, and the only thing the operator
        needs to know at this point is that the credential reaches the
        subscription. The ack deadline comes back in the same call, so the
        one misconfiguration that silently duplicates every message is
        reported here rather than discovered from the duplicates.
        """
        try:
            token = await self._auth.token()
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{_PUBSUB_ROOT}/{self._subscription_path}",
                    headers=self._auth.headers(token),
                )
                resp.raise_for_status()
                described = resp.json()
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

        vendor_deadline = int(described.get("ackDeadlineSeconds") or 0)
        result: dict[str, Any] = {
            "success": True,
            "connector": self.connector_id,
            "subscription": self._subscription_path,
            "topic": described.get("topic"),
            "ack_deadline_seconds": vendor_deadline,
            "service_account": self._auth.client_email,
        }
        if described.get("pushConfig", {}).get("pushEndpoint"):
            result["warning"] = "this is a push subscription; AiSOC pulls, so configure a pull subscription instead"
        elif vendor_deadline and vendor_deadline < 60:
            result["warning"] = (
                f"ack deadline is {vendor_deadline}s — raise it above one poll, or messages redeliver while AiSOC is still reading them"
            )
        return result

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        """Pull up to one budget's worth of the subscription.

        ``since_seconds`` is ignored: the subscription holds exactly what has
        not been acknowledged, and a time window applied on top of it would
        either skip or replay.
        """
        budget = self.collection_budget
        assert budget is not None  # declared on the class; narrows the Optional for mypy
        rows: list[dict[str, Any]] = []
        truncated = False

        try:
            token = await self._auth.token()
        except Exception as exc:
            logger.warning("gcp_pubsub.auth_failed", error=str(exc))
            return []

        async with httpx.AsyncClient(timeout=30.0) as client:
            for _ in range(budget.max_batches_per_poll):
                if len(rows) >= budget.max_events_per_poll:
                    truncated = True
                    break
                try:
                    resp = await client.post(
                        f"{_PUBSUB_ROOT}/{self._subscription_path}:pull",
                        headers=self._auth.headers(token),
                        json={"maxMessages": _PULL_SIZE},
                    )
                    if resp.status_code == 401:
                        # A revoked or rotated key. Dropping the cache means
                        # the next poll re-mints rather than presenting the
                        # dead token until someone restarts the service.
                        self._auth.invalidate()
                        logger.warning("gcp_pubsub.unauthorized", subscription=self._subscription_path)
                        break
                    resp.raise_for_status()
                    payload = resp.json()
                except Exception as exc:
                    logger.warning("gcp_pubsub.pull_failed", subscription=self._subscription_path, error=str(exc))
                    break

                received = payload.get("receivedMessages") or []
                if not received:
                    break

                ack_ids: list[str] = []
                for item in received:
                    if not isinstance(item, dict):
                        continue
                    message = item.get("message") or {}
                    entry = _decode(message)
                    ack_id = item.get("ackId")
                    if ack_id:
                        ack_ids.append(str(ack_id))
                    if not entry:
                        # An empty-payload message is still consumed —
                        # leaving it unacknowledged would redeliver it
                        # forever and the subscription would never drain.
                        continue
                    rows.append(
                        {
                            "record_id": str(message.get("messageId") or ack_id or ""),
                            "event_time": str(entry.get("timestamp") or message.get("publishTime") or ""),
                            "attributes": message.get("attributes") or {},
                            "entry": entry,
                        }
                    )

                # Acknowledge after the batch is in `rows`, never before: a
                # failure between the two has to cost a duplicate, not a gap.
                if ack_ids:
                    await self._acknowledge(client, token, ack_ids)

                if len(received) < _PULL_SIZE:
                    break

        if truncated:
            logger.info(
                "gcp_pubsub.budget_reached",
                rows=len(rows),
                max_events_per_poll=budget.max_events_per_poll,
                detail="remainder stays unacknowledged on the subscription for the next poll",
            )

        return [self.normalize(row) for row in self.apply_checkpoint(rows)]

    async def _acknowledge(self, client: httpx.AsyncClient, token: str, ack_ids: list[str]) -> None:
        try:
            resp = await client.post(
                f"{_PUBSUB_ROOT}/{self._subscription_path}:acknowledge",
                headers=self._auth.headers(token),
                json={"ackIds": ack_ids},
            )
            resp.raise_for_status()
        except Exception as exc:
            # Not fatal, and not silent. The messages redeliver, the
            # checkpoint drops the duplicates, and a persistent failure here
            # shows as a subscription that never drains — which an operator
            # can only diagnose if it was logged.
            logger.warning("gcp_pubsub.ack_failed", count=len(ack_ids), error=str(exc))

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        entry = _as_dict(raw.get("entry"))
        proto = _as_dict(entry.get("protoPayload"))
        auth_info = _as_dict(proto.get("authenticationInfo"))
        request_meta = _as_dict(proto.get("requestMetadata"))
        resource = _as_dict(entry.get("resource"))
        labels = _as_dict(resource.get("labels"))
        method = proto.get("methodName") or ""
        status = _as_dict(proto.get("status"))

        title = method or entry.get("logName", "").rsplit("/", 1)[-1] or "Cloud Logging entry"

        return {
            "source": self.connector_id,
            "category": "cloud",
            "external_id": entry.get("insertId") or raw.get("record_id"),
            "title": title,
            "description": (
                f"{method} on {proto.get('resourceName') or labels.get('project_id') or 'gcp'}"
                if method
                else f"Log entry from {entry.get('logName', 'cloud logging')}"
            ),
            "severity": _entry_severity(entry),
            "cloud_platform": "gcp",
            "gcp_project_id": labels.get("project_id") or self._project_id,
            "gcp_resource_type": resource.get("type"),
            "log_name": entry.get("logName"),
            "method_name": method or None,
            "service_name": proto.get("serviceName"),
            "user_name": auth_info.get("principalEmail"),
            "src_ip": request_meta.get("callerIp"),
            "user_agent": request_meta.get("callerSuppliedUserAgent"),
            "error_code": str(status.get("code")) if status.get("code") else None,
            "raw_event": entry,
            "created_at": raw.get("event_time"),
        }
