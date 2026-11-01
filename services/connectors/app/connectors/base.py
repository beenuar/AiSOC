"""
Base connector interface for all integrations.

Every connector subclass owns:
  * ``connector_id`` / ``connector_name`` / ``connector_category`` —
    identity used in the catalog and registry lookups.
  * ``schema()`` — a self-describing config schema returned to the
    frontend's "Add connector" wizard. This replaces the centralised
    dict that used to live in ``services/connectors/app/api/router.py``.
  * ``test_connection()`` / ``fetch_alerts()`` / ``normalize()`` — the
    runtime contract used by the polling scheduler.

The schema is intentionally JSON-shaped (not Pydantic) because it is
serialised straight to the wire for the click-and-connect UI. We keep
typed dataclasses here as an authoring aid so a typo (e.g. ``"sercret"``
for ``"secret"``) is caught at import time, not at form-render time.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal

import structlog

if TYPE_CHECKING:
    from app.federated.query import UnifiedQuery

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Capability taxonomy (Workstream 4)
#
# Capabilities describe *what an agent can ask a connector to do*, not how the
# connector is configured. They are intentionally coarse-grained so the agent
# can plan ("I want to isolate a host" → look for any connector exposing
# ``ISOLATE_HOST``) without tripping over vendor-specific verbs.
#
# Buckets — keep in sync with the plan doc (READ / QUERY / PIVOT / ENRICH /
# CONTAIN / REMEDIATE / TICKET / AUDIT). Adding a new capability:
#   1. Add the enum member here.
#   2. Update the relevant connectors' ``capabilities()`` classmethod.
#   3. Keep ``test_every_declared_capability_is_a_valid_verb`` in
#      ``services/connectors/tests/test_conformance.py`` passing.
#
# Per-instance downscoping happens in the API layer: an operator can store an
# ``allowed_capabilities`` whitelist on a ``Connector`` row and the agent
# router will intersect it with the connector class's declared capabilities.
# ---------------------------------------------------------------------------


class Capability(str, Enum):
    """Action verbs an agent can ask a connector to perform.

    String-valued enum so JSON serialisation is human-readable on the wire
    (``"isolate_host"`` not ``"Capability.ISOLATE_HOST"``).

    Naming matches the plan's taxonomy exactly. The ``PULL_*`` prefix on
    READ verbs is deliberate — these are *passive* polling reads, distinct
    from ``QUERY_*`` (active ad-hoc search) and ``ENRICH_*`` (single-entity
    lookup). Keeping the verbs distinct lets the agent reason about cost
    and latency: ``PULL_ALERTS`` is "what landed in the lake already";
    ``QUERY_LOGS`` is "go ask the source right now"; ``ENRICH_USER`` is
    "single round-trip for one entity".
    """

    # READ — passive pulls of events / records the source already produced.
    PULL_ALERTS = "pull_alerts"
    PULL_LOGS = "pull_logs"
    PULL_AUDIT = "pull_audit"
    PULL_PCAP = "pull_pcap"
    PULL_FILE = "pull_file"
    #: Pull *vulnerability findings* (per-asset CVE state) rather than the
    #: alert stream. Connectors declaring it must expose
    #: ``fetch_vulnerability_findings()``, which the scheduler materialises
    #: into ``asset_vulnerabilities`` (docs/cve-patch-policy.md): scanner
    #: findings are inventory rows with patch windows, not console alerts.
    PULL_VULNERABILITIES = "pull_vulnerabilities"

    # QUERY — ad-hoc search across the source's index.
    QUERY_LOGS = "query_logs"
    QUERY_PROCESSES = "query_processes"

    # PIVOT — "given this entity, return everything you know about it".
    PIVOT_USER = "pivot_user"
    PIVOT_HOST = "pivot_host"
    PIVOT_IP = "pivot_ip"
    PIVOT_HASH = "pivot_hash"
    PIVOT_DOMAIN = "pivot_domain"

    # ENRICH — return contextual reputation / metadata for a single entity.
    ENRICH_USER = "enrich_user"
    ENRICH_HOST = "enrich_host"
    ENRICH_IOC = "enrich_ioc"
    ENRICH_DOMAIN = "enrich_domain"
    ENRICH_VULN = "enrich_vuln"
    ENRICH_ASSET = "enrich_asset"

    # CONTAIN / REMEDIATE — kinetic actions.
    ISOLATE_HOST = "isolate_host"
    UNISOLATE_HOST = "unisolate_host"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    BLOCK_HASH = "block_hash"
    BLOCK_DOMAIN = "block_domain"
    # Reverse verbs. Every containment action whose contract declares a
    # platform rollback needs its reverse in the vocabulary, otherwise the
    # rollback path resolves to nothing while believing it has a route back.
    # See services/actions/app/live_actions/capability_contracts.py.
    RESTORE_FILE = "restore_file"
    ALLOW_HASH = "allow_hash"
    ALLOW_DOMAIN = "allow_domain"
    ALLOW_IOC = "allow_ioc"
    ENABLE_USER = "enable_user"
    BLOCK_USER_SIGNIN = "block_user_signin"
    DISABLE_USER = "disable_user"
    REVOKE_SESSION = "revoke_session"
    RESET_PASSWORD = "reset_password"
    REVOKE_TOKEN = "revoke_token"

    # WS-E: additional live vendor action verbs
    # CrowdStrike Falcon RTR
    RUN_SCRIPT = "run_script"
    # AWS / Network
    BLOCK_IP = "block_ip"
    ALLOW_IP = "allow_ip"
    # Microsoft Defender for Endpoint
    BLOCK_IOC = "block_ioc"
    RUN_AV_SCAN = "run_av_scan"
    # Okta identity response
    SUSPEND_SESSION = "suspend_session"
    FORCE_MFA = "force_mfa"
    # SIEM response (Splunk + Elastic)
    # Read-only investigation verbs. Mirrored from the actions service,
    # where a CI check asserts the two vocabularies stay identical — a
    # verb present on one side only resolves to executor_not_found at
    # dispatch, which reads as a missing integration rather than a
    # missing enum member.
    GET_HOST = "get_host"
    GET_DETECTIONS = "get_detections"
    GET_USER_ACTIVITY = "get_user_activity"
    # A distributed osquery query across a fleet, through osctrl, FleetDM or
    # AiSOC's own TLS endpoint. Narrower than it looks: the caller names one
    # of a closed set of allowlisted templates and never writes SQL, which is
    # the same boundary LOOKUP_ENDPOINT_TELEMETRY draws.
    OSQUERY_LIVE_QUERY = "osquery_live_query"
    # Gap-closure Phase 4.2. Two reads that do not fit the three above
    # because their subject is neither a host nor a principal: a cloud
    # control-plane audit trail, and endpoint telemetry searched by
    # indicator. Both take typed arguments and build their own query text
    # server-side, which is the point: an investigation agent can reach
    # these, and the plan forbids a model composing query text against a
    # customer's estate.
    LOOKUP_CLOUD_AUDIT = "lookup_cloud_audit"
    LOOKUP_ENDPOINT_TELEMETRY = "lookup_endpoint_telemetry"
    SEARCH_SIEM = "search_siem"
    CREATE_NOTABLE_EVENT = "create_notable_event"
    SYNC_DETECTION_RULE = "sync_detection_rule"
    UPDATE_WATCHER = "update_watcher"
    # The return leg. Ingest carries a vendor finding id in as `external_id`;
    # this verb carries AiSOC's verdict back out to the same finding, so a
    # notable AiSOC dismissed is not re-triaged by a human in Splunk.
    UPDATE_ALERT_DISPOSITION = "update_alert_disposition"
    # Alert lifecycle. Both have had Splunk, Elastic and Defender arms since
    # Phase 3.3 and appeared in neither vocabulary, so the only way to reach
    # working code was the ungoverned ActionType REST route.
    ACK_ALERT = "ack_alert"
    SUPPRESS_ALERT = "suppress_alert"

    # EVIDENCE — acquire artefacts from a host before they age out.
    # The investigation agent proposes this on the C2 / exfiltration path and
    # nothing implemented it, so the product recommended an acquisition it
    # could not perform at the point where evidence matters most.
    CAPTURE_FORENSICS = "capture_forensics"

    # HUMAN-IN-THE-LOOP — ask the affected person a question and route the
    # answer back onto the case. Distinct from NOTIFY: notify tells a SOC
    # channel something, this asks an end user to confirm or deny, and the
    # action is not finished until they answer.
    CHATOPS_VERIFY = "chatops_verify"

    # MAILBOX — reported-phish remediation across the recipients of one
    # message. The subject is a message in a mailbox, which is neither a
    # host nor a principal, so none of the containment verbs above fit.
    #
    # SEARCH_MAILBOXES is the read every one of the others depends on: a
    # purge takes a per-mailbox message id, and only a search maps one
    # internet message id onto the mailboxes that hold a copy.
    SEARCH_MAILBOXES = "search_mailboxes"
    # Soft delete, never a hard one. On Microsoft Graph that is a move to
    # the `recoverableitemsdeletions` well-known folder; on Gmail it is
    # `users.messages.trash`. Both are documented and both are undone by
    # RESTORE_EMAIL, which is why the verb is PURGE and not DELETE: a
    # verb whose rollback resolves to nothing has no business being
    # dispatched across a thousand mailboxes.
    PURGE_EMAIL = "purge_email"
    RESTORE_EMAIL = "restore_email"
    # Per-mailbox sender block. Graph documents it as an inbox message
    # rule and Gmail as a filter; neither vendor exposes its tenant-wide
    # block list through the API this platform speaks, so this verb is
    # scoped to the mailboxes it is dispatched against and says so.
    BLOCK_SENDER = "block_sender"
    UNBLOCK_SENDER = "unblock_sender"

    # TICKET — bidirectional ITSM (Jira / ServiceNow / etc.).
    PUSH_CASE = "push_case"
    PUSH_STATUS = "push_status"
    # Registered against Jira, ServiceNow, PagerDuty and Slack for as long as
    # those adapters have existed, and absent here — so the registry logged
    # `capability_unknown` for four executors at every startup. Distinct from
    # push_case, which syncs an existing case rather than opening a record.
    CREATE_TICKET = "create_ticket"
    NOTIFY = "notify"

    # AUDIT — read-only configuration / posture queries.
    READ_AUDIT_TRAIL = "read_audit_trail"

    # CLOUD IDENTITY — the credentials a workload runs as, rather than the
    # person who owns them. Depth 5.5's first gap: the containment surface
    # stopped at hosts, user sessions and mail, so a leaked CI key or an
    # assumed-role session already in an attacker's hands had no verb at
    # all and the answer was "open a ticket for the cloud team".
    #
    # Key deactivation and its reverse are separate verbs rather than one
    # with a boolean, because the approval conversation is different in
    # each direction: deactivating is containment, reactivating is a
    # decision that the incident is over.
    DEACTIVATE_ACCESS_KEY = "deactivate_access_key"
    REACTIVATE_ACCESS_KEY = "reactivate_access_key"
    # Not "revoke a session": STS has no such call. The documented
    # mechanism, and what the IAM console's own button does, is a deny on
    # credentials issued before a cut-off. Named for what it achieves
    # rather than for the policy it writes.
    REVOKE_ROLE_SESSIONS = "revoke_role_sessions"
    RESTORE_ROLE_SESSIONS = "restore_role_sessions"
    # A service account, service principal or managed identity — the
    # non-human half of the directory. DISABLE_USER does not cover it:
    # the endpoints differ, and so does the blast radius, because a
    # service identity is usually load-bearing for a pipeline.
    DISABLE_SERVICE_IDENTITY = "disable_service_identity"
    ENABLE_SERVICE_IDENTITY = "enable_service_identity"
    # The reverse of REVOKE_TOKEN where the vendor offers one. GCP can
    # re-enable a disabled service-account key; most vendors cannot
    # un-revoke a token, and their contracts say so rather than naming
    # this verb and resolving to nothing.
    RESTORE_TOKEN = "restore_token"
    # A delegated OAuth consent. Revoking the session and the password
    # leaves this untouched, which is how a contained account keeps
    # serving an attacker's application a refresh token.
    REVOKE_OAUTH_GRANT = "revoke_oauth_grant"
    GET_OAUTH_GRANTS = "get_oauth_grants"
    # Read the credentials and state of one cloud or SaaS identity. The
    # read behind most of the probes above, and useful alone: "is this
    # key still active" is the first question of a key-leak triage.
    GET_CLOUD_IDENTITY = "get_cloud_identity"
    # An instance moved onto a quarantine security group. Distinct from
    # ISOLATE_HOST, which is an EDR agent action: this works on an
    # instance with no agent, which is the usual case for the compromised
    # workload that matters.
    QUARANTINE_INSTANCE = "quarantine_instance"
    RELEASE_INSTANCE = "release_instance"

    # CODE PLATFORM — containment on the repository host.
    REMOVE_ORG_MEMBER = "remove_org_member"
    RESTORE_ORG_MEMBER = "restore_org_member"
    REVOKE_DEPLOY_KEY = "revoke_deploy_key"
    DISABLE_WORKFLOW = "disable_workflow"
    ENABLE_WORKFLOW = "enable_workflow"
    # The read that makes token revocation actionable: once a token is
    # known compromised, the question is what else is exposed on the
    # repositories it could reach.
    GET_SECRET_SCANNING_ALERTS = "get_secret_scanning_alerts"

    # SECURE WEB GATEWAY — a single URL rather than a whole host. Blocking
    # the domain to contain one phishing page takes down everything else
    # on that host with it.
    BLOCK_URL = "block_url"
    ALLOW_URL = "allow_url"

    # AI ESTATE — containment for a model provider, its memberships and the
    # gateway in front of it. Depth 6.6: the inventory could score a
    # provider key's exposure and nothing could act on it, so a key found
    # in a public repository was a finding with a recommendation.
    #
    # Demotion and removal are separate verbs because they are separate
    # decisions: demoting a compromised project owner stops them minting
    # keys and leaves their work intact, which is a far narrower action.
    DEMOTE_ROLE = "demote_role"
    REMOVE_WORKSPACE_MEMBER = "remove_workspace_member"
    # Only a gateway offers this. Neither OpenAI's nor Anthropic's public
    # admin API exposes a budget this platform can set, which is recorded
    # in ai_provider_clients.py rather than left as a verb with no arm.
    SET_SPEND_CAP = "set_spend_cap"
    RESTORE_SPEND_CAP = "restore_spend_cap"


# Ordered groupings used by the UI to render checkbox groups. The agent
# tools endpoint (``GET /api/v1/agents/tools``) returns the same grouping
# so the frontend doesn't have to re-derive it.
CAPABILITY_GROUPS: tuple[tuple[str, tuple[Capability, ...]], ...] = (
    (
        "read",
        (
            Capability.PULL_ALERTS,
            Capability.PULL_LOGS,
            Capability.PULL_AUDIT,
            Capability.PULL_PCAP,
            Capability.PULL_FILE,
        ),
    ),
    ("query", (Capability.QUERY_LOGS, Capability.QUERY_PROCESSES)),
    (
        "pivot",
        (
            Capability.PIVOT_USER,
            Capability.PIVOT_HOST,
            Capability.PIVOT_IP,
            Capability.PIVOT_HASH,
            Capability.PIVOT_DOMAIN,
        ),
    ),
    (
        "enrich",
        (
            Capability.ENRICH_USER,
            Capability.ENRICH_HOST,
            Capability.ENRICH_IOC,
            Capability.ENRICH_DOMAIN,
            Capability.ENRICH_VULN,
            Capability.ENRICH_ASSET,
        ),
    ),
    (
        "contain",
        (
            Capability.ISOLATE_HOST,
            Capability.UNISOLATE_HOST,
            Capability.KILL_PROCESS,
            Capability.QUARANTINE_FILE,
            Capability.RESTORE_FILE,
            Capability.BLOCK_HASH,
            Capability.ALLOW_HASH,
            Capability.BLOCK_DOMAIN,
            Capability.ALLOW_DOMAIN,
            Capability.ALLOW_IOC,
            Capability.ENABLE_USER,
        ),
    ),
    (
        "remediate",
        (
            Capability.BLOCK_USER_SIGNIN,
            Capability.DISABLE_USER,
            Capability.REVOKE_SESSION,
            Capability.RESET_PASSWORD,
            Capability.REVOKE_TOKEN,
        ),
    ),
    ("ticket", (Capability.PUSH_CASE, Capability.PUSH_STATUS)),
    ("audit", (Capability.READ_AUDIT_TRAIL,)),
)

# ---------------------------------------------------------------------------
# Schema dataclasses
#
# We expose ``Field`` and ``ConnectorSchema`` as thin builders. Connector
# authors build a schema with native Python objects; ``ConnectorSchema.to_dict``
# emits the JSON shape the frontend expects.
# ---------------------------------------------------------------------------

# Allowed UI field types. Frontend renders each one with the appropriate
# input control (e.g. ``secret`` is a masked password input, ``textarea``
# accepts pasted JSON keys for GCP service accounts).
FieldType = Literal["string", "secret", "select", "textarea", "boolean", "number"]


@dataclass(frozen=True)
class Field:
    """A single config form field exposed to the wizard UI."""

    name: str
    type: FieldType
    label: str
    required: bool = True
    default: Any | None = None
    placeholder: str | None = None
    help_text: str | None = None
    # Only meaningful for ``type="select"`` — list of {"value", "label"} dicts.
    options: list[dict[str, str]] | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Strip Nones so the wire format stays compact and the frontend
        # doesn't have to special-case missing-vs-None.
        return {k: v for k, v in d.items() if v is not None}


@dataclass(frozen=True)
class OAuthHints:
    """Forward-looking hints for hosted OAuth.

    We render a "Hosted OAuth coming soon" badge in the UI when
    ``supported_in_hosted`` is True. Filling in ``authorize_url`` /
    ``token_url`` / ``scopes`` here keeps the OAuth follow-up PR cheap —
    the frontend already knows what to render.
    """

    supported_in_hosted: bool = False
    authorize_url: str | None = None
    token_url: str | None = None
    scopes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, [])}


@dataclass(frozen=True)
class CollectionBudget:
    """What one poll of a queue- or object-backed source is allowed to take.

    Depth plan 4.1. Every connector before these three pulled from an API
    that answers a time window, so the volume a poll could return was bounded
    by the window. A queue is not: an SQS queue after a six-hour outage, a
    Pub/Sub subscription with seven days of retention or an Event Hubs
    partition at its retention edge each hold as much as the estate produced
    in that time, and a poll written as "drain it" turns the recovery into an
    out-of-memory kill, or a flood through ingest that costs more than the
    outage did.

    So the bound is declared rather than implied, and the declaration carries
    the sentence saying where the remainder goes. That field is not
    decoration: a bound that *drops* the overflow has exactly the same shape
    in code as one that leaves it for the next poll, and only one of them is
    backpressure — the other is silent data loss. Writing down which it is
    makes the reviewer's question answerable from the declaration.
    """

    #: Queue receives / object listings / partition reads per poll.
    max_batches_per_poll: int
    #: Normalized events per poll, across every batch. The two bounds are
    #: independent because one object can hold a hundred thousand records:
    #: bounding batches alone bounds nothing.
    max_events_per_poll: int
    #: Why the overflow is safe — which durable thing still holds it, and
    #: what makes the next poll see it again.
    backlog_stays_on_the_queue: str

    def __post_init__(self) -> None:
        if self.max_batches_per_poll <= 0 or self.max_events_per_poll <= 0:
            raise ValueError("a collection budget with a non-positive bound is not a bound")
        if not self.backlog_stays_on_the_queue.strip():
            raise ValueError("a bounded poll must say where the remainder goes; an unexplained bound reads as data loss")


@dataclass(frozen=True)
class AcknowledgementResult:
    """What answering the source actually achieved.

    Phase 3. A connector used to acknowledge inside its own fetch and log a
    failure at ``warning``, which meant the scheduler could not tell a
    drained queue from one that is silently refusing every delete — and the
    two look identical from a poll that reports success either way.

    ``failed`` is the number that matters: those messages will be redelivered,
    so the next poll re-reads source data that downstream has already
    accepted. That is a duplicate, which is survivable, but it is a fact about
    the deployment an operator should be able to see rather than infer from a
    backlog that never shrinks.
    """

    #: Handles the connector tried to answer.
    requested: int
    #: Handles the source confirmed. These will not be redelivered.
    confirmed: int
    #: Handles the source refused or that expired. These will be redelivered.
    failed: int


@dataclass(frozen=True)
class ConnectorSchema:
    """Self-describing schema for a connector.

    Returned by ``BaseConnector.schema()`` and surfaced verbatim by
    ``GET /connectors/{id}/schema`` in the connectors service.
    """

    connector_id: str
    connector_name: str
    category: str
    description: str
    fields: list[Field]
    docs_url: str | None = None
    oauth: OAuthHints | None = None
    # Workstream 4: declared capability set. ``schema()`` populates this
    # by calling ``cls.capabilities()`` so the wire format includes the
    # exact verbs the agent layer is allowed to invoke.
    capabilities: tuple[Capability, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "connector_id": self.connector_id,
            "connector_name": self.connector_name,
            "category": self.category,
            "description": self.description,
            "fields": [f.to_dict() for f in self.fields],
            # Always emit ``capabilities`` (even when empty) so the
            # frontend can rely on the key existing. Empty list = "this
            # connector is read-only by convention" which is a meaningful
            # signal, not an oversight.
            "capabilities": [c.value for c in self.capabilities],
        }
        if self.docs_url:
            out["docs_url"] = self.docs_url
        if self.oauth is not None:
            out["oauth"] = self.oauth.to_dict()
        return out


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class BaseConnector(ABC):
    """All connectors implement this interface.

    Subclasses must set the three class attributes and implement
    ``schema()``, ``test_connection()``, and ``fetch_alerts()``.
    ``normalize()`` is optional but strongly encouraged — the default
    just returns the raw event, which is fine for sources that already
    speak our common alert shape.
    """

    # Class identity. ``connector_category`` was added with the schema
    # refactor so the registry can group entries (EDR / SIEM / Cloud / IAM).
    connector_id: str = ""
    connector_name: str = ""
    connector_category: str = ""

    # ---------------------------- capabilities -------------------------------

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        """Return the set of capabilities this connector class implements.

        Default is empty — a connector with no declared capabilities is
        read-only by convention (its only useful surface is the polling
        scheduler ingesting its events). Subclasses override this to
        opt into specific agent verbs::

            @classmethod
            def capabilities(cls) -> tuple[Capability, ...]:
                return (
                    Capability.PULL_ALERTS,
                    Capability.PIVOT_HOST,
                    Capability.ISOLATE_HOST,
                )
        """
        return ()

    @classmethod
    def effective_capabilities(cls, allowed: Iterable[str] | None = None) -> tuple[Capability, ...]:
        """Intersect declared capabilities with a per-instance allowlist.

        The API layer calls this with the ``allowed_capabilities`` column
        from the ``connectors`` table. ``None`` means "no downscoping —
        use everything the class declares". An empty list means "this
        instance has been scoped to zero capabilities" (legitimately
        useful: an operator can disable an instance from agent use
        without disabling its polling).
        """
        declared = cls.capabilities()
        if allowed is None:
            return declared
        allowed_set = {str(a) for a in allowed}
        return tuple(c for c in declared if c.value in allowed_set)

    # ---------------------------- self-description ----------------------------

    @classmethod
    @abstractmethod
    def schema(cls) -> ConnectorSchema:
        """Return the configuration schema for this connector.

        Authoring example::

            return ConnectorSchema(
                connector_id=cls.connector_id,
                connector_name=cls.connector_name,
                category=cls.connector_category,
                description="...",
                fields=[
                    Field("client_id", "string", "Client ID"),
                    Field("client_secret", "secret", "Client Secret"),
                ],
                docs_url="/docs/connectors/<id>",
            )
        """

    # ------------------------------ runtime ----------------------------------

    @abstractmethod
    async def test_connection(self) -> dict[str, Any]:
        """Test connectivity and credential validity."""

    @abstractmethod
    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        """Fetch recent alerts/events from the source."""

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize a raw event to a common AiSOC alert schema."""
        return raw

    # ----------------------------- ingest checkpoints (10b) -------------------
    #
    # The durable half of this shipped already: ``connector_repo.record_checkpoint``
    # persists a cursor into ``connector_config.checkpoint``, and the scheduler
    # seeds it before each poll and advances it only after ingest accepted the
    # entire submitted batch, so a failed or partially rejected push never
    # moves it forward.
    #
    # What was missing was adoption, and the reason it stayed missing is worth
    # keeping. The scheduler reached the connector through
    # ``getattr(connector, "set_checkpoint", None)``, which is simply absent on
    # a connector that has not implemented it — so eighty-three of the
    # eighty-four silently did nothing, at ``logger.debug``, and there was no
    # way to ask a connector whether it checkpoints at all. A duck-typed
    # optional protocol has no failing state; it only has a quiet one.
    #
    # So the contract lives here. The default is still not-checkpointing —
    # that has to stay true, because a connector whose cursor fields nobody has
    # identified must not pretend to have one — but it is now *declared*
    # not-checkpointing, which :meth:`checkpoints` can answer and a gate can
    # count.
    #
    # Adopting is two class attributes. A connector names the field carrying
    # each row's event time and the field carrying a stable per-row id, and the
    # generic machinery below does the rest: order by ``(time, id)``, drop
    # anything at or before the incoming cursor (which is what suppresses the
    # duplicates an overlapping poll window produces), and stage the advanced
    # value for the scheduler to persist.
    #
    # The tie-breaker is not optional. Two events in the same second are
    # ordinary, and a cursor on time alone either loses the second one or
    # replays the first forever.
    #
    # ----------------------------- and where it is wrong (phase 3) -----------
    #
    # Everything above assumes the source hands rows over in roughly event
    # order, which is true of a time-windowed API poll and is what makes a
    # high-water mark safe there: anything at or below the cursor really has
    # been seen.
    #
    # A queue makes no such promise. Pub/Sub gives no ordering unless the
    # topic was created with message ordering *and* the publisher sets an
    # ordering key, which a Cloud Logging sink does not; S3 notifications over
    # SQS are unordered by construction. On those sources an event older than
    # the last batch's newest is an ordinary first arrival, and a high-water
    # mark discards it the only time it will ever be offered.
    #
    # Such a connector declares :attr:`dedup_identity_field` instead. The
    # queue is what guarantees nothing is lost — an unacknowledged message
    # comes back — so the cursor's only remaining job is to recognise the
    # duplicate that at-least-once delivery will eventually produce, and a set
    # of identities does that without needing an order. Rows keep their
    # arrival order, because arrival order is the only order the source has.
    #
    # The set is bounded, and the direction of the bound is the point: falling
    # off the end of it costs a duplicate, where falling outside a watermark
    # cost the event. See :attr:`max_dedup_identities`.

    #: Field on a raw row carrying its event time. ``None`` means this
    #: connector does not checkpoint, which is the honest default.
    checkpoint_time_field: tuple[str, ...] = ()

    #: Field carrying a stable per-row identifier, used to break ties within
    #: the same timestamp. Required alongside ``checkpoint_time_field``.
    checkpoint_id_field: tuple[str, ...] = ()

    #: Per-poll bound for a queue- or object-backed source (depth plan 4.1).
    #: ``None`` for the API-polling connectors, where the time window is the
    #: bound. See :class:`CollectionBudget` for why the declaration carries a
    #: sentence rather than only two numbers.
    collection_budget: CollectionBudget | None = None

    #: Field carrying a stable, source-scoped identity for a row. Declaring it
    #: switches the cursor from a monotonic event-time watermark to a bounded
    #: set of seen identities — the right shape for an unordered queue, where
    #: "older than the last batch" does not mean "already seen".
    #:
    #: The identity must survive a redelivery of the same source data. A
    #: Pub/Sub ``messageId`` does; its ``ackId`` does not, because the vendor
    #: mints a fresh one every time it hands the message over.
    dedup_identity_field: tuple[str, ...] = ()

    #: How many identities the cursor remembers. Sized to cover more than one
    #: poll's worth for the connectors that declare it, because the window
    #: that needs covering is "accepted downstream but not yet acknowledged",
    #: which is at most the batch in flight. Exceeding it re-emits an event,
    #: which fusion and the lake can collapse; it never drops one.
    #:
    #: Stored as 16-hex truncated digests rather than raw identities: an
    #: object key is long and names a customer's bucket layout, and bounding
    #: the width bounds the JSONB this writes to a connector row (~190 kB at
    #: the default) regardless of what the source calls things.
    max_dedup_identities: int = 10_000

    #: Staged by :meth:`apply_checkpoint`, read by the scheduler after ingest
    #: accepts the batch. Declared here so it has one type rather than being
    #: introduced inside a branch.
    _incoming_checkpoint: dict[str, str] | None = None
    _next_checkpoint: dict[str, Any] | None = None

    #: Identities seeded from the persisted cursor, in the order they were
    #: last seen, so the bound forgets the oldest first.
    _incoming_seen: tuple[str, ...] = ()

    #: Source-side handles — SQS receipt handles, Pub/Sub ack ids — for
    #: messages whose events are in this poll's batch. Staged during the
    #: fetch, committed by the scheduler once ingest confirms the batch is
    #: durable. See :meth:`stage_acknowledgement`.
    _pending_acks: tuple[str, ...] = ()

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Checked at import rather than at poll time: a connector declaring
        # both schemes would silently use one of them, and which one is an
        # implementation detail of a dispatch nobody reads twice.
        if cls.dedup_identity_field and (cls.checkpoint_time_field or cls.checkpoint_id_field):
            raise ValueError(
                f"connector '{cls.connector_id}' declares both an event-time watermark and a dedup identity. "
                "They answer the same question two different ways: pick the watermark for an ordered API poll, "
                "the identity for an unordered queue."
            )

    @classmethod
    def checkpoints(cls) -> bool:
        """Whether this connector resumes from a persisted cursor.

        The question the ``getattr`` could not answer. A connector that
        returns False re-reads its overlap window after a restart, which is
        safe and means a long outage loses events older than that window.
        """
        if cls.dedup_identity_field:
            return True
        return bool(cls.checkpoint_time_field and cls.checkpoint_id_field)

    @classmethod
    def seen_tokens(cls, identities: Iterable[str]) -> list[str]:
        """Dedup tokens for ``identities``, in order.

        The connector id is part of the digest so two sources that happen to
        mint the same record id cannot suppress each other's events. Tenant
        scoping is structural rather than hashed in: the cursor lives on one
        connector *instance* row, which belongs to exactly one tenant.
        """
        prefix = cls.connector_id.encode("utf-8")
        return [hashlib.sha256(prefix + b"\x00" + str(identity).encode("utf-8")).hexdigest()[:16] for identity in identities]

    def set_checkpoint(self, checkpoint: dict[str, Any] | None) -> None:
        """Seed the poll with the last-accepted cursor (the scheduler owns it)."""
        self._incoming_checkpoint = None
        self._incoming_seen = ()
        if not isinstance(checkpoint, dict):
            return
        if self.dedup_identity_field:
            # A connector switched from a watermark to identity dedup finds
            # the old `{"time", "id"}` shape in its config. Reading it would
            # reinstate exactly the behaviour this replaced, so it is ignored
            # — at the cost of re-emitting whatever the last poll emitted
            # once, which is the safe direction.
            seen = checkpoint.get("seen")
            if isinstance(seen, list):
                self._incoming_seen = tuple(str(token) for token in seen if token)
            return
        if checkpoint.get("time") or checkpoint.get("id"):
            self._incoming_checkpoint = {"time": str(checkpoint.get("time") or ""), "id": str(checkpoint.get("id") or "")}

    def get_checkpoint(self) -> dict[str, Any] | None:
        """The advanced cursor after a fetch, or ``None`` if nothing moved.

        The scheduler persists this only once ingest has accepted every
        submitted event, so a failed or partially rejected ingest never
        advances it.
        """
        return self._next_checkpoint

    # ----------------------------- acknowledgement (phase 3) -----------------
    #
    # Separating "we have the data" from "the data is safe" is the whole of
    # finding 4. A connector reading a queue used to answer the source inside
    # ``fetch_alerts``, once the rows were in a local list — but a list is not
    # durability, and ``fetch_alerts`` returns long before the scheduler
    # pushes to ingest. A crash or a 5xx in that gap took messages that are no
    # longer redeliverable, and no cursor can help once a message is gone.
    #
    # So the fetch *stages* the source's handles and the scheduler commits
    # them, because the scheduler is the only layer that sees ingest's answer.
    # Acceptance means broker-confirmed Kafka delivery: ``services/ingest``
    # awaits ``PublishBatch`` with ``RequiredAcks: RequireAll`` and answers
    # 500 on failure, so a 200 with ``accepted == submitted`` is a real
    # guarantee. (Its graph fan-out is deliberately non-blocking and is not
    # part of that guarantee.)
    #
    # The bound: an SQS visibility timeout and a Pub/Sub ack deadline are
    # finite, so a held handle has an expiry. A connector that holds handles
    # stops taking new work once the poll has spent its share of the deadline
    # (see ``acknowledgement_hold_fraction``), leaving the rest for ingest and
    # the checkpoint write. Overrunning anyway costs a duplicate — the handle
    # is refused and the message redelivers — never a gap.

    #: Share of the source's acknowledgement deadline a poll may spend before
    #: it stops collecting. The remainder is the downstream budget: normalize,
    #: filter, push to ingest, persist the cursor. Half each is deliberately
    #: generous on both sides rather than tuned; the failure mode either way
    #: is a duplicate.
    acknowledgement_hold_fraction: float = 0.5

    def stage_acknowledgement(self, handles: Iterable[str]) -> None:
        """Record source handles to be answered once the batch is durable."""
        fresh = tuple(str(handle) for handle in handles if handle)
        if fresh:
            self._pending_acks = self._pending_acks + fresh

    def pending_acknowledgements(self) -> list[str]:
        """Handles staged by this poll and not yet committed."""
        return list(self._pending_acks)

    def take_pending_acknowledgements(self) -> list[str]:
        """Claim the staged handles, clearing them.

        Claiming before the vendor call rather than after means a handle is
        never committed twice if the call partially succeeds and is retried.
        """
        handles = list(self._pending_acks)
        self._pending_acks = ()
        return handles

    def discard_acknowledgements(self) -> None:
        """Drop the staged handles without answering the source.

        What the scheduler does when ingest did not accept the batch. The
        messages redeliver after their visibility timeout or ack deadline,
        which is the entire reason they were not deleted.
        """
        self._pending_acks = ()

    async def commit_acknowledgements(self) -> AcknowledgementResult:
        """Answer the source for every staged handle.

        The default is a no-op *only* when nothing was staged. A connector
        that stages handles and does not implement this would hold them to
        the end of the poll and then drop them, so the queue would never
        drain — louder here than as a backlog nobody attributes to us.
        """
        if not self._pending_acks:
            return AcknowledgementResult(requested=0, confirmed=0, failed=0)
        raise NotImplementedError(
            f"connector '{self.connector_id}' stages acknowledgements but does not implement commit_acknowledgements()"
        )

    def acknowledgement_deadline_seconds(self) -> int:
        """Seconds a staged handle stays valid, or 0 when there is no deadline.

        Overridden by connectors whose source enforces one: SQS reports the
        visibility timeout it was asked for, Pub/Sub the subscription's ack
        deadline.
        """
        return 0

    def acknowledgement_hold_exhausted(self, elapsed_seconds: float) -> bool:
        """Whether this poll has spent its share of the acknowledgement deadline.

        Called from a fetch loop before taking another batch. False when the
        source has no deadline, so a connector without one is unbounded by
        this and bounded by its ``collection_budget`` alone.
        """
        deadline = self.acknowledgement_deadline_seconds()
        if deadline <= 0:
            return False
        return elapsed_seconds >= deadline * self.acknowledgement_hold_fraction

    def _row_time(self, row: dict[str, Any]) -> str:
        return self._first_present(row, self.checkpoint_time_field)

    def _row_id(self, row: dict[str, Any]) -> str:
        return self._first_present(row, self.checkpoint_id_field)

    @staticmethod
    def _first_present(row: dict[str, Any], fields: tuple[str, ...]) -> str:
        for field_name in fields:
            value = row.get(field_name)
            if value not in (None, ""):
                return str(value)
        return ""

    def _row_identity(self, row: dict[str, Any]) -> str:
        return self._first_present(row, self.dedup_identity_field)

    def apply_checkpoint(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """De-duplicate against the cursor and stage the advance.

        A no-op for a connector that does not declare its cursor fields, so
        it is safe to call unconditionally from ``fetch_alerts``. Dispatches
        on which cursor the connector declared: an event-time watermark for an
        ordered poll, a bounded identity set for an unordered queue.
        """
        if self.dedup_identity_field:
            return self._apply_identity_dedup(rows)
        if not self.checkpoints():
            return rows

        ordered = sorted(rows, key=lambda r: (self._row_time(r), self._row_id(r)))
        cursor = self._incoming_checkpoint or {}
        cursor_key = (str(cursor.get("time") or ""), str(cursor.get("id") or ""))

        fresh: list[dict[str, Any]] = []
        for row in ordered:
            if cursor_key[0] and (self._row_time(row), self._row_id(row)) <= cursor_key:
                continue
            fresh.append(row)

        # Staged, never persisted here. Advancing on read rather than on
        # accept is the bug the scheduler's ordering exists to avoid: a batch
        # that ingest rejects must be re-read, not skipped.
        if fresh:
            last = fresh[-1]
            self._next_checkpoint = {"time": self._row_time(last), "id": self._row_id(last)}
        else:
            self._next_checkpoint = None
        return fresh

    def _apply_identity_dedup(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Drop rows this cursor has already seen; keep everything else.

        No ordering and no comparison against a watermark: on an unordered
        source the only thing that makes a row a duplicate is having seen that
        exact identity before.

        Rows are not de-duplicated against *each other* within one batch. The
        same object announced twice in one poll stays twice, which is what the
        watermark did too — the atom here is the cross-poll redelivery that
        at-least-once delivery guarantees, and collapsing within a batch would
        break a connector whose rows legitimately share an identity (every
        record read out of one S3 object shares its object key).
        """
        known = set(self._incoming_seen)
        fresh: list[dict[str, Any]] = []
        this_batch: list[str] = []
        unidentified = 0

        for row in rows:
            identity = self._row_identity(row)
            if not identity:
                # Cannot be proven a duplicate, so it is not treated as one.
                # Counted because a source that stopped emitting its id would
                # otherwise present as a quietly growing duplicate rate.
                unidentified += 1
                fresh.append(row)
                continue
            token = self.seen_tokens([identity])[0]
            if token in known:
                continue
            fresh.append(row)
            this_batch.append(token)

        if unidentified:
            logger.warning(
                "connector.dedup.row_without_identity",
                connector=self.connector_id,
                field=self.dedup_identity_field,
                rows=unidentified,
                detail="emitted without de-duplication; a redelivery of these cannot be recognised",
            )

        if not this_batch:
            self._next_checkpoint = None
            return fresh

        # Oldest first, so truncation forgets what is least likely to still
        # be in flight. The window that must stay covered is this batch: it is
        # the one that has been accepted downstream but not yet acknowledged.
        retained = [token for token in self._incoming_seen if token not in set(this_batch)] + this_batch
        if len(retained) > self.max_dedup_identities:
            dropped = len(retained) - self.max_dedup_identities
            retained = retained[dropped:]
            logger.info(
                "connector.dedup.identities_truncated",
                connector=self.connector_id,
                dropped=dropped,
                kept=len(retained),
                detail="a redelivery older than the retained window would be re-emitted, not dropped",
            )
        self._next_checkpoint = {"seen": retained}
        return fresh

    # ----------------------------- federated search --------------------------

    # Connectors that opt into federated search override ``supports_federated_search``
    # to True and implement ``query()``. Keeping it opt-in means a brand new
    # connector author doesn't have to think about query translation on day one.
    supports_federated_search: bool = False

    async def query(self, unified: UnifiedQuery) -> list[dict[str, Any]]:
        """Translate a ``UnifiedQuery`` and return matching rows.

        Default behaviour is to refuse, so a connector that hasn't been
        wired for federated search returns a clear error to the API layer
        rather than silently returning an empty result set (which would
        be indistinguishable from "no matches" and is a footgun).
        """
        raise NotImplementedError(f"connector '{self.connector_id}' does not support federated search")

    # ----------------------------- bidirectional ITSM (Workstream 8) ----------
    #
    # ``push_case`` mints an external ticket from an AiSOC case. Implementations
    # MUST return an ``ExternalTicketRef`` so the API layer can persist the
    # mapping in ``case_external_refs`` and avoid double-creation on retry.
    #
    # ``push_status_change`` projects an AiSOC status transition onto the
    # external system (e.g. AiSOC ``resolved`` → Jira "Done", ServiceNow
    # ``state=6``).  Implementations are expected to be idempotent and tolerate
    # the case where ``external_ref`` was created before the connector knew
    # about the case (e.g. inbound webhook flow).
    #
    # Both methods are *gated* by ``Capability.PUSH_CASE`` /
    # ``Capability.PUSH_STATUS`` from WS4. Connectors that don't declare those
    # capabilities raise ``NotImplementedError`` from the defaults so the
    # actions worker fails closed instead of silently skipping a case fan-out.

    async def push_case(self, case: dict[str, Any]) -> dict[str, Any]:
        """Create or update an external ticket from an AiSOC case.

        Args:
            case: A dict with at least ``id``, ``case_number``, ``title``,
                ``description``, ``severity``, ``status``, plus optional
                ``assignee``, ``tags``, ``mitre_techniques``, ``alert_ids``,
                and any prior ``external_ref`` (if this is an update / retry
                rather than a first-time push).

        Returns:
            ``{"external_id": str, "external_url": str|None, "vendor": str}``
            so the API layer can persist the link.

        Raises:
            NotImplementedError: connector did not declare ``Capability.PUSH_CASE``.
        """
        raise NotImplementedError(f"connector '{self.connector_id}' does not implement push_case")

    async def push_status_change(
        self,
        case: dict[str, Any],
        old_status: str,
        new_status: str,
        external_ref: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Project an AiSOC status transition onto the external ticket.

        Args:
            case: Same shape as ``push_case``'s argument.
            old_status: AiSOC status the case is moving *from*. Useful for
                detecting "open → closed" transitions that some ITSMs model
                as a workflow action rather than a field write.
            new_status: AiSOC status the case is moving *to*.
            external_ref: ``{"external_id", "external_url", "vendor"}`` row
                from ``case_external_refs``. ``None`` means "this case has
                never been pushed before" — implementations may choose to
                fall back to ``push_case`` in that situation.

        Returns:
            ``{"external_id", "external_url", "vendor", "external_status"}``.

        Raises:
            NotImplementedError: connector did not declare ``Capability.PUSH_STATUS``.
        """
        raise NotImplementedError(f"connector '{self.connector_id}' does not implement push_status_change")

    # ----------------------------- resource snapshots (T1.2) ----------------
    #
    # ``get_resource_config(resource_id, at_ts)`` is the read path for the
    # "config drift / time-travel" feature: given an external resource
    # identifier (an AWS ARN, an Azure resource ID, a GCP self_link, an Okta
    # user id, a GitHub repo full_name) and an ISO-8601 timestamp, return the
    # resource's recorded configuration *as of that moment*. The default raises
    # so every connector starts as a deliberate opt-in. T1.2 fills this in for
    # AWS / Azure / GCP / Okta / GitHub specifically; the rest stay as
    # not-implemented and the calling code falls back to "no historical state
    # available".

    async def get_resource_config(
        self,
        resource_id: str,
        at_ts: str | None = None,
    ) -> dict[str, Any]:
        """Return the recorded config of ``resource_id`` as of ``at_ts``.

        ``at_ts`` is an ISO-8601 UTC timestamp ("2026-05-13T18:00:00Z"); ``None``
        means "latest known". Implementations should return a JSON-serialisable
        dict; the caller is responsible for diffing successive snapshots.

        Default raises ``NotImplementedError`` so connectors that don't model a
        config plane fail loudly rather than silently returning ``{}``.
        """
        raise NotImplementedError(
            f"connector '{self.connector_id}' does not implement get_resource_config "
            "(T1.2 wires AWS / Azure / GCP / Okta / GitHub specifically)"
        )
