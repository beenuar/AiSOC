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

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Iterable, Literal

if TYPE_CHECKING:
    from app.federated.query import UnifiedQuery


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
#   3. Update ``test_capabilities`` in ``services/connectors/tests/test_capabilities.py``.
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
    SEARCH_SIEM = "search_siem"
    CREATE_NOTABLE_EVENT = "create_notable_event"
    SYNC_DETECTION_RULE = "sync_detection_rule"
    UPDATE_WATCHER = "update_watcher"

    # TICKET — bidirectional ITSM (Jira / ServiceNow / etc.).
    PUSH_CASE = "push_case"
    PUSH_STATUS = "push_status"

    # AUDIT — read-only configuration / posture queries.
    READ_AUDIT_TRAIL = "read_audit_trail"


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
            Capability.BLOCK_HASH,
            Capability.BLOCK_DOMAIN,
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
    def effective_capabilities(
        cls, allowed: Iterable[str] | None = None
    ) -> tuple[Capability, ...]:
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
        raise NotImplementedError(
            f"connector '{self.connector_id}' does not implement push_case"
        )

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
        raise NotImplementedError(
            f"connector '{self.connector_id}' does not implement push_status_change"
        )
