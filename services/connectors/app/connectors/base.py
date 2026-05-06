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
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from app.federated.query import UnifiedQuery

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

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "connector_id": self.connector_id,
            "connector_name": self.connector_name,
            "category": self.category,
            "description": self.description,
            "fields": [f.to_dict() for f in self.fields],
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
