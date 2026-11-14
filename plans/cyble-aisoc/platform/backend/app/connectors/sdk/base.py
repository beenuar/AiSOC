"""Base types for the Connector SDK.

A *connector* is a typed adapter to one external security platform for
one tenant. Sub-classes of `BaseConnector` implement the operations the
tool layer calls (e.g. `search_events`, `isolate_host`, `revoke_sessions`).

Every connector is owned by one `ConnectorKind` family (SIEM, EDR, IDP,
EMAIL, …) and reports its vendor (e.g. `splunk`, `crowdstrike`, `okta`).
The tool layer routes by `ConnectorKind`; the registry decides which
vendor to instantiate based on the tenant's configuration.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ConnectorKind(str, Enum):
    """Logical family of integrations.

    The tool layer asks for a kind; the registry decides which vendor
    answers. A tenant can only have one active connector per kind, e.g.
    you can't run Splunk and Sentinel SIEM concurrently for the same
    tenant in v1 — pick one. (Multiple-SIEM fan-out is on the roadmap
    for `t1-realtime-data` but explicitly out of scope here.)
    """

    SIEM = "siem"
    EDR = "edr"
    IDP = "idp"
    EMAIL = "email"
    TICKETING = "ticketing"
    COMMS = "comms"
    THREAT_INTEL = "threat_intel"
    SOAR = "soar"
    # Theme 2d: Cloud Detection & Response. One per-tenant active cloud
    # connector covers the IaaS / control-plane slice (AWS today, GCP/Azure
    # on roadmap). Owns IAM principal graph, STS session inventory,
    # access-key lifecycle, and Kubernetes RBAC reads + targeted revokes.
    CLOUD = "cloud"
    # Theme 2e: SaaS Security Posture Management. One per-tenant active
    # SaaS connector fans out across M365, Google Workspace, Salesforce,
    # GitHub, and Slack (the v1 starter set). Owns the application
    # inventory, public-share / external-collaborator inventory,
    # third-party OAuth/integration inventory, and the targeted
    # remediation surface (revoke OAuth grant, restrict share, remove
    # external member). One kind, many providers — the connector itself
    # multiplexes per `provider` parameter on each call.
    SAAS = "saas"
    # Theme 2j: Live Endpoint Forensics. Deep, on-demand collection from
    # endpoints — artifact collection (process listings, autoruns,
    # network state, persistence artifacts, file timelines), tenant-wide
    # hunts that fan a query out to every connected agent, file fetch
    # for offline analysis, and process termination scoped to a single
    # PID. Velociraptor is the v1 implementation; KAPE / GRR / Wazuh
    # FIM live on the same protocol. Distinct from EDR (which owns
    # always-on telemetry + containment): forensics is *pull*, slower,
    # and answers the post-containment "what actually happened on the
    # box" question.
    FORENSICS = "forensics"


class ConnectorError(RuntimeError):
    """Base class for any error originating in a connector.

    The tool layer catches this and turns it into a structured tool-call
    result (`success=False`, `error=str(e)`) — it never bubbles into the
    LLM as a Python exception.
    """

    def __init__(self, message: str, *, vendor: str | None = None, status: int | None = None) -> None:
        super().__init__(message)
        self.vendor = vendor
        self.status = status


class ConnectorAuthError(ConnectorError):
    """Credentials missing, expired, or refused by the vendor."""


class ConnectorTimeoutError(ConnectorError):
    """Vendor did not respond within the deadline."""


class ConnectorRateLimitError(ConnectorError):
    """Vendor rejected with 429 / quota-exceeded."""

    def __init__(self, message: str, *, vendor: str | None = None, retry_after: float | None = None) -> None:
        super().__init__(message, vendor=vendor, status=429)
        self.retry_after = retry_after


@dataclass(frozen=True)
class ConnectorConfig:
    """Resolved per-tenant configuration for a single connector instance.

    This is the *runtime* config a connector sees. It is built by the
    registry from either:
      - the `connectorconfig` DB table (set via the admin API), or
      - environment-variable defaults (`AISOC_DEFAULT_SIEM_VENDOR`, …).

    Secrets live in `secrets`; the connector should treat them as
    opaque and never log them. `params` is non-secret config (host,
    indexes, default lookback, …).
    """

    tenant_id: str
    kind: ConnectorKind
    vendor: str
    params: dict[str, Any] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)
    enabled: bool = True

    def secret(self, name: str, *, required: bool = True) -> str:
        value = self.secrets.get(name)
        if not value:
            if required:
                raise ConnectorAuthError(
                    f"connector {self.vendor}: missing secret {name!r}",
                    vendor=self.vendor,
                )
            return ""
        return value

    def param(self, name: str, default: Any = None) -> Any:
        return self.params.get(name, default)


class BaseConnector(ABC):
    """Abstract base for all real and mock connectors.

    Concrete connectors live under `app/connectors/<vendor>/connector.py`
    and inherit from a kind-specific protocol (e.g. `BaseSiemConnector`)
    that pins the operation signatures the tool layer expects.

    Lifecycle:
      - `__init__(config)`  — store config, do not do I/O
      - `health_check()`    — verify creds work; called by admin API
      - per-operation async methods — called by tool handlers
      - `aclose()`          — close any HTTP client

    Connectors are cached per `(tenant_id, kind)` so HTTP keepalive and
    OAuth tokens survive across tool calls.
    """

    #: Class-level vendor identifier, e.g. `"splunk"`, `"crowdstrike"`.
    vendor: str = "unknown"
    #: Class-level kind. Must be set by subclasses.
    kind: ConnectorKind

    def __init__(self, config: ConnectorConfig) -> None:
        self.config = config

    @property
    def tenant_id(self) -> str:
        return self.config.tenant_id

    @abstractmethod
    async def health_check(self) -> dict[str, Any]:
        """Verify the connector can talk to its backend.

        Returns a small status dict (e.g. `{"ok": True, "vendor": "splunk",
        "latency_ms": 42}`). Raises `ConnectorAuthError` if credentials
        are wrong.
        """
        raise NotImplementedError

    async def aclose(self) -> None:
        """Release HTTP clients, sessions, etc. Default is a no-op."""
        return None

    def __repr__(self) -> str:  # pragma: no cover - debug only
        return f"<{type(self).__name__} tenant={self.tenant_id!r} vendor={self.vendor!r}>"
