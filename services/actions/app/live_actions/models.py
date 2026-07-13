"""
Data models for the generic ``live_action`` interface.

The live-action layer is the registry-driven counterpart to the original
``EXECUTOR_REGISTRY`` (``services/actions/app/services/executor_registry.py``).
That registry is keyed by the ``ActionType`` enum and only knows about the
in-tree executors that ship with the actions service. It cannot be extended
at runtime, which means every new vendor integration requires a code change
inside the actions service itself.

The live-action layer flips that model on its head:

* Implementations are keyed by ``(vendor_id, capability)`` rather than a
  fixed ``ActionType``. ``vendor_id`` matches the connector ID surfaced by
  ``services/connectors`` (e.g. ``"crowdstrike"``, ``"defender"``,
  ``"okta"``, or any plugin-supplied ID). ``capability`` reuses the existing
  ``Capability`` enum from ``services/connectors/app/connectors/base.py``,
  so the agent's planner does not have to learn a separate vocabulary.
* Multiple implementations can coexist for the same capability — one per
  vendor — and the dispatcher picks the right one based on the request.
* Plugins can register their own implementations at startup via
  :func:`live_actions.registry.register_executor`, including for
  capabilities that no in-tree executor currently supports.

Why we did not just extend ``EXECUTOR_REGISTRY`` directly:
  1. ``ActionType`` and ``Capability`` are not 1:1 — capabilities like
     ``BLOCK_HASH``, ``REVOKE_TOKEN``, or future plugin-only verbs have no
     corresponding ``ActionType`` member. Extending ``ActionType`` for every
     plugin would make it the integration choke point we are trying to
     escape.
  2. The classic registry has no notion of *which vendor* implements the
     action. ``IsolateHostExecutor`` itself fans out to CrowdStrike or
     Defender by inspecting ``parameters["vendor"]``. That hides the choice
     from the planner and from audit logs.
  3. Plugin authors should be able to ship a new ``(vendor_id, capability)``
     pair without reaching into the actions service. Registry-driven dispatch
     is the cleanest way to express that.

Both layers continue to coexist. The classic ``/api/v1/actions`` endpoint
keeps its current behaviour for backwards compatibility; the new
``/api/v1/live-actions`` endpoints (defined in
``app.live_actions.router``) sit alongside it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class LiveActionStatus(str, Enum):
    """Final state of a live-action execution.

    Distinct from :class:`app.models.action.ActionStatus` because the
    live-action layer does not (yet) own approval/rollback orchestration —
    it is a pure execution surface. The fewer states we expose here, the
    clearer the contract for plugin authors.
    """

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SIMULATED = "simulated"  # No credentials → safe simulation path.
    # Phase B2 — the autonomy-safety gate (Phase 9a `decide()`) is wired into
    # dispatch. These two states mean the executor was intentionally NOT
    # invoked: the tier/blast policy blocked it outright, or it needs a human.
    BLOCKED = "blocked"
    PENDING_APPROVAL = "pending_approval"


class LiveActionRequest(BaseModel):
    """Request payload accepted by a :class:`LiveActionExecutor`.

    ``capability`` and ``vendor_id`` are stored as strings rather than the
    ``Capability`` enum so the wire format is stable even if the enum
    grows new members in older deployments. The dispatcher validates them
    against the registry on the way in.

    ``params`` is intentionally an open-ended dict — different vendors need
    different shapes (CrowdStrike's RTR script vs Okta's user lookup) and
    forcing a single typed schema across all of them would either exclude
    real integrations or require a discriminated union we'd have to extend
    every time we add a connector.

    ``dry_run`` is a first-class request field rather than a query param
    because the agent planner emits it as part of the action plan; we want
    the same payload shape whether the executor was invoked from REST,
    from the agent runner, or from a unit test.
    """

    request_id: UUID = Field(default_factory=uuid4)
    capability: str
    vendor_id: str
    target: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    # Phase B2 — connector-style credentials (schema field names, e.g.
    # ``client_id`` / ``api_token``). When present, the dispatcher translates
    # them into the executor's vendor-prefixed params via
    # ``app.services.credential_resolver.resolve_params`` — so callers holding
    # a decrypted connector ``auth_config`` don't need to know each executor's
    # parameter vocabulary. Explicit ``params`` keys win on collision.
    auth_config: dict[str, Any] | None = None
    dry_run: bool = False

    # Provenance — these are filled in by the API layer / agent runner so
    # the executor's structured logs can be correlated back to the case or
    # playbook that triggered it. They are optional because plugin authors
    # invoking executors directly (e.g. from tests) shouldn't have to mint
    # synthetic UUIDs.
    case_id: UUID | None = None
    playbook_run_id: UUID | None = None
    tenant_id: UUID | None = None
    requested_by: str = "system"


class LiveActionResult(BaseModel):
    """Result returned by a :class:`LiveActionExecutor`.

    ``summary`` is a one-line human-readable string that the case timeline
    renders verbatim — keep it short and concrete (e.g.
    ``"Isolated host srv-12 on CrowdStrike (rtr_session=abc123)"``), not
    a paragraph.

    ``details`` carries the structured payload the vendor returned, so
    downstream consumers (agent reflection, post-mortems) can dig in
    without a second round-trip.

    ``error`` is set when ``status == FAILED``; we keep ``status`` as the
    source of truth and let consumers special-case ``error is not None``
    only when they want a stack-trace-style display.
    """

    request_id: UUID
    status: LiveActionStatus
    capability: str
    vendor_id: str
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class LiveActionDescriptor(BaseModel):
    """Discovery payload returned by ``GET /api/v1/live-actions``.

    Lets the agent planner (and the frontend "test action" UI) enumerate
    the available ``(vendor_id, capability)`` pairs without having to
    introspect Python class hierarchies. ``source`` distinguishes
    ``"builtin"`` adapters (which wrap the in-tree executors) from
    ``"plugin"`` registrations so operators can audit which integrations
    a deployment is actually using.
    """

    vendor_id: str
    capability: str
    description: str
    source: str  # "builtin" | "plugin"
    requires_credentials: bool = True
