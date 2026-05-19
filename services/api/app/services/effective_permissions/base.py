"""Abstract ``Resolver`` interface + shared dataclasses (T3.2).

Every concrete resolver (``aws.py``, ``azure.py``, ``gcp.py``, ``okta.py``,
``gws.py``) implements :class:`Resolver`. The shape of the result is
deliberately provider-agnostic so the API endpoint, the Cytoscape UI, and the
Neo4j cache writer all consume one envelope:

* ``actions`` is a sorted list of provider-namespaced action strings
  (``s3:GetObject``, ``Microsoft.Storage/storageAccounts/read``,
  ``okta.users.read``) — what the principal can *do*.
* ``deny_actions`` is the (typically empty) set of actions the resolver
  identified as explicitly denied, even though some upstream policy in the
  chain attempted to allow them. The UI surfaces these in red so SOC analysts
  can see "you tried to grant this, but the SCP / Azure deny assignment /
  organisation policy blocks it."
* ``policy_chain`` is the ordered provenance — every Policy / Role / Binding
  the resolver visited to reach the decision. Each step carries an ``effect``
  so the UI can render the deny-overrides hops in line.

This module never imports a provider SDK. Concrete resolvers can pull in
``boto3`` (or whatever) at module import time; the dispatcher in
``service.py`` looks them up by name, never directly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

RESOLVER_VERSION = "v1.0"

Effect = Literal["allow", "deny"]
Coverage = Literal["full", "scaffold"]


@dataclass(frozen=True)
class PolicyChainStep:
    """A single hop in the resolver's reasoning trail.

    Attributes
    ----------
    kind:
        High-level kind — ``"role"``, ``"policy"``, ``"binding"``,
        ``"scp"``, ``"deny-assignment"``, ``"org-policy"``.
    id:
        Stable identifier for the artefact (IAM policy ARN, Azure role
        assignment GUID, Okta group id, etc.). Always present so the UI can
        anchor a node in the Cytoscape graph.
    name:
        Human-readable label rendered on the UI node.
    effect:
        Whether this step contributed an allow or a deny to the final
        decision. ``deny`` overrides ``allow`` upstream by convention.
    via:
        Optional pointer to the parent step (e.g. a Policy attached via a
        Role) — lets the UI draw the connecting edge without re-querying.
    """

    kind: str
    id: str
    name: str
    effect: Effect = "allow"
    via: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "id": self.id,
            "name": self.name,
            "effect": self.effect,
            "via": self.via,
        }


@dataclass(frozen=True)
class ResolvedPermission:
    """One ``(principal, resource)`` decision."""

    principal_id: str
    resource_id: str
    actions: tuple[str, ...]
    deny_actions: tuple[str, ...] = ()
    policy_chain: tuple[PolicyChainStep, ...] = ()
    resource_kind: str | None = None
    resource_arn: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "resource_id": self.resource_id,
            "resource_kind": self.resource_kind,
            "resource_arn": self.resource_arn,
            "actions": list(self.actions),
            "deny_actions": list(self.deny_actions),
            "policy_chain": [step.to_dict() for step in self.policy_chain],
        }


@dataclass
class ResolverResult:
    """The envelope returned by every resolver.

    The ``last_resolved`` timestamp is exactly the one stamped on the
    ``:EFFECTIVE_PERMISSION`` Neo4j edges by the cache writer — so a UI client
    can correlate the graph snapshot it sees with the API call that produced
    it without a second round-trip.
    """

    provider: str
    principal_id: str
    coverage: Coverage
    last_resolved: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    decisions: list[ResolvedPermission] = field(default_factory=list)
    resolver_version: str = RESOLVER_VERSION
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "principal_id": self.principal_id,
            "coverage": self.coverage,
            "resolver_version": self.resolver_version,
            "last_resolved": self.last_resolved.isoformat(),
            "decisions": [decision.to_dict() for decision in self.decisions],
            "notes": list(self.notes),
        }

    def total_actions(self) -> int:
        return sum(len(d.actions) for d in self.decisions)


class ResolverError(RuntimeError):
    """Operational failure inside a provider resolver.

    Surfaces upward as an HTTP 502 from the API endpoint — the request was
    well-formed but the resolver couldn't reach (or interpret) the source of
    truth.
    """


class Resolver(ABC):
    """Abstract per-provider resolver.

    Concrete subclasses declare ``provider`` and ``coverage`` as class
    attributes and implement :meth:`resolve`.
    """

    provider: str = ""
    coverage: Coverage = "scaffold"

    @abstractmethod
    def resolve(
        self,
        principal_id: str,
        *,
        snapshot: dict[str, Any] | None = None,
    ) -> ResolverResult:
        """Resolve effective permissions for ``principal_id``.

        Parameters
        ----------
        principal_id:
            Provider-scoped identifier (AWS ARN, Azure object id, GCP
            member, Okta user id, Workspace user key).
        snapshot:
            Optional in-memory policy snapshot. Tests pass this in to keep
            the resolver hermetic; production callers leave it ``None`` and
            the resolver reads from its bound store (typically Neo4j, but
            scaffolds use a fixture).
        """


def chain_ids(steps: tuple[PolicyChainStep, ...]) -> list[str]:
    """Flatten a policy chain to the ids the Neo4j cache writes back.

    Order is preserved so the UI can replay the exact same provenance path
    the resolver followed.
    """

    return [step.id for step in steps]
