"""Residency policy + region mesh primitives (t6-multi-region).

Three concerns:

1. **Mesh discovery** — parse ``settings.region_peers`` into a
   :class:`RegionMesh`. The mesh exposes a typed view of every peer
   (``region_id``, ``base_url``, ``residency_zone``).

2. **Per-tenant home region** — :class:`TenantHomeRegion` is the
   persisted record. We give every tenant a home region; the
   default is the platform's configured ``region_default_residency_zone``.

3. **Decision** — :func:`decide_residency` takes a
   ``(local_region_id, tenant_home_region_id)`` and returns a
   :class:`ResidencyDecision` that tells the request handler what
   to do: serve locally, forward to a peer, or reject with 451.

The decision logic is intentionally pure and synchronous so it can
be called from inside a FastAPI dependency without taking a lock
or doing I/O.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Protocol


class ResidencyError(Exception):
    """Raised when a tenant lives outside the allowed residency zones."""


@dataclass(frozen=True)
class RegionInfo:
    """A peer in the multi-region mesh."""

    region_id: str
    base_url: str
    residency_zone: str

    @property
    def is_local(self) -> bool:
        # The mesh sets this attribute on the local entry only;
        # callers should compare ``region_id`` directly.
        return False


@dataclass(frozen=True)
class RegionMesh:
    """An immutable view of every region in the active-active mesh."""

    local_region_id: str
    regions: tuple[RegionInfo, ...]
    allowed_residency_zones: frozenset[str]

    def by_id(self, region_id: str) -> Optional[RegionInfo]:
        for r in self.regions:
            if r.region_id == region_id:
                return r
        return None

    def local(self) -> Optional[RegionInfo]:
        return self.by_id(self.local_region_id)

    def remote_regions(self) -> tuple[RegionInfo, ...]:
        return tuple(r for r in self.regions if r.region_id != self.local_region_id)

    def is_zone_allowed(self, zone: str) -> bool:
        if not self.allowed_residency_zones:
            return True
        return zone in self.allowed_residency_zones


def parse_peers(peers_csv: str) -> tuple[RegionInfo, ...]:
    """Parse the ``AISOC_REGION_PEERS`` env-var format into typed records.

    Format::

        region_id|base_url|residency_zone, region_id|base_url|residency_zone

    Whitespace and trailing commas are ignored.
    """

    out: list[RegionInfo] = []
    for raw in (peers_csv or "").split(","):
        raw = raw.strip()
        if not raw:
            continue
        parts = [p.strip() for p in raw.split("|")]
        if len(parts) != 3 or not all(parts):
            raise ValueError(
                f"region peer entry malformed: '{raw}' "
                f"(expected region_id|base_url|residency_zone)"
            )
        out.append(
            RegionInfo(
                region_id=parts[0],
                base_url=parts[1].rstrip("/"),
                residency_zone=parts[2],
            )
        )
    return tuple(out)


def build_region_mesh(
    *,
    local_region_id: str,
    peers_csv: str,
    allowed_zones_csv: str = "",
) -> RegionMesh:
    """Build the immutable :class:`RegionMesh` from settings."""

    peers = parse_peers(peers_csv)
    if not peers:
        # Tests and minimal dev deployments may not set
        # AISOC_REGION_PEERS. Synthesise a single local entry so the
        # rest of the policy logic has something to operate on.
        peers = (
            RegionInfo(
                region_id=local_region_id,
                base_url="",
                residency_zone="local",
            ),
        )
    if not any(r.region_id == local_region_id for r in peers):
        raise ValueError(
            f"local region '{local_region_id}' not present in region_peers; "
            f"add it to AISOC_REGION_PEERS so the policy can discover its zone"
        )
    allowed = frozenset(
        z.strip() for z in (allowed_zones_csv or "").split(",") if z.strip()
    )
    return RegionMesh(
        local_region_id=local_region_id,
        regions=peers,
        allowed_residency_zones=allowed,
    )


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


class RegionResolution(str, Enum):
    """What the request handler should do."""

    serve_locally = "serve_locally"
    forward_to_peer = "forward_to_peer"
    reject_residency = "reject_residency"


@dataclass(frozen=True)
class ResidencyDecision:
    resolution: RegionResolution
    target_region: Optional[RegionInfo] = None
    reason: str = ""


def decide_residency(
    *,
    mesh: RegionMesh,
    tenant_home_region_id: str,
) -> ResidencyDecision:
    """Resolve a request given the tenant's home region.

    Returns one of three outcomes:

    * Serve locally — the tenant's home region is this process.
    * Forward to peer — the tenant's home region is a different
      region in the mesh; the response carries the peer's
      ``base_url`` so the gateway can proxy the request.
    * Reject — the tenant's home region is not in the mesh, or its
      residency zone falls outside the allowed set.
    """

    if not tenant_home_region_id:
        return ResidencyDecision(
            resolution=RegionResolution.serve_locally,
            target_region=mesh.local(),
            reason="no_home_region_set_default_local",
        )

    target = mesh.by_id(tenant_home_region_id)
    if target is None:
        return ResidencyDecision(
            resolution=RegionResolution.reject_residency,
            target_region=None,
            reason=(
                f"tenant home region '{tenant_home_region_id}' is not "
                f"registered in this mesh"
            ),
        )

    if not mesh.is_zone_allowed(target.residency_zone):
        return ResidencyDecision(
            resolution=RegionResolution.reject_residency,
            target_region=target,
            reason=(
                f"residency zone '{target.residency_zone}' is not allowed "
                f"by this deployment"
            ),
        )

    if target.region_id == mesh.local_region_id:
        return ResidencyDecision(
            resolution=RegionResolution.serve_locally,
            target_region=target,
            reason="home_region_is_local",
        )

    return ResidencyDecision(
        resolution=RegionResolution.forward_to_peer,
        target_region=target,
        reason=(
            f"home region '{target.region_id}' differs from local "
            f"'{mesh.local_region_id}'"
        ),
    )


# ---------------------------------------------------------------------------
# Forwarder protocol
# ---------------------------------------------------------------------------


class RegionForwarder(Protocol):
    """Forwarder contract.

    ``forward`` takes the resolved peer plus the original request
    method/path/body and returns the peer's response as
    ``(status_code, body_dict)``. The forwarder is allowed to
    raise :class:`ResidencyError` on transport failures so the
    gateway can return 503.
    """

    def forward(
        self,
        *,
        target: RegionInfo,
        method: str,
        path: str,
        json: Optional[dict] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> tuple[int, dict]:
        ...
