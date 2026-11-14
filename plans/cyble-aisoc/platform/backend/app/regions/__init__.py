"""Multi-region active-active routing + data-residency policy (t6-multi-region).

This module is the single place every request-time check has to
agree on:

* What region am I?
* What region does *this tenant* live in?
* Is the active region allowed to serve this tenant under the
  configured residency policy?
* If not, where do I forward the request to?

The actual cross-region transport is intentionally pluggable. The
default :class:`HttpRegionForwarder` proxies the request to the
peer region's REST endpoint; a tested, in-process
:class:`InMemoryRegionForwarder` is used by the smoke test so the
multi-region semantics can be verified without booting two
processes.
"""
from app.regions.policy import (
    RegionForwarder,
    RegionInfo,
    RegionMesh,
    RegionResolution,
    ResidencyDecision,
    ResidencyError,
    build_region_mesh,
    decide_residency,
    parse_peers,
)

__all__ = [
    "RegionForwarder",
    "RegionInfo",
    "RegionMesh",
    "RegionResolution",
    "ResidencyDecision",
    "ResidencyError",
    "build_region_mesh",
    "decide_residency",
    "parse_peers",
]
