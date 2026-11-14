"""Identity-posture collection (depth plan 2.5).

A resolver in ``services/api/app/services/effective_permissions/`` is pure:
hand it a snapshot of an estate's identities, roles and policies and it
computes what a principal can actually do. Until now the production loader
returned ``{}`` for every cloud provider, so every live call answered 412 and
the whole subsystem had never once described a real estate. Okta was the only
provider assembled, and it was assembled in the API service.

These collectors are the missing half. Each one reads a provider's identity
plane through the connector that already holds the credential and returns the
snapshot shape that provider's resolver documents.

Three rules the collectors share, each of which exists because the opposite
has shipped here before.

**A gap is data, not a log line.** A collector that cannot read part of the
estate returns what it got with ``partial=True`` and a note naming what was
missed. The resolver's answer is only as complete as its input, and a triage
surface that cannot say "this is incomplete, here is why" will render a gap
as an absence -- an identity that looks harmless because the policy granting
it everything was in the page that 403'd.

**An empty collection is a real and important state.** Zero principals means
the credential lost its read permission far more often than it means the
estate is empty, so an empty snapshot is never silently treated as success.

**Nothing is fabricated.** A collector that cannot reach the provider returns
no snapshot at all and the endpoint answers 412 exactly as it did before.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Sentinel resource id. ``get_resource_config`` returns the full provider
#: snapshot for this id rather than one resource's config. Kept here so the
#: connectors and the API loader cannot drift to two spellings; the API side
#: declares the same constant and a test asserts they are equal.
POSTURE_SNAPSHOT_ID = "__posture_snapshot__"


@dataclass
class Collected:
    """A posture snapshot plus an honest account of what is missing from it."""

    snapshot: dict[str, Any]
    partial: bool = False
    notes: list[str] = field(default_factory=list)

    def note(self, message: str) -> None:
        """Record a gap. Recording one always marks the snapshot partial.

        The two cannot be set separately on purpose: every earlier version of
        this idea in the tree had a notes list that some callers filled and
        no caller read, so the flag and the reason are one operation.
        """
        self.notes.append(message)
        self.partial = True

    def to_resource_config(self) -> dict[str, Any]:
        """The envelope ``get_resource_config`` returns for the sentinel id."""
        return {
            "snapshot": self.snapshot,
            "partial": self.partial,
            "collection_notes": list(self.notes),
        }
