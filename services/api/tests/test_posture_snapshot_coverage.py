"""Which providers can resolve permissions *live* must be stated, not implied.

A resolver reporting ``coverage: "full"`` describes a pure function over a
provider snapshot and says nothing about whether a snapshot can be obtained.
For most of this subsystem's life no connector could produce one for any
cloud provider, so every live call answered 412 while the endpoint advertised
full coverage — and nothing in the tree recorded the difference.

Depth-plan 2.5 closed that: all six providers now have a connector that
answers the ``__posture_snapshot__`` sentinel. These tests hold the closed
state closed. The *behavioural* proof that each connector really collects
lives in ``services/connectors/tests/test_posture_collectors.py``, which
drives ``get_resource_config`` through a stubbed transport; this file can
only assert the declarations, because ``services/api`` and
``services/connectors`` both name their top-level package ``app`` and
importing one in a process shadows the other.

A note on the detector that used to live here, because the lesson outlasted
it. The previous version read each connector's source and asserted the
sentinel string was absent, as a reverse check that the documented gap was
still real. After all five connectors were wired it still passed on four of
them: a connector that imports the shared ``POSTURE_SNAPSHOT_ID`` constant
does not contain the literal ``__posture_snapshot__``, so the grep could only
ever recognise the hardcoded spelling — the one nobody should write. A
source-reading test cannot notice whether the code runs, and this one could
not even notice whether it existed.
"""

from __future__ import annotations

import inspect

from app.services.effective_permissions.posture_loader import (
    POSTURE_SNAPSHOT_ID,
    PROVIDER_CONNECTOR,
)
from app.services.effective_permissions.service import SUPPORTED_PROVIDERS

#: Providers whose snapshot cannot be collected live, with the reason.
#: Empty since 2.5. A provider may be added back when a real gap appears,
#: but never silently: `test_every_registered_resolver_can_collect_a_snapshot`
#: fails on a resolver that has no declared source at all, and this list is
#: the only way to record a source that exists and does not work.
NO_LIVE_SNAPSHOT: dict[str, str] = {}


def test_every_registered_resolver_has_a_snapshot_source_declared() -> None:
    """A resolver with no entry in PROVIDER_CONNECTOR can never run live, and
    would report `coverage: full` while always 412-ing."""
    missing = set(SUPPORTED_PROVIDERS) - set(PROVIDER_CONNECTOR)
    assert not missing, f"{sorted(missing)} have a resolver but no declared snapshot source"


def test_every_registered_resolver_can_collect_a_snapshot() -> None:
    """The inverse of the gap list, which is the direction that rots.

    Before 2.5 this read "only okta". Keeping the assertion pointed at the
    *whole* provider set means adding a seventh resolver without a collector
    fails here rather than shipping as another silent 412.
    """
    uncollectable = set(SUPPORTED_PROVIDERS) & set(NO_LIVE_SNAPSHOT)
    assert not uncollectable, f"{sorted(uncollectable)} cannot collect a live snapshot: " + "; ".join(
        f"{p}: {NO_LIVE_SNAPSHOT[p]}" for p in sorted(uncollectable)
    )


def test_the_sentinel_is_spelled_the_same_on_both_sides() -> None:
    """The API loader and the connectors package each declare the constant.

    They cannot import from one another — two different services, both with
    a top-level package called ``app`` — so the one thing that stops them
    drifting to two spellings is this assertion. A mismatch would make every
    cloud provider 412 again, with each side's unit tests still green.
    """
    connectors_init = (
        __import__("pathlib").Path(__file__).resolve().parents[2] / "connectors" / "app" / "connectors" / "posture" / "__init__.py"
    )
    if not connectors_init.is_file():
        # services/connectors is not in every checkout of this service.
        return

    source = connectors_init.read_text(encoding="utf-8")
    declared = next(
        line.split("=", 1)[1].strip().strip('"').strip("'") for line in source.splitlines() if line.startswith("POSTURE_SNAPSHOT_ID")
    )
    assert declared == POSTURE_SNAPSHOT_ID, (
        f"the connectors package declares {declared!r} and the API loader declares "
        f"{POSTURE_SNAPSHOT_ID!r}; every cloud provider would 412 with both sides green"
    )


def test_no_resolver_claims_scaffold_coverage() -> None:
    """The endpoint docstring described four providers as scaffolds returning
    501 long after they were implemented, which made the 501 branch
    unreachable documentation."""
    for provider, cls in SUPPORTED_PROVIDERS.items():
        assert cls.coverage == "full", f"{provider} reports coverage={cls.coverage!r}"


def test_the_endpoint_docstring_does_not_call_them_scaffolds() -> None:
    """Prose drifts from code silently, so assert on the prose."""
    from app.api.v1.endpoints import effective_permissions as endpoint

    doc = inspect.getdoc(endpoint) or ""
    assert "Scaffolded providers" not in doc, "the endpoint docstring still describes implemented resolvers as scaffolds"
