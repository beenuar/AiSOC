"""Which providers can resolve permissions *live* must be stated, not implied.

All five resolvers (AWS, Azure, GCP, Okta, Google Workspace) are implemented
and report ``coverage: "full"``. That describes the resolver, which is a pure
function over a provider snapshot — and says nothing about whether a snapshot
can be obtained.

Only Okta's is assembled from a live connector. The other four expect a
connector to answer the ``__posture_snapshot__`` sentinel from
``get_resource_config``, and **no connector implements it**, so with
``AISOC_EFFECTIVE_PERMISSIONS_LIVE=1`` they return 412 rather than a
fabricated snapshot.

That is an honest state, but nothing recorded it, so "coverage: full" was the
only number a reader saw. These tests pin the real shape of the gap: if a
connector implements the sentinel, the allow-list below must shrink, and if a
resolver is registered without one, that fails too. The gap is allowed to
exist; it is not allowed to be invisible.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest
from app.services.effective_permissions.posture_loader import (
    POSTURE_SNAPSHOT_ID,
    PROVIDER_CONNECTOR,
)
from app.services.effective_permissions.service import SUPPORTED_PROVIDERS

#: Providers whose snapshot cannot yet be collected live, with the reason.
#: Shrink this as connectors implement the sentinel; never grow it silently.
NO_LIVE_SNAPSHOT = {
    "aws": "aws_security_hub does not answer __posture_snapshot__",
    "azure": "azure_entra implements no get_resource_config at all",
    "gcp": "gcp_scc treats the id as an SCC finding name, not a posture request",
    "gws": "google_workspace implements no get_resource_config at all",
}

CONNECTORS_DIR = Path(__file__).resolve().parents[2] / "connectors" / "app" / "connectors"


def test_every_registered_resolver_has_a_snapshot_source_declared() -> None:
    """A resolver with no entry in PROVIDER_CONNECTOR can never run live, and
    would report `coverage: full` while always 412-ing."""
    missing = set(SUPPORTED_PROVIDERS) - set(PROVIDER_CONNECTOR)
    assert not missing, f"{sorted(missing)} have a resolver but no declared snapshot source"


def test_the_live_gap_is_exactly_the_four_cloud_providers() -> None:
    """Okta is the only provider assembled end-to-end today."""
    live = set(PROVIDER_CONNECTOR) - set(NO_LIVE_SNAPSHOT)
    assert live == {"okta"}, f"the set of live-capable providers changed to {sorted(live)} — update NO_LIVE_SNAPSHOT and the docs"


@pytest.mark.skipif(not CONNECTORS_DIR.is_dir(), reason="services/connectors is not in this checkout")
@pytest.mark.parametrize("provider", sorted(NO_LIVE_SNAPSHOT))
def test_a_provider_on_the_gap_list_really_cannot_collect_a_snapshot(provider: str) -> None:
    """The reverse direction, which is the one that rots.

    A one-directional gate would only check that listed providers stay
    listed. This asserts the listing is still *true*: if the connector starts
    handling the sentinel, the allow-list is stale and must shrink — otherwise
    a capability that now works keeps being reported as missing.
    """
    connector_id = PROVIDER_CONNECTOR[provider]
    source_file = CONNECTORS_DIR / f"{connector_id}.py"
    if not source_file.is_file():
        pytest.fail(f"{provider} maps to connector '{connector_id}', which has no module at {source_file}")

    source = source_file.read_text(encoding="utf-8")
    assert POSTURE_SNAPSHOT_ID not in source, (
        f"{connector_id} now references {POSTURE_SNAPSHOT_ID}, so '{provider}' may be able to "
        f"collect a live snapshot. Remove it from NO_LIVE_SNAPSHOT and update the endpoint docstring."
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
