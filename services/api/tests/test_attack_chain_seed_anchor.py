"""The chain payload must say when the seed happened.

The console rendered ``chain[0]`` with the label "seed" and a comment
claiming the backend had sorted the chain chronologically. Both were
wrong: ``compute_attack_chain`` skips the seed entirely (it scores
"every non-seed candidate") and sorts by score descending, so the row
labelled "seed" was simply the highest-ranked *related* alert, and its
``dt_seconds`` — an absolute distance from the seed — was hidden behind
that label.

Ranking by relevance is the right behaviour and stays. What the payload
owed the renderer is the seed's own event time: without it a client
cannot tell whether a link happened before or after the seed, so it
cannot render an honest chronology no matter how it sorts.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta

from app.services.attack_chain import (
    DEFAULT_WINDOW,
    CandidateAlert,
    compute_attack_chain,
)
from tests.test_attack_chain import (
    SEED_ID,
    T0,
    TENANT,
    _build_lockbit_chain,
    _InMemoryLoader,
)


def _chain():
    loader = _InMemoryLoader(_build_lockbit_chain())
    chain = asyncio.run(
        compute_attack_chain(
            seed_alert_id=SEED_ID,
            tenant_id=TENANT,
            loader=loader,
            window=DEFAULT_WINDOW,
            window_label="24h",
            now=T0,
        )
    )
    assert chain is not None
    return chain


def test_payload_publishes_the_seed_event_time() -> None:
    """Without it, no client can place a link before or after the seed."""
    payload = _chain().to_dict()
    assert "seed_event_time" in payload, (
        "the chain payload names a seed alert but never says when it happened, "
        "so a renderer cannot show the direction of any link's dt_seconds"
    )
    assert payload["seed_event_time"] == T0.isoformat()


def test_the_seed_is_never_a_link_in_the_chain() -> None:
    """Pins the invariant the console contradicted by labelling row 0 'seed'."""
    payload = _chain().to_dict()
    assert payload["chain"], "fixture should produce a non-empty chain"
    assert all(link["alert_id"] != str(SEED_ID) for link in payload["chain"])


def _divergent_fixture() -> list[CandidateAlert]:
    """A chain whose rank order is NOT its time order.

    The repository's existing LockBit fixture cannot tell the two apart —
    its alerts get steadily further from the seed in time *and* in graph
    distance, so score order and time order coincide. That is a large part
    of why the console could render rank order under a chronological label
    for so long without any test objecting. This fixture separates them:
    a far-in-time but directly-linked critical alert outranks a nearer but
    two-hops-away informational one.
    """
    seed_id, mid_id, early_id, late_id = (uuid.uuid4() for _ in range(4))
    common = {"tenant_id": TENANT, "affected_ips": (), "connector_type": "ci"}
    return [
        CandidateAlert(
            id=seed_id,
            title="Seed: suspicious script execution",
            severity="critical",
            event_time=T0,
            mitre_techniques=("T1059",),
            affected_users=("alice@acme.test",),
            affected_hosts=(),
            affected_assets=(),
            source_event_ids=("evt-seed",),
            **common,
        ),
        CandidateAlert(
            id=mid_id,
            title="Bucket touched by the same identity",
            severity="low",
            event_time=T0 + timedelta(minutes=30),
            mitre_techniques=(),
            affected_users=("alice@acme.test",),
            affected_hosts=(),
            affected_assets=("s3://acme-research",),
            source_event_ids=("evt-mid",),
            **common,
        ),
        CandidateAlert(
            id=early_id,
            title="Informational bucket read, two hops out",
            severity="info",
            event_time=T0 + timedelta(hours=1),
            mitre_techniques=(),
            affected_users=(),
            affected_hosts=(),
            affected_assets=("s3://acme-research",),
            source_event_ids=("evt-early",),
            **common,
        ),
        CandidateAlert(
            id=late_id,
            title="Same identity, same technique, twenty hours later",
            severity="critical",
            event_time=T0 + timedelta(hours=20),
            mitre_techniques=("T1059",),
            affected_users=("alice@acme.test",),
            affected_hosts=(),
            affected_assets=(),
            source_event_ids=("evt-late",),
            **common,
        ),
    ]


def test_links_are_ranked_by_relevance_not_by_time() -> None:
    """The ranking is deliberate; a client that wants chronology sorts itself."""
    alerts = _divergent_fixture()
    loader = _InMemoryLoader(alerts)
    chain = asyncio.run(
        compute_attack_chain(
            seed_alert_id=alerts[0].id,
            tenant_id=TENANT,
            loader=loader,
            window=DEFAULT_WINDOW,
            window_label="24h",
            now=T0,
        )
    )
    assert chain is not None
    scores = [link.score for link in chain.chain]
    assert scores == sorted(scores, reverse=True), "chain is ranked by score"
    times = [link.event_time for link in chain.chain]
    assert times != sorted(times), (
        "this fixture exists to separate rank order from time order; if they coincide it can no longer catch a client that confuses the two"
    )


def test_every_link_carries_a_time_a_client_can_order_by() -> None:
    payload = _chain().to_dict()
    seed_time = payload["seed_event_time"]
    for link in payload["chain"]:
        assert link["event_time"]
        # dt_seconds is an absolute distance; direction comes from
        # comparing the two timestamps, which is why the seed's is needed.
        assert link["dt_seconds"] >= 0
        assert (link["event_time"] > seed_time) == (link["event_time"] > T0.isoformat())


def test_seed_event_time_survives_a_window_that_excludes_nothing() -> None:
    loader = _InMemoryLoader(_build_lockbit_chain())
    chain = asyncio.run(
        compute_attack_chain(
            seed_alert_id=SEED_ID,
            tenant_id=TENANT,
            loader=loader,
            window=timedelta(days=7),
            window_label="7d",
            now=T0,
        )
    )
    assert chain is not None
    assert chain.to_dict()["seed_event_time"] == T0.isoformat()
