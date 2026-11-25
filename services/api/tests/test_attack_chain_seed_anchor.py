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
from collections.abc import Iterable
from datetime import datetime, timedelta

from app.services.attack_chain import (
    DEFAULT_WINDOW,
    CandidateAlert,
    compute_attack_chain,
)

# Self-contained on purpose. Importing the sibling suite's fixtures gives
# mypy one file under two module names ("test_attack_chain" and
# "tests.test_attack_chain"), which is a fatal error that stops it checking
# the tree at all — the whole gate, not just this file.
TENANT = uuid.UUID("00000000-0000-0000-0000-000000000777")
T0 = datetime(2026, 5, 14, 8, 0, 0)
SEED_ID = uuid.uuid4()


class _InMemoryLoader:
    """Walks a fixture list the way the Postgres loader walks the table."""

    def __init__(self, alerts: list[CandidateAlert]) -> None:
        self._by_id = {a.id: a for a in alerts}
        self._all = alerts

    async def load_seed(self, alert_id: uuid.UUID, tenant_id: uuid.UUID) -> CandidateAlert | None:
        row = self._by_id.get(alert_id)
        if row is None or row.tenant_id != tenant_id:
            return None
        return row

    async def load_candidates_for_entities(
        self,
        tenant_id: uuid.UUID,
        entities: Iterable[tuple[str, str]],
        start: datetime,
        end: datetime,
        exclude_ids: set[uuid.UUID],
    ) -> list[CandidateAlert]:
        wanted = set(entities)
        return [
            row
            for row in self._all
            if row.tenant_id == tenant_id and row.id not in exclude_ids and start <= row.event_time <= end and row.entities() & wanted
        ]


def _build_lockbit_chain() -> list[CandidateAlert]:
    """A seed plus two alerts linked by the same identity."""
    return [
        CandidateAlert(
            id=SEED_ID,
            title="Phishing email with malicious attachment delivered",
            severity="medium",
            event_time=T0,
            mitre_techniques=("T1566.001",),
            affected_users=("jdoe@acme.test",),
            affected_hosts=("WIN-USR-101",),
            affected_ips=(),
            source_event_ids=("evt-phish-001",),
            tenant_id=TENANT,
            connector_type="ci",
            affected_assets=(),
        ),
        CandidateAlert(
            id=uuid.uuid4(),
            title="Credential harvesting via fake O365 login portal",
            severity="high",
            event_time=T0 + timedelta(minutes=5),
            mitre_techniques=("T1566.002",),
            affected_users=("jdoe@acme.test",),
            affected_hosts=("WIN-USR-101",),
            affected_ips=(),
            source_event_ids=("evt-cred-002",),
            tenant_id=TENANT,
            connector_type="ci",
            affected_assets=(),
        ),
        CandidateAlert(
            id=uuid.uuid4(),
            title="Cloud auth anomaly: impossible-travel sign-in",
            severity="high",
            event_time=T0 + timedelta(hours=2),
            mitre_techniques=("T1078.004",),
            affected_users=("jdoe@acme.test",),
            affected_hosts=(),
            affected_ips=("203.0.113.42",),
            source_event_ids=("evt-auth-003",),
            tenant_id=TENANT,
            connector_type="ci",
            affected_assets=(),
        ),
    ]


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
            tenant_id=TENANT,
            connector_type="ci",
            affected_ips=(),
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
            tenant_id=TENANT,
            connector_type="ci",
            affected_ips=(),
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
            tenant_id=TENANT,
            connector_type="ci",
            affected_ips=(),
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
            tenant_id=TENANT,
            connector_type="ci",
            affected_ips=(),
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
