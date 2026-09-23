"""Alert reduction, measured against the correlation logic that actually runs.

The existing measurement in `services/agents/tests/test_alert_reduction.py`
is honest about being synthetic and has always carried a PARTIAL row saying
it "gates an in-test fusion re-impl, not `services/fusion`". Reading it
closely, the gap is wider than that wording suggests: the test does not
merely reimplement fusion's grouping, it implements **different** grouping.

Its docstring describes four tiers keyed on `(rule_id, host, user)` with
10/30/5-minute windows. `RawAlert.correlation_key()` — the method
`Correlator` actually calls — keys on `{tenant}:{entity}:{tactic}`, where
entity is the first of src_ip, hostname, username, domain. Different
dimensions, different windows, different answer. The published
alert-reduction figure therefore described an algorithm the product does
not run.

This measures the real one. `Correlator` itself needs Redis, but Redis is
where it *stores* incidents — the grouping decision is entirely
`correlation_key()` plus the configured window, so the ratio can be
computed from the real method without the storage layer.

The number this produces is a property of a synthetic workload and is
labelled as such, exactly as the original was. What changes is that it is
now a property of *our* algorithm.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.models.alert import AlertSeverity, RawAlert

TENANT = UUID("11111111-1111-1111-1111-111111111111")

#: Matches the production default (`CORRELATION_WINDOW_SECONDS`). Read as a
#: literal rather than from settings so the measurement does not silently
#: change meaning when an operator tunes their own deployment.
WINDOW = timedelta(seconds=3600)

#: Alert count. Same order as the original so the two numbers are
#: comparable, which is the point of keeping both.
STREAM_SIZE = 1000

TACTICS = [
    "initial-access",
    "execution",
    "persistence",
    "credential-access",
    "lateral-movement",
    "exfiltration",
]


def _seeded(n: int, salt: str, modulus: int) -> int:
    """Deterministic index. blake2b, not hash(): CPython salts string
    hashing per process, so a `hash()`-seeded stream would produce a
    different reduction ratio on every run and the figure would be
    unreproducible — the same defect the sandbox had."""
    digest = hashlib.blake2b(f"{salt}:{n}".encode(), digest_size=8).digest()
    return int.from_bytes(digest, "big") % modulus


def build_stream(size: int = STREAM_SIZE) -> list[tuple[datetime, RawAlert]]:
    """A noisy alert stream with the shapes fusion is supposed to collapse.

    Generated independently of the correlation logic — the point of the
    measurement is that the stream does not know how it will be grouped.
    """
    start = datetime(2026, 9, 22, 8, 0, tzinfo=UTC)
    stream: list[tuple[datetime, RawAlert]] = []

    for n in range(size):
        # A burst: many alerts from one host in a tight window, the case
        # correlation exists for.
        if n % 10 < 4:
            host = f"ws-{_seeded(n, 'burst-host', 12):03d}"
            offset = timedelta(minutes=_seeded(n, "burst-time", 45))
        # Scattered singletons that should survive as distinct incidents.
        else:
            host = f"ws-{_seeded(n, 'wide-host', 400):03d}"
            offset = timedelta(minutes=_seeded(n, "wide-time", 1440))

        stream.append(
            (
                start + offset,
                RawAlert(
                    tenant_id=TENANT,
                    source="synthetic",
                    title=f"alert {n}",
                    hostname=host,
                    username=f"u{_seeded(n, 'user', 60)}",
                    severity=AlertSeverity.MEDIUM,
                    mitre_tactics=[TACTICS[_seeded(n, "tactic", len(TACTICS))]],
                ),
            )
        )
    return stream


def group_by_real_key(
    stream: list[tuple[datetime, RawAlert]], window: timedelta = WINDOW
) -> int:
    """Incident count under the real correlation key and window.

    Mirrors what `Correlator.correlate` does: look up the incident for this
    alert's correlation key, join it if one is open, otherwise open a new
    one. Redis is the lookup table; the decision is the key.
    """
    open_incidents: dict[str, datetime] = {}
    incidents = 0

    for when, alert in sorted(stream, key=lambda pair: pair[0]):
        key = alert.correlation_key()
        opened = open_incidents.get(key)
        if opened is not None and when - opened <= window:
            continue
        open_incidents[key] = when
        incidents += 1

    return incidents


def test_reduction_is_measured_against_the_real_correlation_key() -> None:
    """The measurement runs `RawAlert.correlation_key()`, not a copy of it.

    A reimplementation can drift from the thing it stands for without any
    test failing, and this one had — it grouped on different dimensions
    entirely.
    """
    stream = build_stream()
    incidents = group_by_real_key(stream)
    reduction = 1 - (incidents / len(stream))

    print(
        f"\n[eval] alert reduction (real correlation_key): "
        f"{len(stream)} alerts -> {incidents} incidents = {reduction:.1%}"
    )

    # Bounded on both sides. A floor alone would be satisfied by a key that
    # collapses everything into one incident, which is 99.9% reduction and
    # a useless SOC.
    assert 0.20 <= reduction <= 0.95, (
        f"reduction {reduction:.1%} is outside the plausible band; either "
        f"correlation stopped grouping or it is collapsing unrelated alerts"
    )


def test_the_key_is_the_products_key_not_a_local_one() -> None:
    """Pins the dimensions, so a change to `correlation_key()` that alters
    what gets grouped cannot pass silently."""
    alert = RawAlert(
        tenant_id=TENANT,
        source="s",
        title="t",
        src_ip="10.0.0.1",
        hostname="ws-1",
        username="alice",
        mitre_tactics=["execution"],
    )
    assert alert.correlation_key() == f"{TENANT}:10.0.0.1:execution"


def test_entity_precedence_is_src_ip_then_hostname() -> None:
    """Which entity wins decides what groups with what, so it is worth
    pinning rather than inferring from the reduction number."""
    base = {"tenant_id": TENANT, "source": "s", "title": "t", "mitre_tactics": ["exec"]}
    assert RawAlert(**base, hostname="ws-1").correlation_key().endswith("ws-1:exec")
    assert (
        RawAlert(**base, src_ip="10.0.0.1", hostname="ws-1")
        .correlation_key()
        .endswith("10.0.0.1:exec")
    )


def test_alerts_without_a_tactic_do_not_all_collapse_together() -> None:
    """`correlation_key()` falls back to the literal "unknown" for both
    entity and tactic. Two unrelated alerts each missing one field still
    differ on the other; two missing both would merge, which is worth
    knowing rather than discovering in production."""
    a = RawAlert(tenant_id=TENANT, source="s", title="a", hostname="ws-1")
    b = RawAlert(tenant_id=TENANT, source="s", title="b", hostname="ws-2")
    assert a.correlation_key() != b.correlation_key()

    bare_a = RawAlert(tenant_id=TENANT, source="s", title="a")
    bare_b = RawAlert(tenant_id=TENANT, source="s", title="b")
    assert bare_a.correlation_key() == bare_b.correlation_key(), (
        "two alerts with no entity and no tactic share a key and will merge; "
        "this is current behaviour, pinned so a change to it is deliberate"
    )


def test_the_stream_is_reproducible() -> None:
    """A measurement that moves between runs is not a measurement."""
    first = group_by_real_key(build_stream())
    second = group_by_real_key(build_stream())
    assert first == second


def test_a_wider_window_reduces_more() -> None:
    """Sanity on the window's direction. If this inverts, the grouping is
    not doing what the name says."""
    stream = build_stream()
    narrow = group_by_real_key(stream, timedelta(minutes=5))
    wide = group_by_real_key(stream, timedelta(hours=24))
    assert wide <= narrow
