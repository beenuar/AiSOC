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

#: The figure the docs and the console publish, as a percentage.
#:
#: Pinned here, beside the measurement, because the plausible band below is
#: deliberately wide and would not notice the ratio moving from 33.3 % to
#: 34.1 % — while every published surface went on quoting the old one. The
#: band asks "is the correlation still sane"; this asks "is the number we
#: printed still the number". `scripts/check_alert_reduction_claims.py` reads
#: this constant and holds every published surface to it, so the chain from
#: measurement to prose has no hand-copied link in it.
PUBLISHED_REDUCTION_PCT = 33.3

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


def group_by_real_key(stream: list[tuple[datetime, RawAlert]], window: timedelta = WINDOW) -> int:
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

    print(f"\n[eval] alert reduction (real correlation_key): {len(stream)} alerts -> {incidents} incidents = {reduction:.1%}")

    # Bounded on both sides. A floor alone would be satisfied by a key that
    # collapses everything into one incident, which is 99.9% reduction and
    # a useless SOC.
    assert 0.20 <= reduction <= 0.95, (
        f"reduction {reduction:.1%} is outside the plausible band; either correlation stopped grouping or it is collapsing unrelated alerts"
    )

    assert round(reduction * 100, 1) == PUBLISHED_REDUCTION_PCT, (
        f"reduction is now {reduction:.1%} but PUBLISHED_REDUCTION_PCT says {PUBLISHED_REDUCTION_PCT} %, "
        "which is what the benchmark pages print. Update the constant and re-run "
        "`python3 scripts/check_alert_reduction_claims.py` so the published surfaces move with it."
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
    assert RawAlert(**base, src_ip="10.0.0.1", hostname="ws-1").correlation_key().endswith("10.0.0.1:exec")


def test_alerts_without_a_tactic_do_not_all_collapse_together() -> None:
    """A missing identifier narrows the group instead of widening it.

    The previous fallback substituted the literal "unknown", and since
    neither detection engine sets `mitre_tactics`, every detection alert on
    one entity collapsed into one incident per window regardless of rule —
    and alerts with no entity merged tenant-wide. This file pinned that as
    "current behaviour, pinned so a change to it is deliberate"; this is the
    deliberate change.
    """
    a = RawAlert(tenant_id=TENANT, source="s", title="a", hostname="ws-1")
    b = RawAlert(tenant_id=TENANT, source="s", title="b", hostname="ws-2")
    assert a.correlation_key() != b.correlation_key()

    # Same entity, no tactic: grouping is per detection rule. The same rule
    # firing repeatedly is the storm correlation exists for; two different
    # rules are not known to be one incident and no longer merge.
    storm_1 = RawAlert(tenant_id=TENANT, source="s", title="a", hostname="ws-1", rule_id="r-1")
    storm_2 = RawAlert(tenant_id=TENANT, source="s", title="b", hostname="ws-1", rule_id="r-1")
    other_rule = RawAlert(tenant_id=TENANT, source="s", title="c", hostname="ws-1", rule_id="r-2")
    assert storm_1.correlation_key() == storm_2.correlation_key()
    assert storm_1.correlation_key() != other_rule.correlation_key()
    assert storm_1.correlation_key() == f"{TENANT}:ws-1:rule:r-1"

    # No entity: never groups across rules, and never tenant-wide.
    bare_a = RawAlert(tenant_id=TENANT, source="s", title="a", rule_id="r-1")
    bare_b = RawAlert(tenant_id=TENANT, source="s", title="b", rule_id="r-2")
    assert bare_a.correlation_key() != bare_b.correlation_key()
    assert bare_a.correlation_key() == f"{TENANT}:no-entity:rule:r-1:no-tactic"

    # No entity and no rule: zero evidence of relatedness groups nothing but
    # exact repeats of one shape (the dedup fingerprint).
    blank_a = RawAlert(tenant_id=TENANT, source="s", title="a")
    blank_b = RawAlert(tenant_id=TENANT, source="s", title="b")
    assert blank_a.correlation_key() != blank_b.correlation_key(), (
        "two alerts with no entity, no tactic and no rule carry no evidence of being related; merging them buries one under the other"
    )
    repeat = RawAlert(tenant_id=TENANT, source="s", title="a")
    assert blank_a.correlation_key() == repeat.correlation_key(), "an exact repeat of the same shape still groups"


#: The detection-shaped measurement. Both detection engines emit alerts with
#: a rule_id and NO mitre_tactics, so this stream — not the tactic-carrying
#: one above — is the shape the fallback governs. Measured on this fixed
#: cohort before and after the fallback landed (same stream, same window,
#: real `correlation_key()` both times):
#:
#:   before  574 incidents, 42.6 % reduction, 36 incident-groups spanning
#:           more than one rule, every no-entity alert merged tenant-wide
#:   after   755 incidents, 24.5 % reduction, 0 cross-rule groups
#:
#: The reduction went DOWN and that is the honest direction: the difference
#: was unrelated alerts being counted as grouped. Review-work reduction is
#: only worth having over groups that are actually related.
DETECTION_STREAM_REDUCTION_PCT = 24.5

DETECTION_RULES = [f"det-rule-{i:02d}" for i in range(14)]


def build_detection_stream(size: int = STREAM_SIZE) -> list[tuple[datetime, RawAlert]]:
    """Detection-engine-shaped alerts: rule_id set, no tactics, ~4% entity-less."""
    start = datetime(2026, 9, 22, 8, 0, tzinfo=UTC)
    stream: list[tuple[datetime, RawAlert]] = []
    for n in range(size):
        rule = DETECTION_RULES[_seeded(n, "rule", len(DETECTION_RULES))]
        host: str | None
        if n % 25 == 0:
            host = None
            offset = timedelta(minutes=_seeded(n, "ne-time", 240))
        elif n % 10 < 4:
            host = f"ws-{_seeded(n, 'burst-host', 12):03d}"
            offset = timedelta(minutes=_seeded(n, "burst-time", 45))
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
                    severity=AlertSeverity.MEDIUM,
                    rule_id=rule,
                    mitre_tactics=[],
                ),
            )
        )
    return stream


def _group_members(stream: list[tuple[datetime, RawAlert]], window: timedelta = WINDOW) -> dict[tuple[str, datetime], list[RawAlert]]:
    """Alerts by the incident-group they land in under the real key + window."""
    open_at: dict[str, datetime] = {}
    members: dict[tuple[str, datetime], list[RawAlert]] = {}
    for when, alert in sorted(stream, key=lambda pair: pair[0]):
        key = alert.correlation_key()
        opened = open_at.get(key)
        if opened is None or when - opened > window:
            open_at[key] = when
        members.setdefault((key, open_at[key]), []).append(alert)
    return members


def test_detection_shaped_stream_reduction_and_purity() -> None:
    """The measurement for the alerts the fallback actually governs.

    Three properties, each a claim the published figure rests on:

    * the reduction matches the published constant, so the number in prose
      cannot drift from the measurement;
    * no incident group spans more than one detection rule — cross-rule
      merges were exactly the unrelated-collapse this fallback removes;
    * every alert is accounted for: group sizes sum to the stream size, so
      nothing vanished into the grouping.
    """
    stream = build_detection_stream()
    members = _group_members(stream)
    incidents = len(members)
    reduction = 1 - (incidents / len(stream))

    print(f"\n[eval] detection-shaped reduction (real correlation_key): {len(stream)} alerts -> {incidents} incidents = {reduction:.1%}")

    assert round(reduction * 100, 1) == DETECTION_STREAM_REDUCTION_PCT, (
        f"detection-shaped reduction is now {reduction:.1%} but DETECTION_STREAM_REDUCTION_PCT says "
        f"{DETECTION_STREAM_REDUCTION_PCT} % — update the constant and the published surfaces together"
    )

    cross_rule = [group for group in members.values() if len({a.rule_id for a in group}) > 1]
    assert not cross_rule, (
        f"{len(cross_rule)} incident group(s) span more than one detection rule; the conservative fallback exists to make that impossible"
    )

    assert sum(len(group) for group in members.values()) == len(stream), "every alert resolves to exactly one group; nothing may vanish"


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
