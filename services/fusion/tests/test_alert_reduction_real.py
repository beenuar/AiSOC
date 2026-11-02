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
from app.services.alert_sink import root_cause_key

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


# ── Phase 3.3: repeat folding, measured and labelled separately ───────────
#
# Deduplication and correlation are two different reductions and this file
# publishes them as two different numbers. Correlation groups *related*
# alerts; deduplication folds *the same alert arriving again*. Adding them
# into one headline would be the oldest trick in this category — the
# "75.3 %" this suite exists to retract was exactly a number whose
# denominator nobody could name.
#
# Fusion's fold is permanent, not windowed. The 300 s Redis check in
# `Deduplicator` is a fast path; `uq_alerts_tenant_dedup` (migration 120) is
# on `(tenant_id, dedup_hash)` with no time component, so a repeat folds onto
# the surviving row however much later it arrives. The fold below models the
# index, which is the authority.
#
# Measured on the fixed cohort below, same method both times:
#
#   before 3.3  1000 inputs -> 716 alerts, and 284 folded repeats left no
#               trace anywhere: no count, no window, no link back. The only
#               residue was a `source_event_ids` append, capped at 200 and
#               shared with multi-event correlation, so its length is not a
#               repeat count
#   after  3.3  1000 inputs -> 716 alerts, 284 repeats retained as linked
#               occurrences on the alert each folded onto, each resolving to
#               that alert's id
#
# The *reduction is identical before and after, and that is the point*: 3.3
# folds nothing new. It stops throwing away what the fold removed. The
# number worth publishing is therefore not a bigger reduction — it is the
# same reduction with its 284 inputs accounted for instead of absent, which
# is why this is a separately labelled row and not an addition to either
# correlation figure.
REPEAT_STREAM_DEDUP_PCT = 28.4

#: How many distinct findings the repeating vendors emit. A small set that
#: repeats hard is the real shape: a GuardDuty brute-force finding re-reported
#: every few minutes for a day is one finding and hundreds of deliveries.
_REPEATING_FINDINGS = 24


def build_repeat_stream(size: int = STREAM_SIZE) -> list[tuple[datetime, RawAlert]]:
    """Vendor-shaped traffic in which some findings are re-reported.

    Deliberately not uniform. Roughly a quarter of the stream is re-delivery
    of a small set of noisy findings, and the rest are distinct — which is
    what a cloud-security connector's output actually looks like, and what
    makes the dedup figure worth publishing separately from correlation.
    """
    start = datetime(2026, 9, 22, 8, 0, tzinfo=UTC)
    stream: list[tuple[datetime, RawAlert]] = []
    for n in range(size):
        offset = timedelta(minutes=_seeded(n, "repeat-time", 1440))
        if _seeded(n, "is-repeat", 100) < 30:
            # A re-report of one of the noisy findings. Identical in every
            # field `fingerprint()` reads, which is what makes it a repeat
            # rather than a similar alert.
            which = _seeded(n, "which-finding", _REPEATING_FINDINGS)
            alert = RawAlert(
                tenant_id=TENANT,
                source="AWS GuardDuty",
                title=f"UnauthorizedAccess:EC2/SSHBruteForce finding {which:02d}",
                hostname=f"i-{which:04d}",
                severity=AlertSeverity.HIGH,
                mitre_techniques=["T1110"],
            )
        else:
            # Detection-shaped, carrying a rule_id and no tactics. Shaped this
            # way deliberately: a cohort whose non-repeating half cannot group
            # would let the composition test below pass with correlation doing
            # nothing at all, which is a test that proves the two reductions
            # compose by never exercising one of them.
            alert = RawAlert(
                tenant_id=TENANT,
                source="synthetic",
                title=f"distinct alert {n}",
                hostname=f"ws-{_seeded(n, 'distinct-host', 60):03d}",
                severity=AlertSeverity.MEDIUM,
                rule_id=DETECTION_RULES[_seeded(n, "repeat-rule", len(DETECTION_RULES))],
                mitre_tactics=[],
            )
        stream.append((start + offset, alert))
    return stream


def fold_repeats(
    stream: list[tuple[datetime, RawAlert]],
) -> tuple[dict[str, tuple[datetime, RawAlert]], dict[str, list[tuple[datetime, RawAlert]]]]:
    """Split a stream into surviving alerts and the repeats that folded onto them.

    Mirrors what the sink does: the first sighting of a fingerprint becomes
    the row, and every later one is a `DUPLICATE` that `_record_deduplicated_event`
    turns into an occurrence. Keyed on `fingerprint()` — the same function
    that produces `alerts.dedup_hash` — rather than on a copy of its field
    list, because a test that re-implemented the fingerprint would measure
    itself.
    """
    surviving: dict[str, tuple[datetime, RawAlert]] = {}
    folded: dict[str, list[tuple[datetime, RawAlert]]] = {}
    for when, alert in sorted(stream, key=lambda pair: pair[0]):
        fingerprint = alert.fingerprint()
        if fingerprint in surviving:
            folded.setdefault(fingerprint, []).append((when, alert))
        else:
            surviving[fingerprint] = (when, alert)
    return surviving, folded


def test_repeat_folding_reduction_is_its_own_labelled_figure() -> None:
    """The dedup reduction, published separately from correlation.

    Two numbers that answer two questions. Nothing here is added to the
    correlation figure, and the test asserts that they are not equal so a
    future edit cannot quietly make one stand in for the other.
    """
    stream = build_repeat_stream()
    surviving, folded = fold_repeats(stream)
    folded_count = sum(len(repeats) for repeats in folded.values())
    reduction = 1 - (len(surviving) / len(stream))

    print(
        f"\n[eval] repeat folding (real fingerprint()): {len(stream)} inputs -> "
        f"{len(surviving)} alerts, {folded_count} folded = {reduction:.1%}"
    )

    assert round(reduction * 100, 1) == REPEAT_STREAM_DEDUP_PCT, (
        f"repeat-folding reduction is now {reduction:.1%} but REPEAT_STREAM_DEDUP_PCT says "
        f"{REPEAT_STREAM_DEDUP_PCT} %, which is what the published surfaces print. Update the "
        "constant and re-run `python3 scripts/check_alert_reduction_claims.py`."
    )
    assert REPEAT_STREAM_DEDUP_PCT != PUBLISHED_REDUCTION_PCT, (
        "the dedup figure and the correlation figure have become the same number; they measure "
        "different things and must stay separately labelled"
    )


def test_every_folded_repeat_is_accounted_for_and_resolves_to_its_alert() -> None:
    """The eval-honesty balance, extended to cover folding.

    The rule the replay scorer holds for closures and that
    `test_detection_shaped_stream_reduction_and_purity` holds for grouping:
    every input lands in exactly one bucket and the buckets sum to the
    denominator. Folding adds a bucket, and this is where a repeat could
    vanish into a reduction numerator — 258 inputs disappearing into a
    headline with nothing to point at.

    Two properties, not one. Balance says nothing was lost *in aggregate*;
    resolvability says each folded repeat can still be followed back to the
    record that absorbed it. A count that balances while pointing nowhere is
    the shape of a number that cannot be audited.
    """
    stream = build_repeat_stream()
    surviving, folded = fold_repeats(stream)

    retained = len(surviving)
    folded_count = sum(len(repeats) for repeats in folded.values())

    assert retained + folded_count == len(stream), (
        f"{retained} retained + {folded_count} folded = {retained + folded_count}, "
        f"against {len(stream)} inputs; a repeat vanished into the reduction"
    )

    # Every folded repeat resolves to the alert it folded onto, by the same
    # key the database uses. `deterministic_id()` is derived from the
    # fingerprint, so this is the id an occurrence row's `alert_id` carries.
    for fingerprint, repeats in folded.items():
        assert fingerprint in surviving, f"{len(repeats)} repeats folded onto no retained alert"
        _, survivor = surviving[fingerprint]
        for _, repeat in repeats:
            assert repeat.deterministic_id() == survivor.deterministic_id(), (
                "a folded repeat does not resolve to the retained alert's id, so its "
                "occurrence row would point at a row that is not its survivor"
            )

    # And the count a reader sees is the total sighting count, survivor
    # included — the `COALESCE(occurrence_count, 1)` contract from migration
    # 151, stated here as the arithmetic rather than as a comment. Summing
    # it back to the denominator is what makes that contract checkable: a
    # count that excluded the survivor would land one short per repeated
    # finding, and the shortfall would be invisible in any single row.
    sightings_from_rows = sum(len(repeats) + 1 for repeats in folded.values())
    singletons = [f for f in surviving if f not in folded]
    assert sightings_from_rows + len(singletons) == len(stream), (
        f"occurrence counts sum to {sightings_from_rows} sightings over repeated findings plus "
        f"{len(singletons)} seen once, against {len(stream)} inputs — the count does not include "
        "the surviving alert, so every published total is one short per finding"
    )
    assert len(singletons) + len(folded) == retained, "every retained alert either repeated or did not; there is no third state"


def test_folding_then_correlating_still_accounts_for_every_input() -> None:
    """The two reductions compose without losing anything between them.

    Fusion folds first and correlates second, so the correlation figure is
    computed over *surviving* alerts. The risk this pins is double-counting:
    a repeat that folded must not also appear as a grouped member, or the
    combined accounting would exceed the denominator and the two published
    percentages could be added together by a reader without noticing.
    """
    stream = build_repeat_stream()
    surviving, folded = fold_repeats(stream)
    folded_count = sum(len(repeats) for repeats in folded.values())

    members = _group_members(list(surviving.values()))
    grouped_members = sum(len(group) for group in members.values())

    assert grouped_members == len(surviving), "correlation saw a different number of alerts than folding retained"

    # The four buckets of the full-cohort rule, summing to the denominator.
    retained_alone = sum(1 for group in members.values() if len(group) == 1)
    attached_to_group = sum(len(group) for group in members.values() if len(group) > 1)
    pending_or_failed = 0  # deterministic cohort: nothing is in flight

    total = retained_alone + attached_to_group + folded_count + pending_or_failed
    assert total == len(stream), (
        f"retained alone {retained_alone} + attached to a group {attached_to_group} + "
        f"folded {folded_count} + pending {pending_or_failed} = {total}, "
        f"against {len(stream)} inputs"
    )

    print(
        f"\n[eval] full-cohort accounting: {len(stream)} inputs = "
        f"{retained_alone} retained alone + {attached_to_group} attached to a group + "
        f"{folded_count} folded occurrences + {pending_or_failed} pending/failed"
    )


# ── Phase 3.3, second half: cross-vendor root-cause collapse ──────────────
#
# A third reduction, and a third labelled row. It folds nothing the other
# two fold: correlation groups *related* alerts, repeat folding folds *the
# same finding arriving again*, and this folds *different vendors reporting
# one root cause*. Four products raising their own finding about one public
# bucket produce four different fingerprints, so every dedup layer correctly
# leaves all four standing — and the analyst closes the same
# misconfiguration four times.
#
# Measured on the fixed cohort below, driving the real
# `alert_sink.root_cause_key`:
#
#   1000 inputs -> 832 records, 168 folded, of which 51 findings carry more
#   than one vendor — the number that makes a finding worth having, because
#   one product raising a finding is a finding and four agreeing is a
#   different claim
#
# Published separately from the other two and never summed with them: the
# three reduce different things over overlapping inputs, and a reader adding
# them would count some alerts three times. That is the defect the retracted
# 75.3 % figure carried — a headline whose denominator nobody could name.
CROSS_VENDOR_REDUCTION_PCT = 16.8

#: The products that each raise their own finding about one cloud resource.
#: Real connector type ids, because the vendor count is the number that
#: makes the finding worth having and a fake vendor would inflate it.
_CLOUD_VENDORS = ("aws_security_hub", "azure_defender_cloud", "wiz", "aws_guardduty")


def build_cross_vendor_stream(size: int = STREAM_SIZE) -> list[tuple[datetime, RawAlert]]:
    """Cloud-posture traffic in which several products report one root cause.

    Roughly a fifth of the stream is other vendors re-reporting a
    misconfiguration a first vendor already raised — each with its own
    title, its own severity and its own fingerprint, which is why none of
    the existing dedup layers touches them.
    """
    start = datetime(2026, 9, 22, 8, 0, tzinfo=UTC)
    stream: list[tuple[datetime, RawAlert]] = []
    for n in range(size):
        offset = timedelta(minutes=_seeded(n, "rc-time", 1440))
        if _seeded(n, "rc-shared", 100) < 24:
            # One of 60 misconfigured resources, reported by one of four
            # products. Same resource, same technique, same principal;
            # different vendor, title and severity, so the fingerprints
            # differ and only the root-cause key joins them.
            which = _seeded(n, "rc-which", 60)
            vendor = _CLOUD_VENDORS[_seeded(n, "rc-vendor", len(_CLOUD_VENDORS))]
            alert = RawAlert(
                tenant_id=TENANT,
                source=vendor,
                title=f"{vendor}: public access on storage-{which:03d}",
                hostname=f"storage-{which:03d}",
                username=f"deployer-{which % 7:02d}",
                mitre_techniques=["T1530"],
                severity=AlertSeverity.HIGH if vendor == "aws_guardduty" else AlertSeverity.MEDIUM,
                connector_type=vendor,
            )
        else:
            alert = RawAlert(
                tenant_id=TENANT,
                source="synthetic",
                title=f"unrelated finding {n}",
                hostname=f"ws-{_seeded(n, 'rc-host', 400):03d}",
                username=f"user-{_seeded(n, 'rc-user', 200):03d}",
                mitre_techniques=[f"T{1000 + _seeded(n, 'rc-tech', 90):04d}"],
                severity=AlertSeverity.MEDIUM,
                connector_type="synthetic",
            )
        stream.append((start + offset, alert))
    return stream


def collapse_by_root_cause(
    stream: list[tuple[datetime, RawAlert]],
) -> tuple[dict[tuple[str, str, str], list[RawAlert]], list[RawAlert]]:
    """Split a stream into root-cause findings and the alerts with no key.

    Drives the real `root_cause_key` rather than a copy of it: a measurement
    that re-implemented the derivation would be a producer compared against
    itself, which this repository has shipped before.
    """
    findings: dict[tuple[str, str, str], list[RawAlert]] = {}
    unkeyed: list[RawAlert] = []
    for _, alert in sorted(stream, key=lambda pair: pair[0]):
        key = root_cause_key(alert)
        if key is None:
            unkeyed.append(alert)
            continue
        findings.setdefault(key, []).append(alert)
    return findings, unkeyed


def test_cross_vendor_collapse_is_its_own_labelled_figure() -> None:
    """A third reduction, published beside the other two and never summed."""
    stream = build_cross_vendor_stream()
    findings, unkeyed = collapse_by_root_cause(stream)

    records = len(findings) + len(unkeyed)
    reduction = 1 - (records / len(stream))
    multi_vendor = {k: v for k, v in findings.items() if len({a.connector_type for a in v}) > 1}

    print(
        f"\n[eval] cross-vendor root cause (real root_cause_key): {len(stream)} inputs -> "
        f"{records} records = {reduction:.1%}; {len(multi_vendor)} finding(s) carry more than one vendor"
    )

    assert round(reduction * 100, 1) == CROSS_VENDOR_REDUCTION_PCT, (
        f"cross-vendor reduction is now {reduction:.1%} but CROSS_VENDOR_REDUCTION_PCT says "
        f"{CROSS_VENDOR_REDUCTION_PCT} %, which is what the published surfaces print."
    )
    assert multi_vendor, "no finding collapsed more than one vendor; this cohort does not exercise the feature"
    assert len({CROSS_VENDOR_REDUCTION_PCT, PUBLISHED_REDUCTION_PCT, REPEAT_STREAM_DEDUP_PCT}) == 3, (
        "two of the three published reductions have become the same number; they measure different things and must stay separately labelled"
    )


def test_an_incomplete_key_never_collapses_anything() -> None:
    """A NULL does not match another NULL.

    "We do not know the principal" is not evidence that two findings share
    one, and treating absence as agreement is how a conservative key becomes
    a wide one.
    """
    missing_user = RawAlert(tenant_id=TENANT, source="a", title="x", hostname="h", mitre_techniques=["T1530"])
    missing_tech = RawAlert(tenant_id=TENANT, source="a", title="x", hostname="h", username="u")
    missing_host = RawAlert(tenant_id=TENANT, source="a", title="x", username="u", mitre_techniques=["T1530"])
    for alert in (missing_user, missing_tech, missing_host):
        assert root_cause_key(alert) is None


def test_the_same_resource_under_a_different_technique_is_a_different_finding() -> None:
    """Resource alone over-collapses — the lesson v21 paid for."""
    exfil = RawAlert(tenant_id=TENANT, source="a", title="x", hostname="h", username="u", mitre_techniques=["T1530"])
    recon = RawAlert(tenant_id=TENANT, source="b", title="y", hostname="h", username="u", mitre_techniques=["T1087"])
    assert root_cause_key(exfil) != root_cause_key(recon)


def test_every_input_is_accounted_for_across_all_three_reductions() -> None:
    """The balance invariant, extended to the third fold.

    Nothing may vanish into a numerator. An alert is either the first report
    of its root cause (retained), a later vendor's report of one already
    recorded (folded, and still resolvable to the finding), or carries no
    root-cause key at all (retained individually).
    """
    stream = build_cross_vendor_stream()
    findings, unkeyed = collapse_by_root_cause(stream)

    retained = len(findings) + len(unkeyed)
    folded = sum(len(members) - 1 for members in findings.values())

    assert retained + folded == len(stream), f"{retained} retained + {folded} folded = {retained + folded}, against {len(stream)} inputs"

    # Resolvability, not only balance: every folded report must still point
    # at the finding that absorbed it. A count that balances while pointing
    # nowhere cannot be audited.
    for key, members in findings.items():
        for member in members:
            assert root_cause_key(member) == key

    print(
        f"[eval] cross-vendor accounting: {len(stream)} inputs = {len(findings)} findings + "
        f"{len(unkeyed)} unkeyed + {folded} folded into a finding"
    )


def test_the_stream_is_reproducible() -> None:
    """A measurement that moves between runs is not a measurement."""
    first = group_by_real_key(build_stream())
    second = group_by_real_key(build_stream())
    assert first == second
    assert fold_repeats(build_repeat_stream())[0].keys() == fold_repeats(build_repeat_stream())[0].keys()


def test_a_wider_window_reduces_more() -> None:
    """Sanity on the window's direction. If this inverts, the grouping is
    not doing what the name says."""
    stream = build_stream()
    narrow = group_by_real_key(stream, timedelta(minutes=5))
    wide = group_by_real_key(stream, timedelta(hours=24))
    assert wide <= narrow
