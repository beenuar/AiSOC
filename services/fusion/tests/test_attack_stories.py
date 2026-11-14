"""Attack stories: measured on recall, purity, and what they refuse to merge.

Wave 2, Phase 3.2. Built on `attack_chain_grouper` rather than beside it.

The gap
-------
The grouper chained alerts that shared a **host, user or source-IP string**,
first match wins in a fixed order, and nothing on the result said which of
the three had done it. Three consequences, all reproduced below:

* a NAT egress address or a shared jump host welds two unrelated intrusions
  into one story, and an analyst reading it cannot tell;
* an alert carrying a *session id* — which fusion has written onto the alert
  row since migration 102, alongside `originating_human` for the human
  behind an assumed-role chain — got no more weight than one carrying a
  hostname, so the strongest evidence available was unused;
* no severity was computed for the story at all. `ChainMember` carried a
  per-member severity string and nothing aggregated it, so the plan's "a
  member that is benign alone may be escalated by its story" had nowhere to
  happen and no reason to record.

What is measured here
---------------------
Recall and purity over three labelled multi-stage scenarios, which are the
ones the plan names: phishing then session reuse then cloud access, token
theft then repository clone, and a departing employee then bulk download.
Recall is the share of a scenario's alerts that land in one story; purity is
whether any alert from a *different* scenario landed in it.

And the constraint that matters most: **v21's narrowing must hold.** v21
took the detection-shaped cohort from 42.6 % reduction with 36 cross-rule
groups to 24.5 % with zero, on the reasoning that the difference was
unrelated alerts being counted as grouped. A story layer built on string
matches would undo that without moving the published figure, because the
figure measures the correlation key and not the story. So a weak link may
not join alerts from different rules, and the test below lists every
cross-rule story with the link that justified it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import pytest
from app.services.attack_chain_grouper import (
    LINK_SPECIFIC,
    LINK_STRONG,
    LINK_WEAK,
    AttackChainGrouper,
    ChainMember,
    _links,
    story_severity,
)

TENANT = "11111111-1111-1111-1111-111111111111"


class _FakeRedis:
    """Enough Redis for the grouper: get, set with a TTL we do not expire."""

    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    async def get(self, key: str) -> bytes | None:
        return self.store.get(key)

    async def set(self, key: str, value: Any, ex: int | None = None) -> None:  # noqa: ARG002
        self.store[key] = value if isinstance(value, bytes) else str(value).encode()


@dataclass
class _Alert:
    """An alert with the fields the grouper reads, all optional."""

    title: str
    severity: str = "medium"
    mitre_tactics: tuple[str, ...] = ()
    hostname: str | None = None
    username: str | None = None
    src_ip: str | None = None
    session_id: str | None = None
    originating_human: str | None = None
    file_hash: str | None = None
    domain: str | None = None
    rule_id: str = ""
    cadence: str | None = None
    tenant_id: str = TENANT

    def __post_init__(self) -> None:
        self.id = str(uuid.uuid4())
        self.mitre_tactics = list(self.mitre_tactics)  # type: ignore[assignment]


# ── link typing ───────────────────────────────────────────────────────────


def test_a_session_link_outranks_a_host_string() -> None:
    """Strongest first, so `assign` adopts the right chain rather than the first."""
    alert = _Alert("x", hostname="WIN-DC01", session_id="sess-1", src_ip="203.0.113.9")
    kinds = [link.kind for link in _links(alert)]
    assert kinds[0] == "session"
    assert kinds.index("session") < kinds.index("host") < kinds.index("ip")


def test_every_link_carries_its_strength() -> None:
    alert = _Alert(
        "x",
        session_id="s",
        originating_human="alice@example.com",
        file_hash="ab" * 32,
        domain="evil.example",
        hostname="h",
        username="u",
        src_ip="203.0.113.9",
    )
    by_kind = {link.kind: link.strength for link in _links(alert)}
    assert by_kind["session"] == LINK_STRONG
    assert by_kind["human"] == LINK_STRONG
    assert by_kind["hash"] == LINK_SPECIFIC
    assert by_kind["domain"] == LINK_SPECIFIC
    assert by_kind["host"] == by_kind["user"] == by_kind["ip"] == LINK_WEAK


def test_an_alert_with_nothing_to_link_on_forms_no_story() -> None:
    assert _links(_Alert("x")) == []


# ── the v21 constraint ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_shared_host_does_not_merge_two_detection_rules() -> None:
    """The narrowing v21 bought, held one layer up.

    Two detections firing on one jump host are two detections. Before this,
    the second joined the first's chain on the hostname string, which is
    precisely the unrelated-collapse v21 removed from the correlation key.
    """
    grouper = AttackChainGrouper(_FakeRedis())

    first = await grouper.assign(_Alert("port scan", hostname="jump-01", rule_id="det-rule-01"))
    second = await grouper.assign(_Alert("odd dns", hostname="jump-01", rule_id="det-rule-07"))

    assert first is not None and second is not None
    assert second.chain_id != first.chain_id, (
        "a shared hostname merged two different detection rules into one story, "
        "undoing v21's narrowing above the correlation key where the published "
        "24.5 % figure cannot see it"
    )
    assert second.is_new_chain is True


@pytest.mark.asyncio
async def test_the_same_rule_on_a_shared_host_still_groups() -> None:
    """The guard is about *different* rules. One rule repeating is one story."""
    grouper = AttackChainGrouper(_FakeRedis())
    first = await grouper.assign(_Alert("port scan", hostname="jump-01", rule_id="det-rule-01"))
    second = await grouper.assign(_Alert("port scan", hostname="jump-01", rule_id="det-rule-01"))
    assert first is not None and second is not None
    assert second.chain_id == first.chain_id


@pytest.mark.asyncio
async def test_a_session_link_may_cross_rules_and_says_so() -> None:
    """Sharing a session is evidence, not coincidence — and it is listed.

    This is the plan's "unless a story link justifies them, and each such
    link is listed": the assignment records the kind and strength of the
    link that joined it, so every cross-rule story can be enumerated.
    """
    grouper = AttackChainGrouper(_FakeRedis())
    first = await grouper.assign(
        _Alert("suspicious sign-in", session_id="sess-77", rule_id="det-rule-01", mitre_tactics=("initial-access",))
    )
    second = await grouper.assign(
        _Alert("role assumed", session_id="sess-77", rule_id="det-rule-09", mitre_tactics=("privilege-escalation",))
    )

    assert first is not None and second is not None
    assert second.chain_id == first.chain_id
    assert second.joined_by_kind == "session"
    assert second.joined_by_strength == LINK_STRONG


@pytest.mark.asyncio
async def test_a_bare_ip_does_not_join_a_story_anchored_on_a_session() -> None:
    """Found by measurement, not by reasoning, which is why it is pinned here.

    The first cut of this grouper refused a weak link only when it would
    cross detection rules. `test_story_recall_and_purity_on_the_labelled_scenarios`
    then measured **75 % purity**: a routine antivirus quarantine sharing the
    tenant's NAT egress address joined a phishing-to-cloud-exfiltration
    story, because the scenario's alerts carry no `rule_id` and the
    cross-rule arm had nothing to compare.

    A story about one authenticated session does not admit a new member on
    the strength of an address a thousand hosts share.
    """
    grouper = AttackChainGrouper(_FakeRedis())
    anchored = await grouper.assign(_Alert("token replayed", session_id="sess-1", src_ip="203.0.113.5", mitre_tactics=("defense-evasion",)))
    noise = await grouper.assign(_Alert("antivirus quarantine", src_ip="203.0.113.5", hostname="ws-900"))

    assert anchored is not None and noise is not None
    assert noise.chain_id != anchored.chain_id
    assert noise.is_new_chain is True


@pytest.mark.asyncio
async def test_a_strong_link_may_still_join_a_story_held_together_by_strings() -> None:
    """The asymmetry is deliberate, and the direction matters.

    Arriving evidence should be able to connect a pile that string matching
    had already assembled — refusing that would make the strength tiers a
    rule about arrival order rather than about evidence.
    """
    grouper = AttackChainGrouper(_FakeRedis())
    weak_first = await grouper.assign(_Alert("odd process", hostname="ws-01"))
    strong_later = await grouper.assign(_Alert("session opened", hostname="ws-01", session_id="sess-5"))

    assert weak_first is not None and strong_later is not None
    assert strong_later.chain_id == weak_first.chain_id
    assert strong_later.joined_by_strength == LINK_WEAK, (
        "the host string is what was already pointing at this story; the session is new and points at nothing yet"
    )


@pytest.mark.asyncio
async def test_an_alert_with_no_rule_id_is_not_held_to_the_rule_guard() -> None:
    """The cohort v21's narrowing governs is detection alerts.

    A connector alert carries no `rule_id`; holding it to a rule comparison
    would stop vendor alerts grouping at all.
    """
    grouper = AttackChainGrouper(_FakeRedis())
    first = await grouper.assign(_Alert("guardduty finding", hostname="i-01"))
    second = await grouper.assign(_Alert("defender finding", hostname="i-01"))
    assert first is not None and second is not None
    assert second.chain_id == first.chain_id


# ── story severity and its recorded reason ────────────────────────────────


def _member(severity: str, stage_ordinal: int) -> ChainMember:
    return ChainMember(
        alert_id=str(uuid.uuid4()),
        title="t",
        severity=severity,
        stage_ordinal=stage_ordinal,
        stage="s",
        ts=0.0,
    )


def test_a_one_stage_story_is_no_louder_than_its_loudest_member() -> None:
    severity, reason, span = story_severity([_member("low", 2), _member("medium", 2)])
    assert severity == "medium"
    assert reason == ""
    assert span == 1


def test_three_stages_escalate_by_exactly_one_tier_with_a_reason() -> None:
    """The plan's 'a member benign alone may be escalated by its story'."""
    members = [_member("low", 2), _member("low", 5), _member("low", 12)]
    severity, reason, span = story_severity(members)
    assert span == 3
    assert severity == "medium", "a three-stage story stayed at its members' severity"
    assert "3 kill-chain stages" in reason
    assert "initial-access" in reason and "exfiltration" in reason
    assert "raised from low to medium" in reason


def test_escalation_never_passes_critical() -> None:
    members = [_member("critical", 2), _member("critical", 5), _member("critical", 12)]
    severity, reason, _ = story_severity(members)
    assert severity == "critical"
    assert reason == "", "a critical story reported an escalation it did not make"


def test_members_with_no_stage_do_not_count_toward_the_span() -> None:
    """`stage_ordinal` is -1 when an alert carries no tactic.

    Detection-engine alerts carry none at all, so counting -1 as a stage
    would escalate any three of them — the exact over-grouping this layer
    must not reintroduce.
    """
    members = [_member("low", -1), _member("low", -1), _member("low", -1)]
    severity, reason, span = story_severity(members)
    assert span == 0
    assert severity == "low"
    assert reason == ""


@pytest.mark.asyncio
async def test_the_escalation_reason_travels_on_the_assignment() -> None:
    """An escalation whose cause is in a log line cannot be audited from the alert."""
    grouper = AttackChainGrouper(_FakeRedis())
    for tactic in ("initial-access", "privilege-escalation", "exfiltration"):
        assignment = await grouper.assign(_Alert("step", severity="low", session_id="sess-9", mitre_tactics=(tactic,)))
    assert assignment is not None
    assert assignment.story_severity == "medium"
    assert assignment.escalation_reason
    assert assignment.stage_span == 3


# ── automated vs interactive ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_actor_with_no_cadence_is_unknown_not_interactive() -> None:
    """Phase 1.4 supplies cadence and has not landed; `unknown` is the answer.

    Two inferences were considered and rejected: a credential session with no
    resolved human is *unresolved*, not automated; and a service-account-shaped
    username is a naming convention, not evidence. Putting the wrong word on a
    timeline an analyst uses to decide whether somebody is at a keyboard right
    now is worse than saying nothing.
    """
    grouper = AttackChainGrouper(_FakeRedis())
    assignment = await grouper.assign(_Alert("x", session_id="s", username="svc-backup"))
    assert assignment is not None
    assert assignment.actor_mode == "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("cadence", "expected"),
    [("scheduled", "automated"), ("scripted", "automated"), ("interactive", "interactive"), ("weird", "unknown")],
)
async def test_a_cadence_classification_is_carried_onto_the_timeline(cadence: str, expected: str) -> None:
    grouper = AttackChainGrouper(_FakeRedis())
    assignment = await grouper.assign(_Alert("x", session_id="s", cadence=cadence))
    assert assignment is not None
    assert assignment.actor_mode == expected


# ── recall and purity on labelled scenarios ───────────────────────────────

#: The three multi-stage scenarios the plan names. Each is a list of alerts
#: that genuinely belong to one intrusion, authored so that the link that
#: should join them is a real one — a session, the human behind an
#: assumed-role chain, or a file hash — rather than a shared string.
SCENARIOS: dict[str, list[_Alert]] = {
    "phish-then-session-reuse-then-cloud": [
        _Alert(
            "Phishing link clicked",
            severity="medium",
            mitre_tactics=("initial-access",),
            username="alice@example.com",
            session_id="sess-alice-1",
        ),
        _Alert(
            "Session token replayed from a new ASN",
            severity="high",
            mitre_tactics=("defense-evasion",),
            session_id="sess-alice-1",
            src_ip="203.0.113.5",
        ),
        _Alert(
            "AssumeRole into the production account",
            severity="high",
            mitre_tactics=("privilege-escalation",),
            session_id="sess-alice-1",
            originating_human="alice@example.com",
        ),
        _Alert("S3 bulk read by the assumed role", severity="high", mitre_tactics=("exfiltration",), originating_human="alice@example.com"),
    ],
    "token-theft-then-repo-clone": [
        _Alert(
            "Personal access token used from a new ASN",
            severity="medium",
            mitre_tactics=("credential-access",),
            username="bob",
            session_id="sess-bob-1",
        ),
        _Alert("Burst of repository clones", severity="high", mitre_tactics=("collection",), session_id="sess-bob-1"),
        _Alert("Archive download of a private repository", severity="high", mitre_tactics=("exfiltration",), session_id="sess-bob-1"),
    ],
    "departing-employee-bulk-download": [
        _Alert(
            "Drive bulk external sharing",
            severity="medium",
            mitre_tactics=("collection",),
            username="carol@example.com",
            session_id="sess-carol-1",
        ),
        _Alert("Bulk download from Drive", severity="medium", mitre_tactics=("exfiltration",), session_id="sess-carol-1"),
    ],
}

#: Unrelated traffic running at the same time, sharing the egress IP every
#: scenario above also touches. This is the purity test: a NAT address is the
#: single most common way two intrusions get welded into one story.
NOISE = [
    _Alert("Routine antivirus quarantine", severity="low", src_ip="203.0.113.5", hostname="ws-900", rule_id="det-rule-30"),
    _Alert("Password changed", severity="info", src_ip="203.0.113.5", hostname="ws-901", rule_id="det-rule-31"),
]


@pytest.mark.asyncio
async def test_story_recall_and_purity_on_the_labelled_scenarios() -> None:
    """Published measurement: every scenario is one story, with nothing else in it.

    Interleaved rather than run scenario-by-scenario, because a grouper that
    only works on a quiet queue works on no real queue.
    """
    grouper = AttackChainGrouper(_FakeRedis())
    chain_of: dict[str, str] = {}
    label_of: dict[str, str] = {}

    interleaved: list[tuple[str, _Alert]] = []
    longest = max(len(alerts) for alerts in SCENARIOS.values())
    for index in range(longest):
        for label, alerts in SCENARIOS.items():
            if index < len(alerts):
                interleaved.append((label, alerts[index]))
        if index < len(NOISE):
            interleaved.append(("noise", NOISE[index]))

    for label, alert in interleaved:
        assignment = await grouper.assign(alert)
        assert assignment is not None, f"{label}: {alert.title!r} formed no story"
        chain_of[alert.id] = assignment.chain_id
        label_of[alert.id] = label

    # Recall: the share of each scenario's alerts landing in its largest story.
    recalls: dict[str, float] = {}
    for label, alerts in SCENARIOS.items():
        chains = [chain_of[a.id] for a in alerts]
        dominant = max(set(chains), key=chains.count)
        recalls[label] = chains.count(dominant) / len(alerts)
        print(f"\n[eval] story recall {label}: {recalls[label]:.0%} ({chains.count(dominant)}/{len(alerts)})")

    # Purity: no story contains alerts from two different scenarios.
    members_by_chain: dict[str, set[str]] = {}
    for alert_id, chain in chain_of.items():
        members_by_chain.setdefault(chain, set()).add(label_of[alert_id])
    impure = {chain: labels for chain, labels in members_by_chain.items() if len(labels) > 1}
    purity = 1 - (len(impure) / len(members_by_chain))
    print(f"[eval] story purity: {purity:.0%} ({len(members_by_chain) - len(impure)}/{len(members_by_chain)} stories pure)")

    assert all(value == 1.0 for value in recalls.values()), f"story recall below 1.0: {recalls}"
    assert not impure, (
        f"{len(impure)} story/stories mix unrelated scenarios: "
        f"{ {c: sorted(ls) for c, ls in impure.items()} }. A shared egress IP is the "
        "commonest way this happens and is exactly what the weak-link tier exists to stop."
    )


@pytest.mark.asyncio
async def test_every_cross_rule_story_is_listed_with_the_link_that_justified_it() -> None:
    """The plan's explicit requirement, as an enumeration rather than a tolerance.

    Run over a detection-shaped cohort — a rule on every alert, no tactics —
    plus the scenario traffic. Any story spanning more than one rule must name
    a strong or specific link; a weak link may never produce one.
    """
    grouper = AttackChainGrouper(_FakeRedis())
    stories: dict[str, dict[str, Any]] = {}

    cohort: list[_Alert] = [_Alert(f"detection {n}", hostname=f"ws-{n % 6:03d}", rule_id=f"det-rule-{n % 9:02d}") for n in range(60)]
    for alerts in SCENARIOS.values():
        cohort.extend(alerts)

    for alert in cohort:
        assignment = await grouper.assign(alert)
        if assignment is None:
            continue
        entry = stories.setdefault(assignment.chain_id, {"rules": set(), "links": set()})
        if alert.rule_id:
            entry["rules"].add(alert.rule_id)
        entry["links"].add((assignment.joined_by_kind, assignment.joined_by_strength))

    cross_rule = {cid: e for cid, e in stories.items() if len(e["rules"]) > 1}
    print(f"\n[eval] cross-rule stories: {len(cross_rule)} of {len(stories)}")
    for chain_id, entry in cross_rule.items():
        justifying = sorted({k for k, s in entry["links"] if s in (LINK_STRONG, LINK_SPECIFIC)})
        print(f"[eval]   {chain_id[:8]}: rules={sorted(entry['rules'])} justified_by={justifying}")
        assert justifying, (
            f"story {chain_id} spans {sorted(entry['rules'])} on weak links alone "
            f"({sorted(entry['links'])}); v21's narrowing says that is unrelated alerts "
            "being counted as grouped"
        )
