"""Attack-chain auto-grouping at fuse time (Phase C4).

Correlation groups alerts into incidents by shared entity, and the API can
compute an attack chain *per case* on demand. But nothing formed or extended a
chain **at fuse time**, so related alerts didn't auto-collapse into one ordered
incident narrative as they arrived — the analyst saw N separate alerts instead
of "stage 3 of an intrusion on host X that began with initial-access 20m ago".

This grouper closes that. For each entity an alert touches (host / user / ip),
it looks up (or mints) a stable ``chain_id`` in Redis with a rolling TTL, so a
follow-on alert on the same entity within the window joins the same chain. It
appends a compact member record, orders members by MITRE kill-chain stage, and
returns a :class:`ChainAssignment` the fusion engine attaches to the fused
alert (``enrichments["attack_chain"]``) — giving the UI and the triage agent an
at-a-glance "this is step K of an unfolding attack" view.

Fail-soft: a Redis miss/outage degrades to "no chain assignment", never an
error into the fusion pipeline.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any

import structlog

logger = structlog.get_logger()

# MITRE ATT&CK tactic → kill-chain ordinal. Lower = earlier in an intrusion.
# Names are matched case-insensitively against both dashed and spaced forms.
_TACTIC_ORDER = {
    "reconnaissance": 0,
    "resource-development": 1,
    "initial-access": 2,
    "execution": 3,
    "persistence": 4,
    "privilege-escalation": 5,
    "defense-evasion": 6,
    "credential-access": 7,
    "discovery": 8,
    "lateral-movement": 9,
    "collection": 10,
    "command-and-control": 11,
    "exfiltration": 12,
    "impact": 13,
}
_MAX_MEMBERS = 50

# ── Story links (wave 2, Phase 3.2) ───────────────────────────────────────
#
# Until now a chain was joined on a shared host, user or source-IP *string*,
# first match wins in that fixed order. A string match is a string match: a
# NAT egress address or a shared jump host welds two unrelated intrusions
# into one story, and nothing on the assignment said which of the three had
# done it.
#
# Links are now typed and carry a strength, and the strength decides what a
# link is allowed to do. Three tiers:
#
#   STRONG    one authenticated context. A session id, or the human resolved
#             behind an assumed-role chain. Fusion already writes both onto
#             the alert row (migration 102: `session_id`, `session_key_kind`,
#             `originating_human`), so these are available today and do not
#             wait on Phase 3.1's cross-source identity resolution.
#   SPECIFIC  one artefact that is not shared by accident — a file hash or a
#             domain. Weaker than a session, far stronger than an IP.
#   WEAK      a bare entity string: host, user, source IP.
#
# The rule that keeps v21's narrowing intact is on WEAK links: **a weak link
# may not join alerts from different detection rules.** v21 deliberately
# narrowed grouping so that alerts carrying no tactic group per rule rather
# than collapsing together, taking the detection-shaped reduction from 42.6 %
# to 24.5 % and cross-rule groups from 36 to 0 — "the reduction went DOWN and
# that is the honest direction". A story built on string matches would undo
# exactly that, one layer up, and the 24.5 % figure would still read as 24.5 %
# because it measures the correlation key rather than the story.
#
# A STRONG or SPECIFIC link may cross rules, because sharing a session or a
# file hash is evidence rather than coincidence — and when one does, the
# assignment records which link did it, so every cross-rule story can be
# listed rather than tolerated.
LINK_STRONG = "strong"
LINK_SPECIFIC = "specific"
LINK_WEAK = "weak"

#: Highest strength first: the chain a strong link points at wins over one a
#: weak link points at, rather than whichever entity happened to be checked
#: first.
_STRENGTH_ORDER = (LINK_STRONG, LINK_SPECIFIC, LINK_WEAK)

_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

#: How many distinct kill-chain stages a story needs before its severity is
#: raised above its highest member. Three is the point at which the sequence
#: is the finding: one alert is an alert, two can be one action seen twice,
#: three stages on one authenticated context is a narrative.
_ESCALATION_MIN_STAGES = 3


def _severity_index(value: str) -> int:
    try:
        return _SEVERITY_ORDER.index(str(value).strip().lower())
    except ValueError:
        return -1


def _stage_ordinal(tactics: list[str]) -> int:
    best = -1
    for t in tactics or []:
        key = str(t).strip().lower().replace(" ", "-")
        if key in _TACTIC_ORDER and _TACTIC_ORDER[key] > best:
            best = _TACTIC_ORDER[key]
    return best


def _stage_name(ordinal: int) -> str:
    if ordinal < 0:
        return "unknown"
    for name, ord_ in _TACTIC_ORDER.items():
        if ord_ == ordinal:
            return name
    return "unknown"


@dataclass
class ChainMember:
    alert_id: str
    title: str
    severity: str
    stage_ordinal: int
    stage: str
    ts: float
    #: The detection rule behind this alert, when there is one. Carried so
    #: the grouper can tell a cross-rule join from a same-rule one without
    #: re-reading the alert, which it no longer has.
    rule_id: str = ""
    #: ``automated`` | ``interactive`` | ``unknown``. See `_actor_mode`.
    actor_mode: str = "unknown"
    #: Strength of the link that put this member in the story. Recorded so a
    #: later weak link can be refused against a story that was established on
    #: strong evidence — see `_anchored_on_strong_evidence`.
    link_strength: str = LINK_WEAK


@dataclass
class StoryLink:
    """One reason two alerts belong in the same story."""

    kind: str
    value: str
    strength: str

    def label(self) -> str:
        return f"{self.kind}:{self.value}"


@dataclass
class ChainAssignment:
    chain_id: str
    is_new_chain: bool
    position: int  # 1-based position of this alert in the chain
    stage: str  # this alert's kill-chain stage
    entity: str  # the entity the chain is keyed on ("host:WIN-DC01")
    prior_alert_ids: list[str]
    member_count: int
    #: Which link joined this alert to the story, and how strong it is. A
    #: story whose only joins are `weak` is a string coincidence until
    #: something better arrives, and the console can say so.
    joined_by_kind: str = ""
    joined_by_strength: str = ""
    #: The story's own severity, computed from its members and the shape of
    #: the sequence — not this alert's severity.
    story_severity: str = ""
    #: Why the story's severity exceeds its highest member, when it does.
    #: Empty when it does not. This is the ledger reason the plan requires
    #: for any escalation: a member that is benign alone may be escalated by
    #: its story, and something has to say which links did it.
    escalation_reason: str = ""
    #: Distinct kill-chain stages the story spans.
    stage_span: int = 0
    #: ``automated`` | ``interactive`` | ``unknown`` for this alert's actor.
    actor_mode: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _actor_mode(alert: Any) -> str:
    """Whether this action was automated or interactive — or unknown.

    The plan sources this from Phase 1.4's cadence classes (a token or app
    classified as scheduled, scripted or interactive). **1.4 is Lane A's and
    has not landed**, so there is no cadence on an alert today and the honest
    answer is `unknown` on every one of them.

    `unknown` rather than a guess, and rather than a default of
    "interactive". Two tempting inferences were considered and rejected:
    a session whose `session_key_kind` is `vendor_credential` with no
    `originating_human` is an assumed role with nobody resolved behind it,
    which is *unresolved*, not *automated*; and a username matching a
    service-account shape is a naming convention, not evidence. Marking a
    human's action "automated" on either basis would put the wrong word on a
    timeline an analyst uses to decide whether somebody is at a keyboard
    right now.

    When 1.4 lands it sets `cadence` on the alert and this starts answering.
    The console renders `unknown` as "not classified", never as blank.
    """
    cadence = getattr(alert, "cadence", None)
    if not cadence:
        return "unknown"
    normalised = str(cadence).strip().lower()
    if normalised in {"scheduled", "scripted", "automated"}:
        return "automated"
    if normalised == "interactive":
        return "interactive"
    return "unknown"


def _links(alert: Any) -> list[StoryLink]:
    """Every reason this alert could belong to a story, strongest first.

    Order matters: `assign` adopts the chain behind the first link that
    already has one, so a session link wins over a host-string link rather
    than whichever happened to be listed first.
    """
    out: list[StoryLink] = []

    # Strong — one authenticated context. Both are written onto the alert row
    # by fusion today (migration 102), which is why 3.2's session and
    # role-chain links do not wait on 3.1's cross-source identity resolution.
    session_id = getattr(alert, "session_id", None)
    if session_id:
        out.append(StoryLink("session", str(session_id), LINK_STRONG))
    human = getattr(alert, "originating_human", None)
    if human:
        out.append(StoryLink("human", str(human), LINK_STRONG))

    # Specific — an artefact two unrelated intrusions do not share by
    # accident, unlike an egress IP.
    file_hash = getattr(alert, "file_hash", None)
    if file_hash:
        out.append(StoryLink("hash", str(file_hash), LINK_SPECIFIC))
    domain = getattr(alert, "domain", None)
    if domain:
        out.append(StoryLink("domain", str(domain), LINK_SPECIFIC))

    # Weak — bare entity strings. Kept, because most alerts carry nothing
    # else, and visibly weaker.
    if getattr(alert, "hostname", None):
        out.append(StoryLink("host", str(alert.hostname), LINK_WEAK))
    if getattr(alert, "username", None):
        out.append(StoryLink("user", str(alert.username), LINK_WEAK))
    if getattr(alert, "src_ip", None):
        out.append(StoryLink("ip", str(alert.src_ip), LINK_WEAK))

    out.sort(key=lambda link: _STRENGTH_ORDER.index(link.strength))
    return out


def _entities(alert: Any) -> list[tuple[str, str]]:
    """Back-compatible view of the weak entity links.

    Kept because `test_attack_chain_grouper.py` and the fusion engine have
    both imported it since Phase C4. It is now derived from `_links` so the
    two cannot disagree about what an entity is.
    """
    return [(link.kind, link.value) for link in _links(alert) if link.strength == LINK_WEAK]


def story_severity(members: list[ChainMember]) -> tuple[str, str, int]:
    """The story's own severity, the reason it was raised, and its stage span.

    A story is more than its loudest member when the *sequence* is the
    finding: three or more distinct kill-chain stages on one story is a
    narrative rather than a pile, and the plan requires that a member benign
    on its own may be escalated by the story it sits in.

    Raised by exactly one tier, never more, and never past `critical`. The
    reason is returned rather than logged so it can travel onto the
    assignment and into the ledger — an escalation whose cause is in a log
    line is an escalation an analyst cannot audit from the alert.
    """
    if not members:
        return "", "", 0

    highest = max(_severity_index(m.severity) for m in members)
    stages = {m.stage_ordinal for m in members if m.stage_ordinal >= 0}
    span = len(stages)

    if highest < 0:
        return "", "", span

    base = _SEVERITY_ORDER[highest]
    if span < _ESCALATION_MIN_STAGES or highest >= len(_SEVERITY_ORDER) - 1:
        return base, "", span

    raised = _SEVERITY_ORDER[highest + 1]
    ordered_stages = ", ".join(_stage_name(s) for s in sorted(stages))
    reason = (
        f"story spans {span} kill-chain stages ({ordered_stages}) across {len(members)} alerts; "
        f"raised from {base} to {raised} because the sequence is the finding"
    )
    return raised, reason, span


class AttackChainGrouper:
    """Redis-backed fuse-time chain former/extender. Fail-soft on every op."""

    def __init__(self, redis_client: Any, *, window_seconds: int = 3600) -> None:
        self._redis = redis_client
        self._window = window_seconds

    def _chain_key(self, tenant_id: str, entity_type: str, entity_id: str) -> str:
        return f"chain:idx:{tenant_id}:{entity_type.lower()}:{entity_id.lower()}"

    def _members_key(self, chain_id: str) -> str:
        return f"chain:members:{chain_id}"

    async def assign(self, alert: Any) -> ChainAssignment | None:
        """Form or extend the attack story for ``alert``.

        Returns the assignment, or ``None`` when the alert carries no link at
        all or Redis is down.

        Joining is by link strength, strongest first (wave 2, Phase 3.2): the
        chain a session link points at wins over the chain a host-string link
        points at, rather than whichever entity happened to be checked first.
        A **weak** link may not join alerts from different detection rules —
        see the module's link-tier comment; that is what keeps v21's
        narrowing from being undone one layer up.
        """
        links = _links(alert)
        if not links:
            return None
        tenant_id = str(getattr(alert, "tenant_id", ""))
        rule_id = str(getattr(alert, "rule_id", "") or "")
        try:
            chain_id: str | None = None
            joined_by: StoryLink | None = None
            for link in links:
                existing = await self._redis.get(self._chain_key(tenant_id, link.kind, link.value))
                if not existing:
                    continue
                candidate = existing.decode() if isinstance(existing, bytes) else str(existing)
                if link.strength == LINK_WEAK:
                    refusal = await self._weak_link_refusal(candidate, rule_id)
                    if refusal:
                        # A shared hostname or egress IP is not evidence that
                        # two things are one intrusion. Skipping rather than
                        # joining is what holds the detection-shaped cohort at
                        # zero cross-rule stories; a stronger link later in
                        # this alert's own list may still join it.
                        logger.debug(
                            "attack_chain.weak_link_refused",
                            link=link.label(),
                            rule_id=rule_id,
                            reason=refusal,
                        )
                        continue
                chain_id = candidate
                joined_by = link
                break

            is_new = chain_id is None
            if chain_id is None or joined_by is None:
                # A new story is keyed on this alert's strongest link, which
                # is the one a later alert is most likely to share for a real
                # reason. Narrowed from `chain_id is None` so the type is a
                # `StoryLink` from here down rather than an Optional the
                # reader has to re-prove at each use.
                chain_id = chain_id or str(uuid.uuid4())
                joined_by = links[0]

            # Point every link of this alert at the chain (rolling TTL) so a
            # later alert sharing any of them joins the same story.
            for link in links:
                await self._redis.set(self._chain_key(tenant_id, link.kind, link.value), chain_id, ex=self._window)

            stage_ord = _stage_ordinal(list(getattr(alert, "mitre_tactics", []) or []))
            member = ChainMember(
                alert_id=str(getattr(alert, "id", "")),
                title=str(getattr(alert, "title", ""))[:200],
                severity=str(getattr(getattr(alert, "severity", None), "value", getattr(alert, "severity", ""))),
                stage_ordinal=stage_ord,
                stage=_stage_name(stage_ord),
                ts=time.time(),
                rule_id=rule_id,
                actor_mode=_actor_mode(alert),
                link_strength=joined_by.strength,
            )

            members = await self._load_members(chain_id)
            prior_ids = [m.alert_id for m in members]
            members.append(member)
            members = members[-_MAX_MEMBERS:]
            await self._save_members(chain_id, members)

            # Position = kill-chain-ordered rank of this alert among members.
            ordered = sorted(members, key=lambda m: (m.stage_ordinal, m.ts))
            position = next((i + 1 for i, m in enumerate(ordered) if m.alert_id == member.alert_id), len(members))

            severity, escalation_reason, stage_span = story_severity(members)

            return ChainAssignment(
                chain_id=chain_id,
                is_new_chain=is_new,
                position=position,
                stage=member.stage,
                entity=joined_by.label(),
                prior_alert_ids=prior_ids,
                member_count=len(members),
                joined_by_kind=joined_by.kind,
                joined_by_strength=joined_by.strength,
                story_severity=severity,
                escalation_reason=escalation_reason,
                stage_span=stage_span,
                actor_mode=member.actor_mode,
            )
        except Exception as exc:  # noqa: BLE001 — chaining is additive; never break fusion
            logger.warning("attack_chain.assign_failed", error=str(exc))
            return None

    async def _weak_link_refusal(self, chain_id: str, rule_id: str) -> str:
        """Why a weak link may not join this story, or "" when it may.

        Two refusals, and the second was found by the measurement rather than
        reasoned out in advance — which is the reason it is worth stating.

        **Cross-rule.** Joining would put two detection rules in one story. An
        alert with no ``rule_id`` is not a detection-engine alert and is not
        held to this one: the cohort v21's narrowing governs is the one where
        every alert carries a rule and no tactic.

        **Anchored on strong evidence.** The story was established by a
        session, a resolved human, a file hash or a domain, and this alert
        shares only a bare entity string with it. The first cut of this
        grouper had only the cross-rule arm, and
        `test_story_recall_and_purity_on_the_labelled_scenarios` immediately
        measured 75 % purity: a routine antivirus quarantine sharing the
        tenant's NAT egress address joined a phishing-to-cloud-exfiltration
        story, because the scenario's alerts carry no ``rule_id`` and the
        cross-rule arm therefore had nothing to compare. A story about one
        authenticated session does not admit a new member on the strength of
        an address a thousand hosts share.

        The asymmetry is deliberate: a strong link may always join, including
        into a story so far held together by weak ones, because arriving
        evidence should be able to connect a pile that string matching had
        already assembled.
        """
        members = await self._load_members(chain_id)
        if rule_id and any(m.rule_id and m.rule_id != rule_id for m in members):
            return "cross_rule"
        if any(m.link_strength in (LINK_STRONG, LINK_SPECIFIC) for m in members):
            return "story_anchored_on_strong_evidence"
        return ""

    async def _load_members(self, chain_id: str) -> list[ChainMember]:
        raw = await self._redis.get(self._members_key(chain_id))
        if not raw:
            return []
        try:
            data = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
            return [ChainMember(**m) for m in data]
        except (ValueError, TypeError):
            return []

    async def _save_members(self, chain_id: str, members: list[ChainMember]) -> None:
        payload = json.dumps([asdict(m) for m in members])
        await self._redis.set(self._members_key(chain_id), payload.encode("utf-8"), ex=self._window)
