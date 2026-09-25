"""Investigation strategies: named, composable, testable pivot sequences.

Pillar 2. A strategy is what an experienced analyst brings that a prompt does
not: knowing that a suspicious process on an endpoint is worth chasing
*through* the binary's fleet-wide history and the logged-in account's
authentication trail, and that an identity alert is worth chasing through the
account's other sessions rather than the host's process list.

Encoding that as data rather than prose has three consequences that matter:

* **The model is steered, not scripted.** A strategy supplies the plan as
  guidance in the system prompt and leaves tool selection to the model. A
  hard-coded pivot sequence would be a workflow engine wearing an agent's
  clothes, and would break on the first alert that did not match its shape.
* **Depth becomes measurable.** Each strategy declares the pivots it expects,
  so an investigation can be graded on whether it actually reached them. That
  is what ``scripts/check_investigation_depth.py`` gates on, and it is the
  only thing stopping alert-enrich-summarise from regressing back in.
* **It is reviewable.** A strategy is a dataclass with a rationale. Adding one
  is a reviewable change rather than a prompt edit nobody can diff.

Ten strategies here, covering the kill chains the corpus actually fires on.
The registry is designed for many more; each is ~20 lines and needs its own
selection test.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Pivots a strategy can ask for. Must match tool names in
# ``app.tools.investigation``; the drift test asserts it.
KNOWN_PIVOTS = frozenset(
    {
        "process_activity",
        "historical_execution",
        "network_connections",
        "authentication_events",
        "fleet_ioc_hunt",
        "entity_timeline",
        "technique_activity",
        "process_tree",
        "mailbox_activity",
        "oauth_grants",
        "persistence_mechanisms",
    }
)


@dataclass(frozen=True)
class Strategy:
    """One named investigation approach.

    ``expected_pivots`` is what the depth gate grades against. ``min_pivots``
    is the floor below which the investigation did not actually investigate —
    lower than ``len(expected_pivots)`` because a pivot that returns nothing
    legitimately ends a branch, and grading on the full list would reward
    calling tools for the sake of it.
    """

    id: str
    name: str
    applies_when: str
    rationale: str
    plan: tuple[str, ...]
    expected_pivots: tuple[str, ...]
    min_pivots: int = 2
    techniques: tuple[str, ...] = field(default_factory=tuple)
    keywords: tuple[str, ...] = field(default_factory=tuple)

    def system_guidance(self) -> str:
        """Render the strategy as prompt guidance.

        Phrased as an approach rather than an instruction list: the model
        should skip a step whose predecessor returned nothing, and a numbered
        imperative sequence discourages that.
        """
        steps = "\n".join(f"  {i}. {step}" for i, step in enumerate(self.plan, 1))
        return (
            f"Investigation approach: {self.name}\n"
            f"Why this approach: {self.rationale}\n"
            f"Suggested line of enquiry — follow what the evidence supports and "
            f"skip steps whose inputs came back empty:\n{steps}\n"
            f"Do not stop at the first tool result. Each answer above is the input "
            f"to the next question. If a tool reports its data class is not "
            f"ingested, record that as a gap in coverage rather than as evidence "
            f"the activity did not occur."
        )


STRATEGIES: tuple[Strategy, ...] = (
    Strategy(
        id="endpoint-suspicious-process",
        name="Suspicious process on an endpoint",
        applies_when="An EDR or endpoint alert names a process or binary hash.",
        rationale=(
            "A single suspicious process is almost never decidable in isolation. "
            "What decides it is whether the binary is new to the estate, where "
            "else it has run, and what it talked to."
        ),
        plan=(
            "List what executed on the host around the alert.",
            "Establish the process lineage — what spawned it. A signed binary "
            "launched by a browser is a different finding from the same binary "
            "launched by a scheduler.",
            "Take the binary's hash or name and find every other host that has run it — "
            "first-seen timestamps clustered in one morning mean something different "
            "from a binary present for a year.",
            "Check the host's outbound connections for the same window.",
            "If a user is associated, check where that account authenticated from.",
            "Reconstruct the host timeline once the entities are known.",
        ),
        expected_pivots=(
            "process_activity",
            "process_tree",
            "historical_execution",
            "network_connections",
            "entity_timeline",
        ),
        min_pivots=3,
        techniques=("T1059", "T1204", "T1543", "T1055"),
        keywords=("process", "binary", "executable", "powershell", "cmd.exe", "malware", "edr"),
    ),
    Strategy(
        id="identity-account-takeover",
        name="Suspected account takeover",
        applies_when="An identity provider alert names a user: impossible travel, MFA fatigue, risky sign-in.",
        rationale=(
            "Authentication anomalies are cheap to raise and expensive to judge. "
            "The deciding evidence is the account's own recent pattern and whether "
            "anything followed the suspicious session."
        ),
        plan=(
            "Pull the account's authentication events and look at the distinct source addresses and the intervals between them.",
            "Check for OAuth consent grants and mailbox rule changes on the account — the usual post-compromise steps.",
            "Build the account's timeline across every source to see what followed the suspicious sign-in.",
            "If any host is associated, check what ran on it.",
        ),
        expected_pivots=(
            "authentication_events",
            "oauth_grants",
            "mailbox_activity",
            "entity_timeline",
        ),
        min_pivots=2,
        techniques=("T1078", "T1621", "T1556", "T1098"),
        keywords=("impossible travel", "mfa", "sign-in", "login", "authentication", "account", "okta", "entra"),
    ),
    Strategy(
        id="phishing-payload",
        name="Phishing with a delivered payload",
        applies_when="An email-security or web-proxy alert names a URL, attachment or sender.",
        rationale=(
            "The question is never whether the mail arrived, it is whether anyone acted on it and what happened next on their machine."
        ),
        plan=(
            "Hunt the URL or attachment hash across the fleet to find who else received or fetched it.",
            "For any host that did, list what executed shortly afterwards.",
            "Check outbound connections from those hosts.",
            "Check the recipient account's mailbox for rules added after delivery.",
        ),
        expected_pivots=(
            "fleet_ioc_hunt",
            "process_activity",
            "network_connections",
            "mailbox_activity",
        ),
        min_pivots=2,
        techniques=("T1566", "T1204", "T1598"),
        keywords=("phish", "email", "attachment", "url", "proxy", "sender"),
    ),
    Strategy(
        id="c2-beaconing",
        name="Command-and-control beaconing",
        applies_when="A network or DNS alert names an external address or domain with periodic traffic.",
        rationale=(
            "Beaconing is decided by breadth and regularity, not by a single "
            "connection. One host talking to an address is ambiguous; four hosts "
            "on the same interval is not."
        ),
        plan=(
            "Hunt the destination across the fleet — how many distinct hosts reach it.",
            "For each, list the connections and look at the intervals.",
            "Identify the process responsible on at least one host.",
            "Check whether that binary appears elsewhere.",
        ),
        expected_pivots=(
            "fleet_ioc_hunt",
            "network_connections",
            "process_activity",
            "historical_execution",
        ),
        min_pivots=3,
        techniques=("T1071", "T1095", "T1573", "T1008"),
        keywords=("beacon", "c2", "command and control", "dns", "outbound", "periodic"),
    ),
    Strategy(
        id="lateral-movement",
        name="Lateral movement between hosts",
        applies_when="An alert shows authentication or remote execution from one internal host to another.",
        rationale=(
            "Lateral movement is a path, and a path is only visible by walking it. The useful output is the set of hosts touched, in order."
        ),
        plan=(
            "Pull the account's authentication events to enumerate the hosts it reached.",
            "For each host, list what executed after the authentication.",
            "Hunt any tooling found across the rest of the fleet.",
            "Build the timeline across the account to order the hops.",
        ),
        expected_pivots=(
            "authentication_events",
            "process_activity",
            "historical_execution",
            "entity_timeline",
        ),
        min_pivots=3,
        techniques=("T1021", "T1570", "T1550", "T1563"),
        keywords=("lateral", "psexec", "smb", "rdp", "wmi", "remote execution", "pass-the-hash"),
    ),
    Strategy(
        id="cloud-credential-abuse",
        name="Cloud credential abuse",
        applies_when="A cloud audit alert shows unusual API activity, role assumption or key use.",
        rationale=(
            "A cloud key is only as interesting as what it reached. The pivot that "
            "matters is whether the calling address appears anywhere else in the "
            "estate — a corporate egress is different from a hosting provider."
        ),
        plan=(
            "Check the principal's authentication and API activity for the window.",
            "Hunt the calling source address across the fleet.",
            "Build the principal's timeline to order the API calls.",
            "Look for the same technique elsewhere in the account.",
        ),
        expected_pivots=(
            "authentication_events",
            "fleet_ioc_hunt",
            "entity_timeline",
            "technique_activity",
        ),
        min_pivots=2,
        techniques=("T1078.004", "T1552", "T1580", "T1098.001"),
        keywords=("aws", "iam", "assumerole", "cloudtrail", "gcp", "azure", "access key", "s3"),
    ),
    Strategy(
        id="data-exfiltration",
        name="Data exfiltration",
        applies_when="An alert shows large or unusual outbound transfer, or access to a sensitive store.",
        rationale=(
            "Volume alone is a poor signal. What distinguishes exfiltration is the "
            "destination being unusual for the estate and the access preceding it "
            "being unusual for the account."
        ),
        plan=(
            "List the outbound connections and identify the destination.",
            "Hunt the destination across the fleet — is anyone else reaching it.",
            "Check the account's recent activity for the access that preceded it.",
            "Build the timeline to establish order.",
        ),
        expected_pivots=(
            "network_connections",
            "fleet_ioc_hunt",
            "entity_timeline",
            "authentication_events",
        ),
        min_pivots=3,
        techniques=("T1041", "T1567", "T1048", "T1030"),
        keywords=("exfil", "upload", "transfer", "egress", "large", "dlp"),
    ),
    Strategy(
        id="privilege-escalation",
        name="Privilege escalation",
        applies_when="An alert shows a permission grant, role change or privileged-group membership change.",
        rationale=(
            "The grant itself is rarely the incident. What matters is what the "
            "account did with it, and whether the granting account was itself "
            "acting normally."
        ),
        plan=(
            "Check the account's authentication trail before the change.",
            "Build the timeline after the grant to see what the new privilege was used for.",
            "If a host is involved, list what executed on it.",
            "Check whether the same technique appears elsewhere.",
        ),
        expected_pivots=(
            "authentication_events",
            "entity_timeline",
            "process_activity",
            "technique_activity",
        ),
        min_pivots=2,
        techniques=("T1068", "T1078.003", "T1098", "T1548"),
        keywords=("privilege", "escalat", "admin", "sudo", "role", "group membership", "grant"),
    ),
    Strategy(
        id="persistence-established",
        name="Persistence established on a host",
        applies_when="An alert names a scheduled task, service, run key or startup item.",
        rationale=(
            "Persistence is an outcome, not an entry. The investigation is mostly "
            "backwards: what installed it, and is it on other machines too."
        ),
        plan=(
            "Enumerate persistence mechanisms on the host.",
            "List what executed around the time it was created.",
            "Hunt the installing binary across the fleet.",
            "Build the host timeline to establish the entry point.",
        ),
        expected_pivots=(
            "persistence_mechanisms",
            "process_activity",
            "historical_execution",
            "entity_timeline",
        ),
        min_pivots=2,
        techniques=("T1053", "T1543", "T1547", "T1546"),
        keywords=("persistence", "scheduled task", "cron", "service", "run key", "startup", "launchd"),
    ),
    Strategy(
        id="generic-triage",
        name="General triage",
        applies_when="No more specific strategy matches the alert.",
        rationale=(
            "The fallback still has to investigate. Without one, an unmatched alert "
            "reverts to summarising the alert text, which is the behaviour the "
            "strategy library exists to replace."
        ),
        plan=(
            "Identify the entities named in the alert: host, account, indicator.",
            "For each entity, pull its recent timeline.",
            "Hunt any indicator across the fleet.",
            "Check whether the mapped technique appears elsewhere recently.",
        ),
        expected_pivots=("entity_timeline", "fleet_ioc_hunt", "technique_activity"),
        min_pivots=2,
        keywords=(),
    ),
)

_BY_ID = {s.id: s for s in STRATEGIES}
FALLBACK = _BY_ID["generic-triage"]


def get_strategy(strategy_id: str) -> Strategy | None:
    return _BY_ID.get(strategy_id)


def select_strategy(
    *,
    summary: str = "",
    techniques: list[str] | None = None,
) -> Strategy:
    """Pick the strategy best matching an alert.

    Technique match outranks keyword match: an ATT&CK mapping is a deliberate
    classification, whereas a keyword can appear in any narrative. Ties go to
    the earlier strategy, and no match falls back to general triage rather
    than to no strategy at all.
    """
    text = (summary or "").lower()
    mapped = {t.upper() for t in (techniques or [])}

    best: Strategy | None = None
    best_score = 0

    for strategy in STRATEGIES:
        if strategy is FALLBACK:
            continue
        score = 0
        for technique in strategy.techniques:
            # A sub-technique alert should match its parent's strategy:
            # T1078.004 is still an identity problem.
            if any(m == technique or m.startswith(technique + ".") for m in mapped):
                score += 10
        score += sum(2 for keyword in strategy.keywords if keyword in text)

        if score > best_score:
            best, best_score = strategy, score

    return best or FALLBACK
