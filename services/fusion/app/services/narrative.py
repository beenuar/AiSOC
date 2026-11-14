"""
Correlation narrative builder.

Wave 6 of the v1.5 SOC Console Parity plan. Every fused alert ships with a
human-readable, deterministic correlation narrative that the
``InvestigationRail`` on ``/alerts`` renders verbatim. The narrative answers
the analyst's first three questions in one short paragraph — *what fired*,
*what evidence supports it*, and *what we recommend next* — so the right pane
of the alerts workbench is useful **without** an LLM round-trip. The
streaming LLM explanation still exists; it sits behind a "Deep Explain"
button inside the rail (``POST /api/v1/alerts/{id}/explain``).

Design contract
===============

* **Deterministic.** Given identical inputs the output is byte-for-byte
  identical. No timestamps, no random ordering, no LLM. The output is safe to
  cache on the row and serve cold.
* **Pure.** ``build_narrative`` is a free function that takes a
  ``NarrativeInputs`` dataclass and returns a string. No database calls, no
  network, no logging side effects.
* **Vendored.** This module lives canonically in ``services/fusion`` and is
  byte-mirrored into ``services/api/app/_vendor/narrative.py`` so the API can
  lazily compute the narrative on first read for legacy alerts that were
  fused before the column existed. ``scripts/sync_vendored_narrative.py``
  guards the mirror; CI fails the build the moment the two copies drift.
* **Markdown-light.** The output uses a tiny markdown dialect — ``**bold**``,
  bullet lists, blank-line paragraphs. The rail renders these without a full
  markdown engine. No tables, no headings, no images.

Schema
======

The narrative is composed of up to four blocks separated by a blank line:

1. **Summary** — one sentence: *severity*, *title*, *primary entity*.
2. **Why we believe it** — up to four bullets pulled from the confidence
   rationale, sorted by impact, prefixed with ``+`` or ``−``.
3. **Correlated activity** — one short paragraph if the alert is part of an
   incident, otherwise omitted.
4. **Recommended next step** — one bullet derived from severity + MITRE
   tactic. Action surface is deliberately conservative; the rail also
   surfaces the LLM-generated remediation actions from the responder agent
   for cases that need richer planning.

If any block has no content it is dropped — the narrative never contains
empty sections.

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

NARRATIVE_VERSION = 1
"""Bump this whenever the algorithm changes in a way that should invalidate
existing cached narratives. The API uses this to opportunistically refresh
rows whose ``narrative`` was generated under a stale version (a follow-up
PR will add a ``narrative_version`` column once we need it; for now the
constant simply marks the algorithm revision in code)."""


Severity = Literal["critical", "high", "medium", "low", "info"]
ConfidenceBand = Literal["high", "medium", "low"]


@dataclass(frozen=True)
class NarrativeFactor:
    """One row of the confidence rationale, as seen by the builder.

    Mirrors ``services/fusion/app/models/alert.py::ConfidenceFactor`` and
    ``services/api/app/models/alert.py::Alert.confidence_rationale`` (which
    stores the same shape as JSONB). The builder only needs the human-
    facing fields, so we keep this dataclass minimal and avoid taking a
    runtime dependency on either model.

    ``contribution`` is signed in [-1.0, +1.0]; positive nudges the score
    up, negative nudges it down. ``weight`` is in [0, 1].
    """

    label: str
    value: str
    contribution: float
    weight: float

    @property
    def impact(self) -> float:
        """Absolute signed effect — used to sort the rationale."""
        return self.contribution * self.weight


@dataclass(frozen=True)
class NarrativeInputs:
    """Everything ``build_narrative`` needs to produce a narrative.

    Both services construct this from their own native model. Keeping the
    dataclass deliberately minimal lets us add new signals (RBA score,
    UEBA z-score, …) by adding optional fields without breaking the
    fusion-time call site.
    """

    severity: Severity
    title: str

    # Detection confidence
    confidence: int | None = None  # 0-100 surfaced on the row
    confidence_label: ConfidenceBand | None = None
    rationale: tuple[NarrativeFactor, ...] = ()

    # Entities — first non-empty wins for the "primary entity" mention.
    src_ip: str | None = None
    dst_ip: str | None = None
    hostname: str | None = None
    username: str | None = None
    file_hash: str | None = None
    domain: str | None = None
    url: str | None = None

    # MITRE coverage — we only use the first tactic + technique count to
    # keep the prose terse. The full list still lives on the row.
    mitre_tactics: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()

    # Correlation context — populated when the alert was attached to an
    # incident at fusion time.
    incident_alert_count: int | None = None  # total alerts on the incident
    correlation_decision: str | None = None  # "new_incident" | "correlated"

    # Risk-Based Alerting — set when the alert touches an entity that
    # already accumulated RBA points before this fired.
    rba_entity: str | None = None
    rba_score: float | None = None

    # Exploit-in-wild boost (Tier 3.5) — the vuln_boost service flips this
    # when one of the alert's entities matches an asset vulnerability with
    # ``is_exploited=True``. The narrative calls it out explicitly because
    # it materially changes the recommended action.
    exploit_in_wild: bool = False

    # Optional source/connector — included in the summary for context.
    source: str | None = None

    # Optional tags surfaced verbatim ("byok-llm", "ransomware-family:lockbit").
    tags: tuple[str, ...] = field(default_factory=tuple)


# ─── Helpers ─────────────────────────────────────────────────────────────────


# Recommended-next-step lookup. Keyed by ``(severity, mitre_tactic)`` so that
# the same tactic at different severities gives a proportionate response.
# ``"*"`` is a wildcard fallback that catches alerts with no MITRE mapping.
#
# These are deliberately *operational* sentences — what an analyst would
# actually do in the next 60 seconds. The richer multi-step LLM remediation
# plan is generated by the responder agent and surfaced separately.
_RECOMMENDED_ACTIONS: dict[tuple[str, str], str] = {
    ("critical", "initial-access"): "Isolate the affected host and revoke the impacted user's sessions immediately.",
    ("critical", "execution"): "Isolate the host, snapshot volatile memory, and trigger the incident response playbook.",
    ("critical", "persistence"): "Isolate the host and rotate any credentials with access to the persistence mechanism.",
    ("critical", "privilege-escalation"): "Quarantine the host and audit privileged-group membership changes in the last 24h.",
    ("critical", "defense-evasion"): "Isolate the host and validate EDR/AV state on every endpoint sharing the same image.",
    ("critical", "credential-access"): "Force a password reset and revoke active sessions for every affected identity.",
    ("critical", "discovery"): "Isolate the host and review authentication logs for lateral pivot attempts.",
    ("critical", "lateral-movement"): "Quarantine the source and destination hosts; block the SMB/RDP path between them.",
    ("critical", "collection"): "Isolate the host, preserve the staged data, and notify Legal/DPO of potential exfil.",
    ("critical", "exfiltration"): "Block the destination at the egress firewall, isolate the source, and start IR.",
    ("critical", "impact"): "Activate the disaster-recovery runbook and isolate every host in the blast radius.",
    ("critical", "command-and-control"): "Block the C2 destination at the firewall and isolate the beaconing host.",
    ("high", "initial-access"): "Investigate the auth/login chain; suspend the user pending verification.",
    ("high", "execution"): "Triage the process tree and quarantine the binary if it is unsigned or rare.",
    ("high", "persistence"): "Inspect autoruns / scheduled tasks on the host and capture the persistence artifact.",
    ("high", "privilege-escalation"): "Review the privilege change chain and validate it against the change calendar.",
    ("high", "defense-evasion"): "Verify EDR is healthy on the host and compare to a known-good baseline.",
    ("high", "credential-access"): "Force a password rotation for the affected identity and review session activity.",
    ("high", "discovery"): "Pull recon-related telemetry and check for follow-on lateral movement.",
    ("high", "lateral-movement"): "Audit recent authentication on the destination host and block stale credentials.",
    ("high", "collection"): "Snapshot the staged artifacts and review who else accessed the same data store.",
    ("high", "exfiltration"): "Rate-limit the destination and confirm whether the upload is sanctioned.",
    ("high", "impact"): "Verify backup integrity and tighten access to the impacted system.",
    ("high", "command-and-control"): "Sinkhole the destination and inspect outbound DNS from the host.",
    ("medium", "*"): "Triage the alert in the queue: confirm whether the activity is sanctioned before escalating.",
    ("low", "*"): "Acknowledge in the queue; suppress if this is a known benign pattern.",
    ("info", "*"): "Informational — review during the next batch tuning pass.",
}

_DEFAULT_ACTION = "Triage the alert in the queue and validate the supporting evidence before escalating."

# Bullet glyph for the action — kept identical with the rationale glyph so
# the rail can re-flow the list without re-thinking the bullet style.
_BULLET = "- "


def _primary_entity(inputs: NarrativeInputs) -> str | None:
    """Pick the most informative entity to mention in the summary.

    Order: ``src_ip → hostname → username → domain → url → dst_ip →
    file_hash``. This matches the precedence used by the deduplicator's
    correlation key so the narrative and the dedup key always agree on
    which entity is "primary".
    """
    for value in (
        inputs.src_ip,
        inputs.hostname,
        inputs.username,
        inputs.domain,
        inputs.url,
        inputs.dst_ip,
        inputs.file_hash,
    ):
        if value:
            return value
    return None


def _summary_block(inputs: NarrativeInputs) -> str:
    severity_word = inputs.severity.capitalize() if inputs.severity else "Unknown"
    primary = _primary_entity(inputs)

    pieces = [f"**{severity_word}** alert: {inputs.title.strip()}"]
    if primary:
        pieces.append(f"on **{primary}**")
    if inputs.source:
        pieces.append(f"from `{inputs.source}`")

    sentence = " ".join(pieces).rstrip(".") + "."
    return sentence


def _rationale_block(inputs: NarrativeInputs) -> str | None:
    if not inputs.rationale:
        return None
    # Sort by absolute impact, take the top four. We do *not* drop zero-
    # impact factors silently — if the only factors we have are noise, the
    # rail should say so explicitly. We only drop a factor whose absolute
    # impact rounds to exactly zero *and* there are more impactful factors
    # available.
    ordered = sorted(inputs.rationale, key=lambda f: abs(f.impact), reverse=True)
    keep: list[NarrativeFactor] = []
    for factor in ordered:
        if len(keep) >= 4:
            break
        # Skip purely zero rows once we already have one bullet.
        if keep and round(abs(factor.impact), 3) == 0.0:
            continue
        keep.append(factor)
    if not keep:
        return None
    lines = ["Why we believe it:"]
    for factor in keep:
        sign = "+" if factor.contribution >= 0 else "−"
        lines.append(f"{_BULLET}{sign} **{factor.label}** — {factor.value}")
    if inputs.confidence is not None and inputs.confidence_label is not None:
        lines.append(f"{_BULLET}Confidence: **{inputs.confidence_label}** ({inputs.confidence}/100)")
    elif inputs.confidence is not None:
        lines.append(f"{_BULLET}Confidence: **{inputs.confidence}/100**")
    elif inputs.confidence_label is not None:
        lines.append(f"{_BULLET}Confidence: **{inputs.confidence_label}**")
    return "\n".join(lines)


def _correlation_block(inputs: NarrativeInputs) -> str | None:
    pieces: list[str] = []
    if inputs.correlation_decision == "correlated" and inputs.incident_alert_count and inputs.incident_alert_count > 1:
        pieces.append(f"Correlated activity: this alert is part of an incident with **{inputs.incident_alert_count}** related alerts.")
    elif inputs.correlation_decision == "new_incident":
        pieces.append("Correlated activity: this is the **first** alert on a newly opened incident.")
    if inputs.rba_entity and inputs.rba_score is not None:
        pieces.append(
            f"Risk-based alerting has accumulated **{inputs.rba_score:.0f}** points on `{inputs.rba_entity}` before this alert fired."
        )
    if inputs.exploit_in_wild:
        pieces.append(
            "**Exploit-in-wild**: one of the indicators on this alert matches an asset vulnerability marked as actively exploited."
        )
    if not pieces:
        return None
    return " ".join(pieces)


def _action_block(inputs: NarrativeInputs) -> str:
    # Resolve the recommended-action lookup. We use the first declared
    # tactic; the rest are still visible on the row.
    severity = inputs.severity or "medium"
    tactic = inputs.mitre_tactics[0].lower() if inputs.mitre_tactics else "*"

    action = _RECOMMENDED_ACTIONS.get((severity, tactic))
    if action is None:
        # Fall back to the severity-wildcard row, then to the default.
        action = _RECOMMENDED_ACTIONS.get((severity, "*"), _DEFAULT_ACTION)
    return f"Recommended next step:\n{_BULLET}{action}"


# ─── Public API ──────────────────────────────────────────────────────────────


def build_narrative(inputs: NarrativeInputs) -> str:
    """Build the deterministic correlation narrative.

    The output is plain Markdown-light (see module docstring). The same
    inputs always produce the same string; callers can safely cache the
    result keyed by the alert id.
    """
    blocks: list[str] = [_summary_block(inputs)]

    rationale = _rationale_block(inputs)
    if rationale:
        blocks.append(rationale)

    correlation = _correlation_block(inputs)
    if correlation:
        blocks.append(correlation)

    blocks.append(_action_block(inputs))

    return "\n\n".join(blocks)


__all__ = [
    "NARRATIVE_VERSION",
    "NarrativeFactor",
    "NarrativeInputs",
    "build_narrative",
]
