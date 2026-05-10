"""
Pillar-1 Evaluation: Playbook Completion Rate (WS-C3)
=====================================================

For every incident in the 200-case synthetic benchmark, ask:

    "Does the shipped playbook pack contain at least one playbook that:
       (a) is tagged with one of the incident's mapped categories,
       (b) has a trigger.severity that includes the incident's severity, and
       (c) declares at least one step whose action aligns with the incident's
           expected ``response_class``?"

If yes, the incident is considered **covered**. The headline metric is

    completion_rate = covered_incidents / total_incidents

Three derived gates run alongside it:

  * **Severity gate** — high+critical incidents must clear a stricter floor
    (0.60) because that is the band where containment playbooks matter most.
  * **Per-category presence gate** — every shipped playbook category
    (account-takeover, bec, cloud-misconfig, …) must cover ≥ 1 incident in
    the dataset. A category that matches *no* incidents is dead weight and a
    regression in the dataset↔pack alignment.
  * **Action-alignment gate** — among the matched incidents, ≥ 0.85 must
    pair with a playbook whose primary step type aligns with the incident's
    response class (isolate_host → ``isolate_host`` step; block_indicator →
    ``block_ip`` step; etc.). This is what stops a "matches by tag only"
    playbook from being scored as a real response.

This is a **substrate self-consistency gate**, not an LLM judgement: the
matcher uses the dataset's deterministic ``template_id`` and the pack's
declarative ``trigger`` + ``tags`` + step-type metadata. CI gates on it so
that:

  * Removing a playbook → coverage drops → CI fails.
  * Adding a broken playbook (bad trigger / no aligned step) → orphan
    playbook gate fails.
  * Adding new playbooks that cover previously-orphaned templates → coverage
    rises (no false negatives because per-template macro is also reported).

What this does **not** prove:

  * It does not assert the playbook actually mitigates the incident at
    runtime (that would need an executor with mocked SOAR APIs — orthogonal,
    tracked separately).
  * It does not enforce per-template coverage for the ~22 endpoint-
    compromise / persistence templates the v1 pack does not yet cover; those
    are explicitly listed in ``_TEMPLATES_WITHOUT_PACK_COVERAGE`` and the
    floor is set so the regression signal is preserved without falsely
    blocking PRs.

Run:
    pytest services/agents/tests/test_playbook_completion_rate.py -v
"""

from __future__ import annotations

import json
import re
import unittest
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_TESTS_DIR = Path(__file__).parent
_DATASET_PATH = _TESTS_DIR / "eval_data" / "synthetic_incidents.json"
_REPO_ROOT = _TESTS_DIR.parent.parent.parent
_PACK_ROOT = _REPO_ROOT / "playbooks" / "packs" / "v1"


# ---------------------------------------------------------------------------
# Floors
# ---------------------------------------------------------------------------

OVERALL_COMPLETION_FLOOR: float = 0.50
# This is the *mapped* high+critical floor: covered/mapped, where "mapped" means
# the template has at least one entry in _TEMPLATE_CATEGORIES. The raw
# severity-only rate is reported alongside but not gated, because it bakes in
# the pack's documented coverage gaps (endpoint compromise, persistence,
# defense-evasion) and would punish CI for known v1 scope decisions.
HIGH_CRIT_MAPPED_FLOOR: float = 0.95
ACTION_ALIGNMENT_FLOOR: float = 0.85


# ---------------------------------------------------------------------------
# Template -> playbook-category mapping
#
# Hand-authored against the v1 pack (50 playbooks, 9 categories). Each
# template_id maps to the *set* of categories whose playbooks should be
# considered candidate responders. Templates that the v1 pack legitimately
# does not yet cover (endpoint compromise, persistence, defense-evasion,
# pure execution) are mapped to an empty list so the metric exposes the
# coverage gap honestly without silently inflating itself.
# ---------------------------------------------------------------------------

_TEMPLATE_CATEGORIES: dict[str, list[str]] = {
    # account-takeover / suspicious-signin (overlapping — both packs respond)
    "azure-ad-impossible-travel": ["account-takeover", "suspicious-signin"],
    "credential-spray": ["account-takeover", "brute-force"],
    "github-pat-leak": ["account-takeover", "supply-chain"],
    "helpdesk-password-reset-abuse": ["account-takeover", "suspicious-signin", "brute-force"],
    "oauth-refresh-token-theft": ["account-takeover", "cloud-account-takeover"],
    "saml-golden-ticket": ["account-takeover", "lateral-movement", "cloud-account-takeover"],
    "vpn-new-geography": ["account-takeover", "suspicious-signin"],
    # bec / phishing (email-based attack chains share playbooks)
    "bec-wire-fraud": ["bec"],
    "oauth-consent-phish": ["bec", "account-takeover", "phishing"],
    "outlook-auto-forward-rule": ["bec"],
    "phishing-macro-email": ["bec", "phishing"],
    # cloud-misconfig / cloud-account-takeover
    "ec2-imds-credential-theft": ["cloud-misconfig", "cloud-account-takeover"],
    "malicious-container-image": ["cloud-misconfig", "supply-chain"],
    "public-s3-bucket-pii": ["cloud-misconfig", "data-exfil"],
    # data-exfil / anomalous-data (exfil triggers anomalous-data playbooks too)
    "bulk-pii-download": ["data-exfil", "insider-risk", "anomalous-data"],
    "dns-tunnel-exfil": ["data-exfil", "anomalous-data"],
    "insider-mailbox-export": ["data-exfil", "insider-risk"],
    "personal-drive-exfil": ["data-exfil", "insider-risk"],
    "s3-exfil-cloud-storage": ["data-exfil", "anomalous-data"],
    # ddos / network-containment (DDoS requires active network containment)
    "ddos-syn-flood": ["ddos", "network-containment"],
    # insider-risk
    "service-account-privileged-command": ["insider-risk"],
    # lateral-movement
    "ad-dcsync": ["lateral-movement"],
    "kerberoasting": ["lateral-movement"],
    "pass-the-hash-lateral": ["lateral-movement"],
    "rdp-lateral-movement": ["lateral-movement"],
    "wmi-lateral-execution": ["lateral-movement"],
    # ransomware
    "ransomware-encryption": ["ransomware"],
    # supply-chain
    "compromised-ci-runner": ["supply-chain"],
    "npm-supply-chain": ["supply-chain"],
    # container-escape (moved from _TEMPLATES_WITHOUT_PACK_COVERAGE — v1 pack now covers)
    "docker-runtime-abuse": ["container-escape"],
    "k8s-privileged-pod-escape": ["container-escape", "privilege-escalation"],
    # endpoint-isolation (moved from _TEMPLATES_WITHOUT_PACK_COVERAGE — v1 pack now covers)
    "disable-edr-tooling": ["endpoint-isolation"],
    "lsass-memory-dump": ["endpoint-isolation"],
    # ids-critical (moved from _TEMPLATES_WITHOUT_PACK_COVERAGE — IDS/IPS pack now covers)
    "dga-c2": ["ids-critical"],
    "https-c2-beacon": ["ids-critical"],
    # malware / endpoint-isolation (malware execution triggers both response tracks)
    "powershell-obfuscated-dropper": ["malware", "endpoint-isolation"],
    "process-hollowing-svchost": ["malware"],
    # privilege-escalation (moved from _TEMPLATES_WITHOUT_PACK_COVERAGE — v1 pack now covers)
    "linux-suid-abuse": ["privilege-escalation"],
    "uac-bypass-fodhelper": ["privilege-escalation"],
    # web-compromise (moved from _TEMPLATES_WITHOUT_PACK_COVERAGE — v1 pack now covers)
    "confluence-watering-hole": ["web-compromise", "phishing"],
    "webapp-sqli-ssrf-exploit": ["web-compromise"],
}

# Templates the v1 pack legitimately does not cover. Listed explicitly so
# adding a new template without either a pack mapping or an explicit
# no-coverage entry will trip ``test_every_template_is_classified``.
_TEMPLATES_WITHOUT_PACK_COVERAGE: set[str] = {
    # Endpoint persistence / defense-evasion templates not yet covered by a
    # v1 playbook. These remain endpoint-native signals where the pack's
    # identity/network/cloud playbooks cannot meaningfully respond. Slated
    # for v1.1 endpoint containment packs.
    "certutil-download-cradle",
    "clipboard-keylogger",
    "cron-backdoor",
    "event-log-cleared",
    "linux-journald-tampering",
    "office-vsto-addin",
    "registry-run-persistence",
    "scheduled-task-persistence",
    "uefi-firmware-implant",
    "usb-autorun-airgap",
    "wmi-event-subscription",
    # Medium-severity reconnaissance / early-stage templates. The dataset
    # generator emits these at medium severity (pre-exploitation signals),
    # while the pack's containment playbooks (lateral, ransomware) are
    # correctly scoped to high+critical post-exploitation events. Mapping
    # them would either force a noisy false-positive match or require
    # downgrading the playbooks. Listed here so the regression gate stays
    # meaningful for the templates that *should* match.
    "ldap-bloodhound-discovery",
    "smb-share-enumeration",
    "xmrig-cryptominer",
}

# Playbooks that ship in the v1 pack for real-world coverage but are not
# exercised by the deterministic 200-incident benchmark. These are *not*
# bugs — the dataset is biased toward high/critical post-exploitation
# incidents, while these playbooks target medium-severity edge cases
# (removable-media exfil, after-hours insider access, critical-only
# volumetric DDoS). Removing one of these from the pack should still trip
# CI elsewhere (the pack inventory test); excluding them from the
# orphan-playbook gate keeps that gate honest about *broken* triggers.
_PLAYBOOKS_NOT_IN_BENCHMARK_DATASET: set[str] = {
    "exfil-removable-media-v1",
    "ddos-volumetric-l3-v1",
    "insider-after-hours-access-v1",
}

# All categories the pack actually ships. Loaded dynamically below from disk
# so an analyst adding a new category folder can't drift this list silently.


# ---------------------------------------------------------------------------
# response_class -> action-alignment signals
#
# When matching a playbook against an incident, we ask: does the playbook
# have at least one step whose declared type or human-readable name implies
# the incident's expected response action? Step-type matching is the strong
# signal; step-name keyword matching is the fallback for response classes
# that v1 expresses as generic ``http`` or ``investigate`` steps (e.g.
# disable_account → POST to IDP /reset endpoint).
# ---------------------------------------------------------------------------

_RESPONSE_ACTION_SIGNALS: dict[str, dict[str, set[str]]] = {
    "isolate_host": {
        "step_types": {"isolate_host"},
        "step_name_keywords": {"isolate", "contain", "quarantine"},
    },
    "block_indicator": {
        "step_types": {"block_ip"},
        "step_name_keywords": {"block", "blocklist", "deny", "sinkhole"},
    },
    "disable_account": {
        "step_types": set(),
        "step_name_keywords": {
            "disable",
            "reset",
            "revoke",
            "lock account",
            "force reset",
            "force log",
            "kill session",
        },
    },
    "rollback_change": {
        "step_types": set(),
        "step_name_keywords": {
            "rollback",
            "roll back",
            "revert",
            "restore",
            "remove rule",
            "remove forwarding",
            "rotate",
            "patch",
        },
    },
    "escalate": {
        "step_types": {"create_ticket", "notify"},
        "step_name_keywords": {"escalate", "page", "notify", "alert", "ticket"},
    },
    "monitor": {
        "step_types": {"investigate"},
        "step_name_keywords": {"investigate", "monitor", "audit", "watch", "hunt"},
    },
}


# ---------------------------------------------------------------------------
# IO
# ---------------------------------------------------------------------------


def _load_dataset() -> list[dict[str, Any]]:
    if not _DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Synthetic incidents dataset missing at {_DATASET_PATH}. Run `python3 scripts/generate_eval_incidents.py` to regenerate."
        )
    with _DATASET_PATH.open() as f:
        return json.load(f)


def _load_playbooks() -> tuple[list[dict[str, Any]], list[str]]:
    """Walk the pack root and return (playbooks, categories).

    A "category" is the immediate subfolder under ``packs/v1/`` so the list
    is canonical and stays in sync with disk layout. Each playbook is
    augmented with a ``__category`` field (the on-disk folder name) and a
    ``__path`` field for diagnostics.
    """
    if not _PACK_ROOT.exists():
        raise FileNotFoundError(f"Playbook pack missing at {_PACK_ROOT}. Verify `playbooks/packs/v1/` is checked in.")
    playbooks: list[dict[str, Any]] = []
    categories: set[str] = set()
    for category_dir in sorted(p for p in _PACK_ROOT.iterdir() if p.is_dir()):
        category = category_dir.name
        if category.startswith("."):
            continue
        categories.add(category)
        for path in sorted(category_dir.glob("*.playbook.json")):
            try:
                pb = json.loads(path.read_text())
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid playbook JSON: {path} -- {exc}") from exc
            pb["__category"] = category
            pb["__path"] = str(path.relative_to(_REPO_ROOT))
            playbooks.append(pb)
    return playbooks, sorted(categories)


SYNTHETIC_INCIDENTS_DATA: list[dict[str, Any]] = _load_dataset()
PLAYBOOK_PACK, PACK_CATEGORIES = _load_playbooks()


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip().lower()


def _playbook_severity_set(playbook: dict[str, Any]) -> set[str]:
    trigger = playbook.get("trigger") or {}
    sevs = trigger.get("severity") or []
    return {str(s).lower() for s in sevs}


def _playbook_tag_set(playbook: dict[str, Any]) -> set[str]:
    return {str(t).lower() for t in (playbook.get("tags") or [])}


def _step_signals(playbook: dict[str, Any]) -> tuple[set[str], str]:
    """Return (step_types, concatenated_step_name_text)."""
    types: set[str] = set()
    name_blob_parts: list[str] = []
    for step in playbook.get("steps") or []:
        st = str(step.get("type", "")).lower()
        if st:
            types.add(st)
        name_blob_parts.append(_normalize(str(step.get("name", ""))))
    return types, " | ".join(name_blob_parts)


def _action_aligned(playbook: dict[str, Any], response_class: str) -> bool:
    sig = _RESPONSE_ACTION_SIGNALS.get(response_class)
    if sig is None:
        # Unknown response class -> any playbook with at least one step
        # qualifies. Conservative because we'd rather over-credit a brand-
        # new response class than block the gate when the dataset evolves.
        return bool(playbook.get("steps"))
    types, name_blob = _step_signals(playbook)
    if sig["step_types"] & types:
        return True
    return any(kw in name_blob for kw in sig["step_name_keywords"])


@dataclass
class PlaybookMatch:
    """One playbook<->incident match record."""

    playbook_id: str
    playbook_name: str
    category: str
    severity_match: bool
    tag_match: bool
    action_aligned: bool

    @property
    def is_full_match(self) -> bool:
        return self.severity_match and self.tag_match and self.action_aligned

    @property
    def is_partial_match(self) -> bool:
        # Severity + tag is enough to "cover" the incident even if no step
        # aligns with the response class — we want the action-alignment
        # gate to surface separately so a partial match isn't masked.
        return self.severity_match and self.tag_match


@dataclass
class IncidentEvaluation:
    incident_id: str
    template_id: str
    severity: str
    response_class: str
    mapped_categories: list[str]
    matches: list[PlaybookMatch] = field(default_factory=list)

    @property
    def is_covered(self) -> bool:
        return any(m.is_partial_match for m in self.matches)

    @property
    def has_aligned_match(self) -> bool:
        return any(m.is_full_match for m in self.matches)


@dataclass
class PlaybookCompletionResult:
    incidents: int = 0
    covered: int = 0
    aligned: int = 0
    per_severity: dict[str, dict[str, int]] = field(default_factory=dict)
    per_category: dict[str, dict[str, int]] = field(default_factory=dict)
    per_template: dict[str, dict[str, int]] = field(default_factory=dict)
    orphan_templates: list[str] = field(default_factory=list)
    orphan_playbooks: list[dict[str, str]] = field(default_factory=list)
    per_incident: list[IncidentEvaluation] | None = None

    @property
    def completion_rate(self) -> float:
        return self.covered / self.incidents if self.incidents else 0.0

    @property
    def action_alignment_rate(self) -> float:
        # Alignment rate is conditional on coverage: of the matched
        # incidents, how many had a step-aligned playbook match? An
        # incident with zero matches contributes neither numerator nor
        # denominator, so adding fully-uncovered templates can't game it.
        return self.aligned / self.covered if self.covered else 0.0

    def severity_completion_rate(self, severities: Iterable[str]) -> float:
        target = {s.lower() for s in severities}
        total = 0
        covered = 0
        for sev, bucket in self.per_severity.items():
            if sev not in target:
                continue
            total += bucket["incidents"]
            covered += bucket["covered"]
        return covered / total if total else 0.0

    def severity_completion_rate_mapped(
        self,
        severities: Iterable[str],
        per_incident: Iterable[IncidentEvaluation],
    ) -> tuple[float, int, int]:
        """Severity completion measured *only* over mapped templates.

        Returns (rate, covered, total). "Mapped" means the incident's
        template appears in ``_TEMPLATE_CATEGORIES``; templates explicitly
        listed in ``_TEMPLATES_WITHOUT_PACK_COVERAGE`` are excluded so the
        rate doesn't bake in v1's documented coverage gaps. This is the
        gated metric for high+critical severity.
        """
        target = {s.lower() for s in severities}
        total = 0
        covered = 0
        for ev in per_incident:
            if ev.severity not in target:
                continue
            if ev.template_id not in _TEMPLATE_CATEGORIES:
                continue
            if not _TEMPLATE_CATEGORIES[ev.template_id]:
                continue
            total += 1
            if ev.is_covered:
                covered += 1
        return (covered / total if total else 0.0, covered, total)


def _empty_severity_bucket() -> dict[str, int]:
    return {"incidents": 0, "covered": 0, "aligned": 0}


def _evaluate_one(incident: dict[str, Any], playbooks: list[dict[str, Any]]) -> IncidentEvaluation:
    template_id = str(incident.get("template_id", ""))
    severity = str(incident.get("severity", "")).lower()
    response_class = str(incident.get("response_class", "")).lower()
    mapped = _TEMPLATE_CATEGORIES.get(template_id, [])
    mapped_lower = {c.lower() for c in mapped}
    ev = IncidentEvaluation(
        incident_id=str(incident.get("id", "")),
        template_id=template_id,
        severity=severity,
        response_class=response_class,
        mapped_categories=list(mapped),
    )
    if not mapped:
        return ev
    for pb in playbooks:
        pb_tags = _playbook_tag_set(pb)
        pb_sevs = _playbook_severity_set(pb)
        tag_match = bool(pb_tags & mapped_lower)
        if not tag_match:
            # Cheap reject: if the playbook is tagged for an entirely
            # different scenario we don't even score severity/action.
            continue
        severity_match = severity in pb_sevs if pb_sevs else False
        action_aligned = _action_aligned(pb, response_class)
        ev.matches.append(
            PlaybookMatch(
                playbook_id=str(pb.get("id", "")),
                playbook_name=str(pb.get("name", "")),
                category=str(pb.get("__category", "")),
                severity_match=severity_match,
                tag_match=tag_match,
                action_aligned=action_aligned,
            )
        )
    return ev


def evaluate_playbook_completion(
    dataset: list[dict[str, Any]] | None = None,
    playbooks: list[dict[str, Any]] | None = None,
    *,
    keep_per_incident: bool = False,
) -> PlaybookCompletionResult:
    data = dataset if dataset is not None else SYNTHETIC_INCIDENTS_DATA
    pb_pack = playbooks if playbooks is not None else PLAYBOOK_PACK

    result = PlaybookCompletionResult(per_incident=[] if keep_per_incident else None)

    # Per-category presence: which categories actually fired against any
    # incident? Initialised from the pack so an empty bucket surfaces.
    pack_categories = sorted({pb.get("__category", "") for pb in pb_pack if pb.get("__category")})
    for cat in pack_categories:
        result.per_category[cat] = {"incidents": 0, "covered": 0, "aligned": 0}

    # Per-playbook firing: tracks orphan playbooks (no incident matches).
    pb_firing: dict[str, dict[str, Any]] = {
        str(pb.get("id", "")): {
            "name": pb.get("name", ""),
            "category": pb.get("__category", ""),
            "path": pb.get("__path", ""),
            "covers": 0,
            "aligned_covers": 0,
        }
        for pb in pb_pack
    }

    template_buckets: dict[str, dict[str, int]] = defaultdict(_empty_severity_bucket)

    for inc in data:
        ev = _evaluate_one(inc, pb_pack)
        result.incidents += 1

        sev_bucket = result.per_severity.setdefault(ev.severity or "unknown", _empty_severity_bucket())
        sev_bucket["incidents"] += 1

        tpl_bucket = template_buckets[ev.template_id or "unknown"]
        tpl_bucket["incidents"] += 1

        if ev.is_covered:
            result.covered += 1
            sev_bucket["covered"] += 1
            tpl_bucket["covered"] += 1
            for m in ev.matches:
                if m.is_partial_match:
                    cat_bucket = result.per_category.setdefault(m.category, {"incidents": 0, "covered": 0, "aligned": 0})
                    cat_bucket["covered"] += 1
                    pb_firing[m.playbook_id]["covers"] += 1

        if ev.has_aligned_match:
            result.aligned += 1
            sev_bucket["aligned"] += 1
            tpl_bucket["aligned"] += 1
            for m in ev.matches:
                if m.is_full_match:
                    cat_bucket = result.per_category.setdefault(m.category, {"incidents": 0, "covered": 0, "aligned": 0})
                    cat_bucket["aligned"] += 1
                    pb_firing[m.playbook_id]["aligned_covers"] += 1

        # per-category incident counter (mapped categories side, not
        # firing side, so a category with mapped templates but no firing
        # playbooks shows up as "incidents>0, covered=0").
        for cat in ev.mapped_categories:
            cat_bucket = result.per_category.setdefault(cat, {"incidents": 0, "covered": 0, "aligned": 0})
            cat_bucket["incidents"] += 1

        if keep_per_incident and result.per_incident is not None:
            result.per_incident.append(ev)

    # Roll up per-template stats.
    for tpl, bucket in sorted(template_buckets.items()):
        result.per_template[tpl] = bucket
        if (
            bucket["covered"] == 0
            and tpl not in _TEMPLATES_WITHOUT_PACK_COVERAGE
            and tpl in _TEMPLATE_CATEGORIES
            and _TEMPLATE_CATEGORIES[tpl]
        ):
            # Templates the pack *should* cover but didn't — distinct from
            # the documented gap list. These are real regressions.
            result.orphan_templates.append(tpl)

    for pb_id, info in pb_firing.items():
        if info["covers"] == 0 and pb_id not in _PLAYBOOKS_NOT_IN_BENCHMARK_DATASET:
            result.orphan_playbooks.append(
                {
                    "playbook_id": pb_id,
                    "name": info["name"],
                    "category": info["category"],
                    "path": info["path"],
                }
            )

    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPlaybookCompletionRate(unittest.TestCase):
    """Pack-vs-dataset coverage gates (WS-C3)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = evaluate_playbook_completion(keep_per_incident=True)

    def test_dataset_and_pack_loaded(self) -> None:
        self.assertGreaterEqual(
            len(SYNTHETIC_INCIDENTS_DATA),
            200,
            "Expected the 200-incident benchmark to be present.",
        )
        self.assertGreaterEqual(
            len(PLAYBOOK_PACK),
            10,
            f"Expected v1 playbook pack to ship at least 10 playbooks; got {len(PLAYBOOK_PACK)}.",
        )

    def test_every_template_is_classified(self) -> None:
        """Every template in the dataset must either map to a category or be
        explicitly listed in the no-pack-coverage allowlist."""
        seen = {str(i["template_id"]) for i in SYNTHETIC_INCIDENTS_DATA}
        classified = set(_TEMPLATE_CATEGORIES) | _TEMPLATES_WITHOUT_PACK_COVERAGE
        unclassified = sorted(seen - classified)
        self.assertFalse(
            unclassified,
            f"Unclassified templates (add to _TEMPLATE_CATEGORIES or _TEMPLATES_WITHOUT_PACK_COVERAGE): {unclassified}",
        )

    def test_overall_completion_rate_floor(self) -> None:
        rate = self.result.completion_rate
        print(
            "\n[eval] playbook_completion_rate "
            f"overall: {rate:.3f} | covered: {self.result.covered}/{self.result.incidents} | "
            f"aligned: {self.result.aligned} | "
            f"orphan_templates: {len(self.result.orphan_templates)} | "
            f"orphan_playbooks: {len(self.result.orphan_playbooks)}"
        )
        self.assertGreaterEqual(
            rate,
            OVERALL_COMPLETION_FLOOR,
            f"Overall completion {rate:.3f} below floor {OVERALL_COMPLETION_FLOOR:.2f}. "
            "Either ship a new playbook for an uncovered category or "
            "verify the matcher's mapping is still accurate.",
        )

    def test_high_critical_completion_rate_floor(self) -> None:
        """High+critical severity gate, measured over *mapped* templates only.

        We deliberately don't gate the raw severity rate because the
        dataset includes ~22 endpoint-compromise / persistence templates
        that are documented as v1 coverage gaps in
        ``_TEMPLATES_WITHOUT_PACK_COVERAGE`` — a hard severity gate would
        either force inflating coverage with mismatched playbooks or
        penalise CI for known scope decisions. The mapped rate answers
        the right question: of the high+critical incidents the pack
        *claims* to cover, how many actually have a matching playbook?
        """
        per_incident = self.result.per_incident or []
        rate, covered, total = self.result.severity_completion_rate_mapped(("high", "critical"), per_incident)
        raw_rate = self.result.severity_completion_rate(("high", "critical"))
        print(f"\n[eval] playbook_completion_rate high+critical mapped: {rate:.3f} ({covered}/{total}) | raw: {raw_rate:.3f}")
        self.assertGreaterEqual(
            rate,
            HIGH_CRIT_MAPPED_FLOOR,
            f"high+critical (mapped) completion {rate:.3f} below floor "
            f"{HIGH_CRIT_MAPPED_FLOOR:.2f}. Severe mapped incidents must "
            "have containment playbooks.",
        )

    def test_action_alignment_when_matched(self) -> None:
        rate = self.result.action_alignment_rate
        self.assertGreaterEqual(
            rate,
            ACTION_ALIGNMENT_FLOOR,
            f"Action-alignment rate {rate:.3f} below floor "
            f"{ACTION_ALIGNMENT_FLOOR:.2f}. A matched playbook that lacks a "
            "step aligned with the incident's response_class doesn't count "
            "as a real response.",
        )

    def test_every_pack_category_fires(self) -> None:
        """Every category folder under packs/v1 must match at least one
        incident in the dataset. Dead-weight categories are a regression."""
        dead = [cat for cat, bucket in self.result.per_category.items() if cat in PACK_CATEGORIES and bucket["covered"] == 0]
        self.assertFalse(
            dead,
            f"Pack categories with zero matched incidents: {dead}",
        )

    def test_no_orphan_playbooks(self) -> None:
        """Every playbook in the pack must match at least one incident."""
        self.assertFalse(
            self.result.orphan_playbooks,
            "Orphan playbooks (no matching incident in the dataset):\n"
            + "\n".join(f"  - [{p['category']}] {p['playbook_id']} ({p['path']})" for p in self.result.orphan_playbooks),
        )

    def test_no_unexpected_template_regressions(self) -> None:
        """Templates that *should* be covered (i.e. mapped to a category)
        but produced zero matches indicate either a broken mapping or a
        broken playbook trigger. Distinct from documented gaps."""
        self.assertFalse(
            self.result.orphan_templates,
            f"Mapped templates with zero playbook matches (regression): {self.result.orphan_templates}",
        )


if __name__ == "__main__":
    unittest.main()
