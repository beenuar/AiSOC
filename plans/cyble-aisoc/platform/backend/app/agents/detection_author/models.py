"""Input/output dataclasses for the detection-author pipeline.

The pipeline is intentionally pure-data on its edges so each stage —
extraction, generation, validation, GitOps — can be unit-tested in
isolation and the HTTP layer is a thin shell on top.

``ThreatReport``
    What the analyst (or an upstream Threat-Intel feed) hands us. The
    free-text ``narrative`` is mandatory; everything else is a hint
    that lets us skip expensive guessing.

``SyntheticEvent``
    A positive/negative test event that travels alongside the rule
    through GitOps so reviewers can see WHY the rule fires.

``DetectionProposal``
    The full output of one run: the YAML, the parsed `SigmaRule`, the
    multi-backend translations, the synthetic events, the self-test
    verdict, and the GitOps artifacts (file paths, branch, commit
    message, PR body). Serializable to JSON for the API response.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

# Re-exported only for type hints; we never *import* SigmaRule at the
# top of this module to keep the agent boot-time cheap. Callers that
# need the actual SigmaRule should import it from app.detections.sigma.


# --------------------------------------------------------------------------- #
# Input
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ThreatReport:
    """Natural-language threat description fed into the agent.

    The agent is forgiving about which hints are present:
    - Missing ``mitre_techniques`` → it extracts them from ``narrative``
      via a curated map of technique IDs and aliases.
    - Missing ``iocs`` → it extracts URLs/IPs/hashes/domains via regex.
    - Missing ``logsource`` → it guesses from keywords in the narrative
      (``okta`` → identity, ``edr``/``process`` → endpoint, etc.) and
      defaults to the generic ``application`` logsource.

    The optional ``rule_title`` lets the analyst pre-name the rule so
    its slug-derived id is stable across iterations of the same report.
    """

    narrative: str
    """Free-form prose: 'TA0552 ran impacket secretsdump against DC01...'"""

    rule_title: Optional[str] = None
    """Optional analyst-supplied rule title; otherwise derived from narrative."""

    mitre_techniques: tuple[str, ...] = ()
    """Hints like ('T1003.001', 'T1078'). Lowercased + deduped on intake."""

    iocs: tuple[str, ...] = ()
    """Pre-extracted indicators: URLs, IPs, hashes, domains, filenames."""

    logsource: Optional[dict[str, str]] = None
    """Sigma logsource hint, e.g. ``{'product': 'okta', 'service': 'system'}``."""

    severity: Optional[Literal["low", "medium", "high", "critical"]] = None
    """Override for the derived severity."""

    author: str = "Cyble AiSOC detection-author"
    """Recorded in the YAML's ``author:`` field and the commit signature."""

    tenant_id: Optional[int] = None
    """For audit; the rule itself is tenant-agnostic but the trace is not."""


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SyntheticEvent:
    """One synthetic event used to validate the proposed rule.

    The agent always emits at least one positive (should match) and one
    negative (should NOT match) example. These are shipped in the
    GitOps PR so a reviewer can read the test events alongside the rule
    and see the intent without re-deriving it from the YAML.
    """

    label: Literal["positive", "negative"]
    description: str
    """Short prose explaining what the event represents."""
    payload: dict[str, Any]


@dataclass(frozen=True)
class SelfTestResult:
    """Verdict from running the generated rule against its synthetic events."""

    passed: bool
    """True iff every positive matched AND every negative did NOT match."""

    positives_total: int
    positives_matched: int
    negatives_total: int
    negatives_false_matched: int
    """Negatives that incorrectly matched — these are bugs."""

    failures: tuple[str, ...] = ()
    """Human-readable reasons for any failures. Empty if ``passed``."""


@dataclass(frozen=True)
class TranslationSet:
    """Multi-backend translations of the rule.

    ``errors`` records backends that failed to translate (e.g. because
    the rule used ``base64offset`` against Lucene). The HTTP response
    still includes the rule and the working translations — the agent
    doesn't refuse to propose a rule just because one backend can't
    express it.
    """

    splunk: Optional[str] = None
    kql: Optional[str] = None
    lucene: Optional[str] = None
    chronicle: Optional[str] = None
    """Google Chronicle UDM Search query. ``None`` if the backend can't
    express this rule (captured in ``errors['chronicle']``)."""
    chronicle_yaral: Optional[str] = None
    """Google Chronicle YARA-L 2.0 rule. Sibling to ``chronicle`` —
    UDM Search is interactive hunting syntax, YARA-L is the stored-rule
    syntax. We emit both so analysts can paste either into Chronicle
    without re-translating by hand."""
    errors: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class GitOpsArtifact:
    """Everything a downstream PR-builder needs to open a real PR.

    We materialize the PR as plain text rather than calling a Git
    library directly because:

    1. The platform may not have shell-out to git in every deployment
       (e.g. demo mode, sandbox).
    2. The PR text is what the analyst reviews in the HITL queue
       BEFORE we touch the source tree. Decoupling lets the reviewer
       see exactly what will be committed.

    Callers integrate via:
    - Writing ``files`` (path -> content) into a checkout
    - Switching to ``branch_name``
    - ``git commit -m commit_message``
    - Opening a PR with ``pr_title`` / ``pr_body``
    """

    branch_name: str
    """Slug-derived: ``detection-author/<rule-id>`` so it's idempotent."""

    commit_message: str
    pr_title: str
    pr_body: str
    """GitHub-flavored markdown including the diff narrative + test events."""

    files: dict[str, str]
    """Path → file contents. Paths are repo-relative POSIX strings."""


@dataclass(frozen=True)
class DetectionProposal:
    """The full output of one detection-author run."""

    rule_id: str
    """Slug-derived rule id, stable across iterations of the same title."""

    title: str
    yaml: str
    """Pretty-printed Sigma YAML, terminating with a single newline."""

    sigma_dict: dict[str, Any]
    """The parsed YAML as a dict; useful for callers that don't want
    to re-parse to introspect fields like ``logsource``."""

    translations: TranslationSet
    synthetic_events: tuple[SyntheticEvent, ...]
    self_test: SelfTestResult
    gitops: GitOpsArtifact
    extracted_techniques: tuple[str, ...]
    extracted_iocs: tuple[str, ...]
    """The actual MITRE / IOCs we used after extraction — may differ
    from what was passed in if hints were sparse."""

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection for the HTTP layer."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "yaml": self.yaml,
            "sigma": self.sigma_dict,
            "translations": {
                "splunk": self.translations.splunk,
                "kql": self.translations.kql,
                "lucene": self.translations.lucene,
                "chronicle": self.translations.chronicle,
                "chronicle_yaral": self.translations.chronicle_yaral,
                "errors": dict(self.translations.errors),
            },
            "synthetic_events": [
                {
                    "label": e.label,
                    "description": e.description,
                    "payload": e.payload,
                }
                for e in self.synthetic_events
            ],
            "self_test": {
                "passed": self.self_test.passed,
                "positives_total": self.self_test.positives_total,
                "positives_matched": self.self_test.positives_matched,
                "negatives_total": self.self_test.negatives_total,
                "negatives_false_matched": self.self_test.negatives_false_matched,
                "failures": list(self.self_test.failures),
            },
            "gitops": {
                "branch_name": self.gitops.branch_name,
                "commit_message": self.gitops.commit_message,
                "pr_title": self.gitops.pr_title,
                "pr_body": self.gitops.pr_body,
                "files": dict(self.gitops.files),
            },
            "extracted_techniques": list(self.extracted_techniques),
            "extracted_iocs": list(self.extracted_iocs),
        }
