"""Materialize a ``GitOpsArtifact`` from a generated Sigma rule.

This is the last stage of the detection-author pipeline. It produces
the plain-text inputs a downstream PR-builder (or a human) needs:

- the file path inside the repo where the YAML should land
- a stable branch name derived from the rule id (so re-runs update
  the same PR rather than spawning duplicates)
- a commit message and a GitHub-flavored markdown PR body that
  includes the synthetic events, the self-test verdict, and the
  multi-backend translations so reviewers see *everything* the
  generator considered, in one place.

We never shell out to ``git`` here on purpose — see ``models.py`` for
the rationale. The caller decides whether to apply the diff locally
or hand it to a GitHub bot.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from .models import (
    GitOpsArtifact,
    SelfTestResult,
    SyntheticEvent,
    ThreatReport,
    TranslationSet,
)

# --------------------------------------------------------------------------- #
# Where the rule lands inside the repo
# --------------------------------------------------------------------------- #


# Logsource (product/service/category) → rules subdirectory. We mirror
# the layout already used by the built-in rule pack
# (``app/detections/rules/{endpoint,identity,cloud,email,network,webserver}``)
# so the detection-author drops files where reviewers expect to find
# them.
_RULES_BASE = "platform/backend/app/detections/rules"


def _rules_subdir(logsource: dict[str, str]) -> str:
    """Pick the rules/ subdirectory that matches this rule's logsource.

    The mapping is intentionally a small switch table rather than a
    big regex — the categories are stable and adding a new one should
    be a deliberate review decision, not an accidental regex match.
    """
    product = (logsource.get("product") or "").lower()
    service = (logsource.get("service") or "").lower()
    category = (logsource.get("category") or "").lower()

    if product in {"okta", "azure", "google_workspace", "duo"}:
        return "identity"
    if product == "windows" and service == "security":
        # AD / domain-controller security log → identity, not endpoint
        return "identity"
    if product in {"aws", "gcp", "azure_arm"} or service in {"cloudtrail", "guardduty"}:
        return "cloud"
    if product in {"m365", "slack", "github", "google_workspace"} and service in {
        "audit",
        "exchange",
    }:
        return "email" if service == "exchange" else "identity"
    if product in {"crowdstrike", "sentinelone", "windows", "linux", "macos"}:
        return "endpoint"
    if product in {"zeek", "suricata"} or category in {"dns", "firewall", "proxy"}:
        return "network"
    if category in {"webserver", "web"}:
        return "webserver"
    # Default bucket for anything we can't classify — endpoint is the
    # most common landing zone for new generic rules.
    return "endpoint"


def _file_path_for(rule_id: str, logsource: dict[str, str]) -> str:
    """Compute the repo-relative POSIX path for the rule's YAML file.

    The filename strips the ``aisoc-author-`` prefix from the rule id
    so the on-disk name stays readable; the prefix lives inside the
    YAML as ``id:`` and that's what makes the rule globally unique.
    """
    sub = _rules_subdir(logsource)
    name = rule_id
    if name.startswith("aisoc-author-"):
        name = name[len("aisoc-author-"):]
    if not name:
        name = "untitled"
    return f"{_RULES_BASE}/{sub}/{name}.yml"


# --------------------------------------------------------------------------- #
# PR body
# --------------------------------------------------------------------------- #


def _format_events_markdown(events: tuple[SyntheticEvent, ...]) -> str:
    """Render the synthetic events as a fenced markdown block."""
    if not events:
        return "_No synthetic events generated._\n"
    parts: list[str] = []
    for ev in events:
        parts.append(f"**{ev.label.upper()}** — {ev.description}\n")
        parts.append("```json")
        parts.append(json.dumps(ev.payload, indent=2, sort_keys=True))
        parts.append("```")
    return "\n".join(parts) + "\n"


def _format_translations_markdown(t: TranslationSet) -> str:
    """Render the multi-backend translations as readable markdown.

    Each entry is ``(display_label, value, error_key)`` so the error
    lookup never has to guess from a fragment of the display label
    (which broke when Chronicle's label contains two backends). The
    ``error_key`` is the canonical key on ``TranslationSet.errors``.
    """
    lines: list[str] = []
    backends: tuple[tuple[str, Optional[str], str], ...] = (
        ("Splunk SPL", t.splunk, "splunk"),
        ("Microsoft KQL", t.kql, "kql"),
        ("Elastic Lucene", t.lucene, "lucene"),
        ("Google Chronicle UDM Search", t.chronicle, "chronicle"),
        ("Google Chronicle YARA-L 2.0", t.chronicle_yaral, "chronicle_yaral"),
    )
    for backend, value, error_key in backends:
        lines.append(f"#### {backend}")
        if value:
            lines.append("```")
            lines.append(value.strip())
            lines.append("```")
        else:
            reason = t.errors.get(error_key) or "translation unavailable"
            lines.append(f"_{reason}_")
        lines.append("")
    return "\n".join(lines)


def _format_self_test_markdown(st: SelfTestResult) -> str:
    """Render the self-test verdict as readable markdown."""
    status = "PASS" if st.passed else "FAIL"
    out = [
        f"**Self-test: {status}**",
        "",
        f"- Positives: {st.positives_matched}/{st.positives_total} matched",
        f"- Negatives: {st.negatives_false_matched}/{st.negatives_total} falsely matched",
    ]
    if st.failures:
        out.append("")
        out.append("**Failures:**")
        for f in st.failures:
            out.append(f"- {f}")
    return "\n".join(out) + "\n"


def _format_pr_body(
    *,
    report: ThreatReport,
    rule_id: str,
    yaml_text: str,
    events: tuple[SyntheticEvent, ...],
    self_test: SelfTestResult,
    translations: TranslationSet,
    techniques: tuple[str, ...],
    iocs: tuple[str, ...],
) -> str:
    """Compose the full GitHub-flavored PR body for the new rule.

    The structure is fixed so reviewers can skim the same sections in
    the same order across every detection-author PR. Anchor links in
    the body would be nice but GitHub strips anchors with non-ASCII
    chars so we keep it linear.
    """
    techniques_md = ", ".join(f"`{t}`" for t in techniques) if techniques else "_none extracted_"
    iocs_md = ", ".join(f"`{i}`" for i in iocs) if iocs else "_none extracted_"
    parts = [
        f"## Detection Author — `{rule_id}`",
        "",
        "_Auto-generated by Cyble AiSOC Detection Author Agent. Review the synthetic test events and self-test verdict before merging._",
        "",
        "### Threat narrative",
        "",
        "> " + report.narrative.strip().replace("\n", "\n> "),
        "",
        "### Extracted signal",
        "",
        f"- **MITRE ATT&CK:** {techniques_md}",
        f"- **IOCs:** {iocs_md}",
        f"- **Severity:** `{(report.severity or 'auto').lower()}`",
        f"- **Author:** {report.author}",
        "",
        "### Sigma rule",
        "",
        "```yaml",
        yaml_text.rstrip(),
        "```",
        "",
        "### Synthetic test events",
        "",
        _format_events_markdown(events),
        "### Self-test",
        "",
        _format_self_test_markdown(self_test),
        "### Backend translations",
        "",
        _format_translations_markdown(translations),
    ]
    return "\n".join(parts).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# Top-level builder
# --------------------------------------------------------------------------- #


def build_artifact(
    *,
    report: ThreatReport,
    rule_id: str,
    title: str,
    yaml_text: str,
    sigma_dict: dict[str, Any],
    events: tuple[SyntheticEvent, ...],
    self_test: SelfTestResult,
    translations: TranslationSet,
    techniques: tuple[str, ...],
    iocs: tuple[str, ...],
) -> GitOpsArtifact:
    """Build a fully-populated ``GitOpsArtifact``.

    The artifact is self-contained: ``files`` includes both the YAML
    and a sibling ``.tests.json`` carrying the synthetic events, so a
    reviewer browsing the PR sees the rule and its acceptance tests
    side-by-side.
    """
    logsource = dict(sigma_dict.get("logsource") or {})
    yml_path = _file_path_for(rule_id, logsource)
    tests_path = yml_path.rsplit(".", 1)[0] + ".tests.json"

    tests_blob = json.dumps(
        {
            "rule_id": rule_id,
            "events": [
                {"label": e.label, "description": e.description, "payload": e.payload}
                for e in events
            ],
        },
        indent=2,
        sort_keys=True,
    ) + "\n"

    files = {
        yml_path: yaml_text,
        tests_path: tests_blob,
    }

    branch_name = f"detection-author/{rule_id}"
    commit_message = (
        f"feat(detections): add {rule_id}\n"
        f"\n"
        f"{title}\n"
        f"\n"
        f"Auto-generated by Cyble AiSOC Detection Author Agent.\n"
    )
    pr_title = f"[detection-author] {title}"
    pr_body = _format_pr_body(
        report=report,
        rule_id=rule_id,
        yaml_text=yaml_text,
        events=events,
        self_test=self_test,
        translations=translations,
        techniques=techniques,
        iocs=iocs,
    )

    return GitOpsArtifact(
        branch_name=branch_name,
        commit_message=commit_message,
        pr_title=pr_title,
        pr_body=pr_body,
        files=files,
    )
