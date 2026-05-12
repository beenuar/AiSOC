#!/usr/bin/env python3
"""Build the Splunk-imports quarantine README index.

The repository ships **1,989 raw Splunk SPL rules** under
``detections/splunk-imports/_quarantine/`` (Stage 2 #4 in the AiSOC
community roadmap). They are checked in so the import lineage is
auditable, but they cannot be executed by the AiSOC engine until the SPL
is translated into the AiSOC detection schema. Without an index they
form a 1,989-line ``ls`` and contributors don't know:

  - what categories the quarantine spans (endpoint vs cloud vs network),
  - which rules are *production* vs *experimental* upstream,
  - which MITRE techniques are over- and under-represented,
  - or which umbrella tracking issue they should reference when they
    open a translation PR.

This script walks every YAML in
``detections/splunk-imports/_quarantine/`` and writes a single
``README.md`` in that directory with:

  - a top-level summary table (count by ``tags.categories`` bucket),
  - a translation-tracking-issue mapping (one umbrella issue per
    category — the IDs live in ``QUARANTINE_TRACKING_ISSUES`` below
    and are surfaced as ``TBD`` placeholders if not yet wired up),
  - a "how to translate" contributor workflow, including the CI gate
    contract,
  - per-category sub-sections with top MITRE techniques and a folded
    full rule listing (rule name → file → splunk_status → MITRE).

The script also carries a ``--check`` mode for CI: it regenerates the
README in memory and compares it against the on-disk file. Any drift
fails with exit code 2, so PRs that add new quarantined rules without
running the generator are caught early.

Usage::

    python3 scripts/build_quarantine_index.py            # write README
    python3 scripts/build_quarantine_index.py --check    # CI: verify
    python3 scripts/build_quarantine_index.py --print    # stdout only

Exit codes:
    0 — README is on disk and current (or was successfully written)
    2 — drift: ``--check`` and on-disk README disagree
"""

from __future__ import annotations

import argparse
import collections
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
QUARANTINE_DIR = REPO_ROOT / "detections" / "splunk-imports" / "_quarantine"
README_PATH = QUARANTINE_DIR / "README.md"

# Canonical category order used in tables and section headers.
# Matches the four buckets surfaced by ``tags.categories`` across the
# 1,989 quarantined rules.
CATEGORIES = ["endpoint", "cloud", "application", "network"]

# Maintainers wire the umbrella translation tracking issues here. Each
# category has one umbrella issue contributors reference when they open
# a translation PR. ``None`` renders as ``TBD`` in the README and the
# CI gate falls back to "any ``#NNN`` issue reference is accepted" until
# the maintainers fill these in. See ``.github/workflows/quarantine-tracker.yml``.
QUARANTINE_TRACKING_ISSUES: dict[str, int | None] = {
    "endpoint": None,
    "cloud": None,
    "application": None,
    "network": None,
}

# Categories not present in CATEGORIES bucket into "other".
OTHER_BUCKET = "other"

# Top-N MITRE techniques surfaced per-category in the README.
TOP_MITRE_PER_CATEGORY = 10


@dataclass(frozen=True)
class QuarantineRule:
    """One quarantined rule, normalised for the index."""

    file_name: str
    rule_id: str
    name: str
    severity: str
    splunk_status: str
    categories: tuple[str, ...]
    mitre: tuple[str, ...]
    quarantine_reason: str
    primary_category: str = field(init=False)

    def __post_init__(self) -> None:
        # First category in CATEGORIES order that the rule has, else "other".
        primary = OTHER_BUCKET
        for cat in CATEGORIES:
            if cat in self.categories:
                primary = cat
                break
        # frozen dataclass workaround
        object.__setattr__(self, "primary_category", primary)


def _load_rule(path: Path) -> QuarantineRule | None:
    """Parse one quarantined rule YAML; skip on YAML or schema errors."""
    try:
        with path.open() as handle:
            doc = yaml.safe_load(handle) or {}
    except yaml.YAMLError as exc:
        print(f"warning: skipping {path.name}: YAML error: {exc}", file=sys.stderr)
        return None

    if not isinstance(doc, dict):
        return None

    tags = doc.get("tags") or {}
    notes = doc.get("notes") or {}

    categories = tags.get("categories") or []
    # Top-level technique IDs only — strip sub-technique suffixes for
    # a cleaner top-N list. Preserves order, dedupes.
    seen: set[str] = set()
    mitre: list[str] = []
    for tag in tags.get("mitre") or []:
        if not isinstance(tag, str):
            continue
        top = tag.split(".", 1)[0]
        if top not in seen:
            seen.add(top)
            mitre.append(top)

    return QuarantineRule(
        file_name=path.name,
        rule_id=str(doc.get("id", "")),
        name=str(doc.get("name", path.stem)),
        severity=str(doc.get("severity", "")),
        splunk_status=str(notes.get("splunk_status", "unknown")),
        categories=tuple(c for c in categories if isinstance(c, str)),
        mitre=tuple(mitre),
        quarantine_reason=str(doc.get("quarantine_reason", "")),
    )


def _load_quarantine() -> list[QuarantineRule]:
    rules: list[QuarantineRule] = []
    for path in sorted(QUARANTINE_DIR.glob("*.yaml")):
        rule = _load_rule(path)
        if rule is not None:
            rules.append(rule)
    return rules


def _issue_link(category: str) -> str:
    issue = QUARANTINE_TRACKING_ISSUES.get(category)
    if issue is None:
        return "**TBD** — umbrella issue not yet filed"
    return f"[#{issue}](https://github.com/beenuar/AiSOC/issues/{issue})"


def _render_summary_table(by_cat: dict[str, list[QuarantineRule]]) -> list[str]:
    lines = [
        "| Category | Quarantined rules | Production | Experimental | Translation tracking issue |",
        "| --- | ---: | ---: | ---: | --- |",
    ]
    total = total_prod = total_exp = 0
    for cat in CATEGORIES + [OTHER_BUCKET]:
        rules = by_cat.get(cat, [])
        if not rules:
            continue
        prod = sum(1 for r in rules if r.splunk_status == "production")
        exp = sum(1 for r in rules if r.splunk_status == "experimental")
        total += len(rules)
        total_prod += prod
        total_exp += exp
        link = _issue_link(cat) if cat in QUARANTINE_TRACKING_ISSUES else "n/a"
        lines.append(f"| `{cat}` | {len(rules):,} | {prod:,} | {exp:,} | {link} |")
    lines.append(f"| **Total** | **{total:,}** | **{total_prod:,}** | **{total_exp:,}** |  |")
    return lines


def _render_mitre_lines(rules: Iterable[QuarantineRule]) -> list[str]:
    counter: collections.Counter[str] = collections.Counter()
    for r in rules:
        for technique in r.mitre:
            counter[technique] += 1
    if not counter:
        return ["_(No MITRE technique tags on the rules in this category.)_"]
    out = []
    for technique, count in counter.most_common(TOP_MITRE_PER_CATEGORY):
        out.append(
            f"- [`{technique}`](https://attack.mitre.org/techniques/{technique}/) "
            f"— {count:,} rule{'s' if count != 1 else ''}"
        )
    extra = len(counter) - TOP_MITRE_PER_CATEGORY
    if extra > 0:
        out.append(f"- _… and {extra:,} more techniques._")
    return out


def _render_rule_table(rules: list[QuarantineRule]) -> list[str]:
    lines = [
        "| Rule | File | Splunk status | Severity | MITRE |",
        "| --- | --- | --- | --- | --- |",
    ]
    for rule in sorted(rules, key=lambda r: r.name.lower()):
        mitre = ", ".join(f"`{t}`" for t in rule.mitre[:5])
        if len(rule.mitre) > 5:
            mitre += f", _+{len(rule.mitre) - 5}_"
        if not mitre:
            mitre = "_n/a_"
        # Escape pipe characters in rule name to avoid breaking the table
        safe_name = rule.name.replace("|", "\\|")
        lines.append(
            f"| {safe_name} | [`{rule.file_name}`](./{rule.file_name}) "
            f"| `{rule.splunk_status}` | `{rule.severity or 'n/a'}` | {mitre} |"
        )
    return lines


def render_readme(rules: list[QuarantineRule]) -> str:
    by_cat: dict[str, list[QuarantineRule]] = collections.defaultdict(list)
    for rule in rules:
        by_cat[rule.primary_category].append(rule)

    lines: list[str] = []
    lines.append("# Splunk-imports — quarantined rules")
    lines.append("")
    lines.append(
        f"This directory holds **{len(rules):,} raw Splunk Enterprise Security rules** "
        "imported from public detection content. They ship **disabled** "
        "(`enabled: false`) and the AiSOC engine intentionally skips them at "
        "runtime — see [`detections/README.md`](../../README.md#tier-3-quarantined) "
        "for the tier definition."
    )
    lines.append("")
    lines.append(
        "**Why they're in the repo at all.** Detection content is the most "
        "valuable artefact a SOC owns, so we'd rather check the upstream "
        "lineage in (with attribution and `quarantine_reason`) than silently "
        "drop it. Translating these rules into native AiSOC detections is a "
        "long-running community workstream tracked through this index."
    )
    lines.append("")
    lines.append(
        "> ⚠️ **This file is auto-generated by "
        "[`scripts/build_quarantine_index.py`](../../../scripts/build_quarantine_index.py). "
        "Do not edit by hand — re-run the script and commit the result.**"
    )
    lines.append("")

    lines.append("## At a glance")
    lines.append("")
    lines.extend(_render_summary_table(by_cat))
    lines.append("")
    lines.append(
        "Categories come from the `tags.categories` field on each rule. "
        "`production` vs `experimental` reflects the upstream "
        "`notes.splunk_status` carried over from Splunk ES."
    )
    lines.append("")

    lines.append("## How to translate a rule")
    lines.append("")
    lines.append(
        "1. **Pick a rule** from one of the per-category sections below. "
        "Lower-severity, single-technique rules are the gentlest place to start."
    )
    lines.append(
        "2. **Read the existing YAML** in this directory. The Splunk SPL is "
        "captured under `detection.splunk_spl`; the metadata (MITRE, severity, "
        "category, references) is already populated."
    )
    lines.append(
        "3. **Re-author the detection** under the right native bucket "
        "(`detections/<category>/`) using the AiSOC schema documented in "
        "[`apps/docs/docs/detections/`](../../../apps/docs/docs/detections/). "
        "Map the SPL search to the AiSOC OCSF stream — usually a "
        "`logsource` + `detection.condition` block. Carry the original "
        "`provenance.upstream_path` over so attribution is preserved."
    )
    lines.append(
        "4. **Add fixtures** under `detections/fixtures/positive/<rule-id>.json` "
        "and `detections/fixtures/negative/<rule-id>.json`. "
        "[`scripts/validate_detections.py --strict-fixtures`](../../../scripts/validate_detections.py) "
        "will refuse to merge a rule that ships without both."
    )
    lines.append(
        "5. **Delete the quarantined file** as part of the same PR — the rule "
        "now lives in the native tier and the quarantine entry is no longer "
        "the source of truth."
    )
    lines.append(
        "6. **Re-run** `python3 scripts/build_quarantine_index.py` to regenerate "
        "this index, then commit the README delta with your translation. CI "
        "verifies the index is in sync (`--check` mode)."
    )
    lines.append("")

    lines.append("## CI gate")
    lines.append("")
    lines.append(
        "[`.github/workflows/quarantine-tracker.yml`](../../../.github/workflows/quarantine-tracker.yml) "
        "runs on every push and pull request that touches "
        "`detections/splunk-imports/_quarantine/**` or the generator script, "
        "and enforces a single hard rule:"
    )
    lines.append("")
    lines.append(
        "- **Index stays current.** The workflow runs "
        "`python3 scripts/build_quarantine_index.py --check`. If the on-disk "
        "README disagrees with the regenerated output, the job fails and "
        "prints a diff against the stale file. Re-run the generator locally "
        "and commit the regenerated README to make CI green."
    )
    lines.append("")
    lines.append(
        "Two soft conventions sit on top of the gate (not machine-enforced "
        "today, but expected for translation PRs):"
    )
    lines.append("")
    lines.append(
        "- **Reference an umbrella tracking issue.** When you translate a "
        "quarantined rule, link the umbrella issue for that category in your "
        "PR body (see the table above). One issue per category, not per "
        "rule."
    )
    lines.append(
        "- **Translations remove their quarantine entry.** The happy path is "
        "*delete* a row from this index in the same PR that adds the native "
        "AiSOC detection. New quarantine entries should be rare and should "
        "explain in the PR body why translation isn't viable yet."
    )
    lines.append("")

    lines.append("## Inventory by category")
    lines.append("")

    for cat in CATEGORIES + [OTHER_BUCKET]:
        cat_rules = by_cat.get(cat, [])
        if not cat_rules:
            continue
        link = _issue_link(cat) if cat in QUARANTINE_TRACKING_ISSUES else "n/a"
        lines.append(f"### `{cat}` ({len(cat_rules):,} rules)")
        lines.append("")
        lines.append(f"**Translation tracking issue:** {link}")
        lines.append("")
        lines.append("**Top MITRE techniques represented:**")
        lines.append("")
        lines.extend(_render_mitre_lines(cat_rules))
        lines.append("")
        lines.append(f"<details><summary>Full rule list ({len(cat_rules):,} rules)</summary>")
        lines.append("")
        lines.extend(_render_rule_table(cat_rules))
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "_Generated by `scripts/build_quarantine_index.py`. "
        f"Source: {len(rules):,} YAML rules in this directory._"
    )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the on-disk README matches the regenerated index. CI uses this.",
    )
    parser.add_argument(
        "--print",
        dest="print_only",
        action="store_true",
        help="Render the README to stdout without touching the filesystem.",
    )
    args = parser.parse_args(argv)

    rules = _load_quarantine()
    if not rules:
        print(
            f"error: no rules found under {QUARANTINE_DIR.relative_to(REPO_ROOT)}",
            file=sys.stderr,
        )
        return 1

    rendered = render_readme(rules)

    if args.print_only:
        sys.stdout.write(rendered)
        return 0

    if args.check:
        if not README_PATH.exists():
            print(
                f"error: {README_PATH.relative_to(REPO_ROOT)} is missing — "
                "run `python3 scripts/build_quarantine_index.py` and commit the result.",
                file=sys.stderr,
            )
            return 2
        on_disk = README_PATH.read_text()
        if on_disk != rendered:
            print(
                f"error: {README_PATH.relative_to(REPO_ROOT)} is out of date — "
                "re-run `python3 scripts/build_quarantine_index.py` and commit "
                "the regenerated README.",
                file=sys.stderr,
            )
            return 2
        print(f"ok: {README_PATH.relative_to(REPO_ROOT)} is in sync ({len(rules):,} rules indexed).")
        return 0

    README_PATH.write_text(rendered)
    print(
        f"wrote {README_PATH.relative_to(REPO_ROOT)} "
        f"({len(rules):,} rules indexed, {len(rendered):,} bytes)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
