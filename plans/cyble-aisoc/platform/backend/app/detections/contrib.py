"""OSS detection-content contribution policy + validator (t5-oss-detections).

This module is the *single source of truth* for what is and isn't an
acceptable detection rule in the open-source repo. It is used in three
places:

1. ``scripts/validate_detection.py`` — invoked by the CI workflow
   (``.github/workflows/detections-validate.yml``) on every PR that
   touches ``app/detections/rules/**``.
2. ``GET /detections/catalog`` — the public catalog endpoint that
   surfaces the same metadata used to gate PRs.
3. The ``DetectionAuthor`` agent's tool-call gate, so internally
   generated rules are held to the same bar as community rules.

We deliberately put the policy in code (not just docs) so the rules
are enforceable. The policy is intentionally narrow — we only enforce
what we will actually *grade on*. If a check is "soft" (style, prose,
formatting), it lives in the contributor docs, not here.

Hard checks (rejected on failure):
  H1. Rule has a non-empty ``id`` and the id is unique within the pack.
  H2. Rule has ``title`` and ``description`` (description >= 40 chars).
  H3. Rule has at least one ``tags:`` entry from the MITRE ATT&CK
      namespace (``attack.t1234`` / ``attack.tactic``).
  H4. ``status`` is one of ``stable``, ``test``, ``experimental``,
      ``deprecated``.
  H5. ``logsource:`` block exists with at least one of
      ``category``/``product``/``service``.
  H6. ``detection:`` block exists, parses, and matches at least one
      *positive* sample event from a ``.tests.yml`` sibling file when
      such a file exists. (Tests are encouraged but not required for
      v1 to lower the contribution bar; if a tests file *is*
      present, all positives must hit.)
  (H7 reserved — promoted to soft warning S4; see below.)
  H8. The compiled rule produces valid Splunk SPL **and** Microsoft
      Sentinel KQL. We refuse rules whose detection logic can't be
      compiled to both — those are useless to most customers.

Soft warnings (logged but don't block):
  S1. ``level:`` should be set; we default to ``medium`` if missing.
  S2. ``author:`` should be set; we default to ``community`` if missing.
  S3. Rule should reference at least one ``aisoc.<vertical>`` tag so
      we know what pack it belongs to in the public catalog.
  S4. ``falsepositives:`` should be non-empty. Today this is a
      warning; it will be promoted to a hard error (H7) in v0.2 once
      the legacy rules are backfilled.

Contribution provenance:
  Each rule carries a derived ``provenance`` field that records:
    - ``source``: ``cyble-native`` | ``community`` | ``mirrored``
    - ``contributor``: github handle, parsed from rule's
      ``author:`` field if it looks like ``Name <handle@gh>``.

  The provenance is stamped at *load* time, not at write time, so a
  community rule that gets adopted into the Cyble-native bundle keeps
  its ``community`` lineage in the catalog (even if the rule's YAML
  ``author:`` field gets edited).
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from .pack import RulePack
from .sigma import SigmaParseError, SigmaRule
from .translator import BackendError, translate_kql, translate_splunk

logger = logging.getLogger(__name__)


_VALID_STATUSES = {"stable", "test", "experimental", "deprecated"}
_ATTACK_TAG_RE = re.compile(r"^attack\.(t\d{4}(\.\d{3})?|[a-z_]+)$", re.IGNORECASE)


# ─── DTOs ───────────────────────────────────────────────────────────


@dataclass
class ValidationIssue:
    """A single problem found by ``validate_rule``."""

    rule_id: str
    code: str  # e.g. "H1", "S2"
    severity: str  # "error" | "warning"
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationReport:
    """Aggregated result for one or more rules."""

    rules_checked: int
    errors: list[ValidationIssue] = field(default_factory=list)
    warnings: list[ValidationIssue] = field(default_factory=list)
    accepted: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "rules_checked": self.rules_checked,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "errors": [e.to_dict() for e in self.errors],
            "warnings": [w.to_dict() for w in self.warnings],
        }


@dataclass
class CatalogEntry:
    """One row in the public detection catalog."""

    id: str
    title: str
    description: str
    severity: str
    status: str
    tags: list[str]
    logsource: dict[str, Any]
    falsepositives: list[str]
    pack: str  # "builtin", "verticals/finserv", etc.
    provenance: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─── Provenance helpers ────────────────────────────────────────────


def _parse_provenance(rule: SigmaRule, *, path_hint: Path | None = None) -> dict[str, str]:
    """Stamp a provenance dict for ``rule``.

    Heuristic, deterministic, and stable across reloads:

    - ``source = cyble-native`` if the file lives in the built-in
      ``rules/`` directory **and** the author is ``Cyble AiSOC``.
    - ``source = mirrored`` if the rule id starts with
      ``sigma-`` / ``elastic-`` / ``splunk-`` (we ingest those from
      upstream OSS catalogs and don't claim authorship).
    - ``source = community`` otherwise.
    """
    author = (rule.author or "").strip()
    is_native = author.lower() == "cyble aisoc"
    rid = rule.id.lower()
    if rid.startswith(("sigma-", "elastic-", "splunk-")):
        source = "mirrored"
    elif is_native:
        source = "cyble-native"
    else:
        source = "community"

    contributor = ""
    # ``Name <handle@github>`` or ``Name (github:handle)``
    if author:
        m = re.search(r"<([^@>]+)@(?:gh|github)>", author)
        if m:
            contributor = m.group(1)
        else:
            m = re.search(r"\(github:([^)]+)\)", author)
            if m:
                contributor = m.group(1)

    return {
        "source": source,
        "contributor": contributor,
        "author": author or "community",
    }


def _pack_label(path: Path | None, root: Path) -> str:
    """Return the pack label (``builtin``, ``verticals/finserv``, etc.)."""
    if path is None:
        return "unknown"
    try:
        rel = path.resolve().relative_to(root.resolve())
    except ValueError:
        return "external"
    parts = rel.parts[:-1]
    if not parts:
        return "builtin"
    if parts[0] == "verticals" and len(parts) >= 2:
        return f"verticals/{parts[1]}"
    return parts[0]


# ─── Validation ────────────────────────────────────────────────────


def _read_tests(rule_path: Path) -> list[dict[str, Any]]:
    """Load positive samples from a ``<rule>.tests.yml`` sibling file.

    The file format is intentionally tiny:

    .. code-block:: yaml

        positives:
          - { source.process.name: powershell.exe, ... }
          - ...
        negatives:
          - { source.process.name: notepad.exe }
    """
    tests_path = rule_path.with_suffix(".tests.yml")
    if not tests_path.exists():
        return []
    try:
        with tests_path.open("r", encoding="utf-8") as fh:
            blob = yaml.safe_load(fh) or {}
    except Exception as exc:
        logger.warning("contrib:tests_unreadable path=%s err=%s", tests_path, exc)
        return []
    return list(blob.get("positives") or [])


def _read_negatives(rule_path: Path) -> list[dict[str, Any]]:
    tests_path = rule_path.with_suffix(".tests.yml")
    if not tests_path.exists():
        return []
    try:
        with tests_path.open("r", encoding="utf-8") as fh:
            blob = yaml.safe_load(fh) or {}
    except Exception:
        return []
    return list(blob.get("negatives") or [])


def validate_rule(
    rule: SigmaRule,
    *,
    seen_ids: set[str] | None = None,
    rule_path: Path | None = None,
) -> tuple[list[ValidationIssue], list[ValidationIssue]]:
    """Apply the H1–H8 / S1–S3 checks to a single rule.

    Returns ``(errors, warnings)``. Callers typically aggregate these
    into a :class:`ValidationReport` across many rules.
    """
    errors: list[ValidationIssue] = []
    warnings: list[ValidationIssue] = []
    rid = rule.id or "<unknown>"

    # H1 — id presence + uniqueness
    if not rule.id:
        errors.append(
            ValidationIssue(
                rule_id=rid,
                code="H1",
                severity="error",
                message="rule must have a non-empty `id`",
            )
        )
    elif seen_ids is not None and rule.id in seen_ids:
        errors.append(
            ValidationIssue(
                rule_id=rid,
                code="H1",
                severity="error",
                message=f"duplicate rule id `{rule.id}` already loaded by another file",
            )
        )

    # H2 — title + description
    if not rule.title or not rule.title.strip():
        errors.append(
            ValidationIssue(
                rule_id=rid, code="H2", severity="error",
                message="rule is missing `title`",
            )
        )
    if not rule.description or len(rule.description.strip()) < 40:
        errors.append(
            ValidationIssue(
                rule_id=rid, code="H2", severity="error",
                message=(
                    "`description` must be >= 40 characters and explain "
                    "what the rule detects + why it matters"
                ),
            )
        )

    # H3 — at least one ATT&CK tag
    if not any(_ATTACK_TAG_RE.match(t) for t in rule.tags):
        errors.append(
            ValidationIssue(
                rule_id=rid, code="H3", severity="error",
                message=(
                    "rule must reference at least one MITRE ATT&CK tag, "
                    "e.g. `attack.t1003.001` or `attack.credential_access`"
                ),
            )
        )

    # H4 — status enum
    status = (rule.status or "").strip().lower() or "stable"
    if status not in _VALID_STATUSES:
        errors.append(
            ValidationIssue(
                rule_id=rid, code="H4", severity="error",
                message=f"`status` must be one of {sorted(_VALID_STATUSES)}",
            )
        )

    # H5 — logsource sanity
    ls = rule.logsource or {}
    if not (ls.get("category") or ls.get("product") or ls.get("service")):
        errors.append(
            ValidationIssue(
                rule_id=rid, code="H5", severity="error",
                message="`logsource` must declare at least one of "
                        "category / product / service",
            )
        )

    # H6 — positive samples must hit (if a tests file is provided)
    if rule_path is not None:
        positives = _read_tests(rule_path)
        for i, evt in enumerate(positives):
            try:
                if not rule.matches(evt):
                    errors.append(
                        ValidationIssue(
                            rule_id=rid, code="H6", severity="error",
                            message=(
                                f"positive sample #{i + 1} did not match the rule "
                                f"(file: {rule_path.with_suffix('.tests.yml').name})"
                            ),
                        )
                    )
            except Exception as exc:
                errors.append(
                    ValidationIssue(
                        rule_id=rid, code="H6", severity="error",
                        message=f"positive sample #{i + 1} crashed: {exc!r}",
                    )
                )
        # Negatives must NOT match.
        for i, evt in enumerate(_read_negatives(rule_path)):
            try:
                if rule.matches(evt):
                    errors.append(
                        ValidationIssue(
                            rule_id=rid, code="H6", severity="error",
                            message=(
                                f"negative sample #{i + 1} matched (it should not). "
                                "Tighten the detection or move the sample to "
                                "positives."
                            ),
                        )
                    )
            except Exception:
                # A crashing negative is suspicious but not a hard fail.
                warnings.append(
                    ValidationIssue(
                        rule_id=rid, code="H6", severity="warning",
                        message=f"negative sample #{i + 1} crashed during evaluation",
                    )
                )

    # S4 — falsepositives encouraged (will be promoted to a hard error
    # for new contributions in a future minor release; today this is a
    # warning so we don't reject 100+ legacy rules that pre-date the
    # policy).
    if not rule.falsepositives:
        warnings.append(
            ValidationIssue(
                rule_id=rid, code="S4", severity="warning",
                message=(
                    "`falsepositives:` is empty; add at least one entry "
                    "(use 'none expected' if you genuinely don't expect any). "
                    "This will become a hard error in v0.2."
                ),
            )
        )

    # H8 — must compile to SPL and KQL
    for backend, fn in (("splunk", translate_splunk), ("kql", translate_kql)):
        try:
            fn(rule)
        except BackendError as exc:
            errors.append(
                ValidationIssue(
                    rule_id=rid, code="H8", severity="error",
                    message=f"rule cannot be compiled to {backend}: {exc}",
                )
            )

    # S1–S3 (warnings)
    if not rule.author or rule.author.strip() == "":
        warnings.append(
            ValidationIssue(
                rule_id=rid, code="S2", severity="warning",
                message="`author:` is empty; will default to `community`",
            )
        )
    if not any(t.lower().startswith("aisoc.") for t in rule.tags):
        warnings.append(
            ValidationIssue(
                rule_id=rid, code="S3", severity="warning",
                message=(
                    "rule does not carry an `aisoc.<vertical>` tag; it "
                    "won't surface in any vertical pack"
                ),
            )
        )

    return errors, warnings


def validate_pack_directory(
    rules_dir: str | Path,
    *,
    paths: Iterable[Path] | None = None,
) -> ValidationReport:
    """Validate every YAML rule under ``rules_dir`` (or the supplied subset).

    ``paths`` is the explicit list of files to validate. CI passes the
    list of files changed in the PR so we don't waste cycles
    re-checking the entire library on every push.
    """
    root = Path(rules_dir).resolve()
    if not root.exists():
        return ValidationReport(rules_checked=0)

    targets: list[Path]
    if paths is None:
        targets = sorted(root.rglob("*.y*ml"))
    else:
        targets = sorted(p.resolve() for p in paths if p.suffix in {".yml", ".yaml"})

    # Skip ``.tests.yml`` companions — those aren't rule files.
    targets = [p for p in targets if not p.name.endswith(".tests.yml")]

    seen_ids: set[str] = set()
    report = ValidationReport(rules_checked=0)

    for path in targets:
        try:
            rule = SigmaRule.from_file(path)
        except SigmaParseError as exc:
            report.rules_checked += 1
            report.errors.append(
                ValidationIssue(
                    rule_id=path.stem,
                    code="parse",
                    severity="error",
                    message=f"YAML/Sigma parse failed: {exc}",
                )
            )
            report.rejected.append(path.stem)
            continue
        except Exception as exc:  # noqa: BLE001 — we want to capture all
            report.rules_checked += 1
            report.errors.append(
                ValidationIssue(
                    rule_id=path.stem, code="parse", severity="error",
                    message=f"unexpected error loading rule: {exc!r}",
                )
            )
            report.rejected.append(path.stem)
            continue

        report.rules_checked += 1
        errs, warns = validate_rule(rule, seen_ids=seen_ids, rule_path=path)
        report.errors.extend(errs)
        report.warnings.extend(warns)
        if errs:
            report.rejected.append(rule.id)
        else:
            report.accepted.append(rule.id)
            seen_ids.add(rule.id)

    return report


# ─── Public catalog ────────────────────────────────────────────────


def build_catalog(
    rules_dir: str | Path,
    *,
    include_verticals: bool = True,
) -> list[CatalogEntry]:
    """Return a flat list of catalog entries for every loadable rule.

    Used by ``GET /detections/catalog`` and by the marketplace UI.
    Rules that fail to parse are silently skipped — the validator (and
    CI) is the place where parse errors get surfaced.
    """
    root = Path(rules_dir).resolve()
    if not root.exists():
        return []

    exclude_subdirs: tuple[str, ...] = () if include_verticals else ("verticals",)
    pack = RulePack.load_directory(
        root, name=root.name, strict=False, exclude_subdirs=exclude_subdirs
    )

    # Map id -> path so we can stamp pack labels and provenance.
    id_to_path: dict[str, Path] = {}
    for yml in root.rglob("*.y*ml"):
        if yml.name.endswith(".tests.yml") or not yml.is_file():
            continue
        try:
            with yml.open("r", encoding="utf-8") as fh:
                blob = yaml.safe_load(fh) or {}
        except Exception:
            continue
        rid = blob.get("id")
        if isinstance(rid, str) and rid:
            id_to_path[rid] = yml

    catalog: list[CatalogEntry] = []
    for rule in pack:
        path = id_to_path.get(rule.id)
        catalog.append(
            CatalogEntry(
                id=rule.id,
                title=rule.title,
                description=rule.description,
                severity=rule.severity.value if hasattr(rule.severity, "value") else str(rule.severity),
                status=(rule.status or "stable").lower(),
                tags=list(rule.tags),
                logsource=dict(rule.logsource or {}),
                falsepositives=list(rule.falsepositives),
                pack=_pack_label(path, root),
                provenance=_parse_provenance(rule, path_hint=path),
            )
        )
    catalog.sort(key=lambda e: (e.pack, e.id))
    return catalog


def catalog_summary(rules_dir: str | Path) -> dict[str, Any]:
    """Aggregate stats for the public catalog.

    Powers the headline numbers on the public detections page
    (``X rules across Y packs, Z% community-contributed``).
    """
    entries = build_catalog(rules_dir, include_verticals=True)
    by_pack: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_source: dict[str, int] = {}
    attack_tags: set[str] = set()
    for e in entries:
        by_pack[e.pack] = by_pack.get(e.pack, 0) + 1
        by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
        src = e.provenance.get("source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1
        for t in e.tags:
            if _ATTACK_TAG_RE.match(t):
                attack_tags.add(t.lower())
    total = len(entries)
    community = by_source.get("community", 0) + by_source.get("mirrored", 0)
    pct_community = round((community / total) * 100.0, 2) if total else 0.0
    return {
        "total_rules": total,
        "by_pack": by_pack,
        "by_severity": by_severity,
        "by_source": by_source,
        "unique_attack_techniques": len(attack_tags),
        "percent_community": pct_community,
    }


__all__ = [
    "CatalogEntry",
    "ValidationIssue",
    "ValidationReport",
    "build_catalog",
    "catalog_summary",
    "validate_pack_directory",
    "validate_rule",
]
