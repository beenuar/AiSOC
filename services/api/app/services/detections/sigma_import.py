"""Bulk Sigma import pipeline (WS-B1).

This module is the in-process counterpart to the offline batch importer in
``tools/detection_import/sigma_importer.py``. The offline importer writes
YAML files into ``detections/sigma-imports/`` for code review and
fixture-testing; this service ingests those same Sigma rules straight
into the runtime ``detection_rules`` table so a tenant can opt into the
community corpus without redeploying.

The pipeline does four things, in order, for every input rule:

1. **Validate** the upstream rule has the minimum fields a Sigma
   rule needs to be useful (``id``, ``title``, ``detection``).
2. **Auto-map** the Sigma ``logsource`` block to an OCSF v1.1 class so
   coverage queries can talk OCSF without re-parsing rules. See
   :mod:`app.services.detections.ocsf_mapping`.
3. **Extract** MITRE ATT&CK tactics and technique IDs from the Sigma
   ``tags:`` block. We canonicalise to upper-case (``T1078``) and we
   don't invent technique IDs from descriptions — if the upstream
   maintainer didn't tag it, we leave it untagged.
4. **Persist** with full provenance: source repo, upstream id, commit
   SHA, license, importer name, and import timestamp. The
   ``(source, source_id)`` pair makes re-imports idempotent: the same
   upstream rule across two import runs becomes ``UPDATE``, not a
   duplicate ``INSERT``.

The hand-off boundary is deliberate: a future API endpoint can call
:func:`import_sigma_rules` with a list of pre-parsed dicts and stay out
of the YAML-reading business. CLI plumbing (cloning the SigmaHQ repo,
walking files) lives in the orchestrator under ``tools/``.

Design constraints worth flagging for future maintainers:

* We never raise on a single bad rule — community Sigma quality varies
  wildly and one broken rule shouldn't abort an import of 2000+. Each
  failure is captured in :class:`SigmaImportReport.failures` for the
  caller to surface.
* We do not call ``rule_engine`` to validate the detection block at
  import time. Sigma's grammar is too loose to catch every runtime
  failure statically, and pySigma compilation is slow enough that
  doing it for every rule blows the import budget. Runtime evaluation
  errors surface in the alert pipeline with the rule id intact.
* Provenance is stored as JSONB and indexed on
  ``(source, source_id)`` — see migration
  ``036_detection_rule_provenance.sql``. Don't try to cram it into
  ``tags`` or ``suppression_config``; those are tenant-mutable.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection_rule import DetectionRule
from app.services.detections.ocsf_mapping import OcsfClassRef, map_logsource_to_ocsf

logger = logging.getLogger(__name__)


# ─── Public types ────────────────────────────────────────────────────────────


class SigmaImportError(Exception):
    """Raised for errors that should abort the entire import run.

    Per-rule failures are captured in :class:`SigmaImportReport.failures`
    and don't raise — see the module docstring for rationale.
    """


@dataclass(frozen=True, slots=True)
class SigmaImportResult:
    """The outcome for a single Sigma rule.

    ``rule_id`` is the AiSOC ``detection_rules.id`` (a UUID).
    ``source_id`` is the upstream Sigma rule id (also a UUID, but
    that's a coincidence — for non-Sigma sources it could be
    ``CAR-2021-04-001`` etc.).
    """

    rule_id: uuid.UUID
    source: str
    source_id: str
    title: str
    action: str  # "inserted" | "updated" | "skipped"
    reason: str | None = None  # for skipped/updated: human-readable why


@dataclass(slots=True)
class SigmaImportReport:
    """Aggregate report from one :func:`import_sigma_rules` call.

    The shape mirrors what we want to surface in the import endpoint
    response and in CLI output, so callers don't have to reshape it.
    """

    inserted: list[SigmaImportResult] = field(default_factory=list)
    updated: list[SigmaImportResult] = field(default_factory=list)
    skipped: list[SigmaImportResult] = field(default_factory=list)
    failures: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total_seen(self) -> int:
        return len(self.inserted) + len(self.updated) + len(self.skipped) + len(self.failures)

    @property
    def total_persisted(self) -> int:
        return len(self.inserted) + len(self.updated)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dict for API responses."""
        return {
            "summary": {
                "total_seen": self.total_seen,
                "inserted": len(self.inserted),
                "updated": len(self.updated),
                "skipped": len(self.skipped),
                "failures": len(self.failures),
            },
            "inserted": [_result_to_dict(r) for r in self.inserted],
            "updated": [_result_to_dict(r) for r in self.updated],
            "skipped": [_result_to_dict(r) for r in self.skipped],
            "failures": self.failures,
        }


def _result_to_dict(r: SigmaImportResult) -> dict[str, Any]:
    return {
        "rule_id": str(r.rule_id),
        "source": r.source,
        "source_id": r.source_id,
        "title": r.title,
        "action": r.action,
        "reason": r.reason,
    }


# ─── Status / quarantine policy ──────────────────────────────────────────────
#
# These mirror the offline importer's policy in
# ``tools/detection_import/sigma_importer.py`` — keep them in sync. The
# AiSOC ``status`` column maps loosely to detection lifecycle: ``testing``
# is the conservative default for community-imported content.

# Sigma statuses that we drop entirely.
_SIGMA_SKIP_STATUSES = frozenset({"deprecated", "unsupported"})

# Sigma statuses that get imported but disabled-by-default. Operators
# can flip them on once they've vetted the upstream rule.
_SIGMA_QUARANTINE_STATUSES = frozenset({"experimental", "test"})

# Severity normalisation. Sigma uses ``level``; we normalise to AiSOC's
# four-tier ``severity`` ladder. Anything we don't recognise becomes
# ``medium`` — never ``critical`` (would be a foot-gun for paging).
_SEVERITY_MAP: dict[str, str] = {
    "informational": "low",
    "info": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


# ─── Tag / category helpers ──────────────────────────────────────────────────


def _extract_mitre_techniques(tags: list[Any] | None) -> list[str]:
    """Pull MITRE ATT&CK technique IDs from a Sigma ``tags`` list.

    Sigma uses ``attack.t1078`` and ``attack.t1078.004`` style tags;
    we canonicalise to upper-case (``T1078``) and dedupe while
    preserving the order the upstream maintainer chose.

    We only recognise the ``attack.t<digits>(.subtechnique)?`` shape.
    Free-form tags like ``attack.persistence`` are *tactics*, handled
    separately by :func:`_extract_mitre_tactics`.
    """
    if not tags:
        return []

    out: list[str] = []
    seen: set[str] = set()
    for tag in tags:
        if not isinstance(tag, str):
            continue
        normalised = tag.strip().lower()
        if not normalised.startswith("attack.t"):
            continue
        # ``attack.t1078`` -> ``t1078``; ``attack.t1078.004`` stays.
        parts = normalised.split(".", 1)
        if len(parts) != 2:
            continue
        technique = parts[1].upper()
        # Sanity check: must look like ``T<digits>`` or ``T<digits>.<digits>``.
        # Cheap regex-free validation: starts with T, second char is a digit.
        if len(technique) < 2 or technique[0] != "T" or not technique[1].isdigit():
            continue
        if technique in seen:
            continue
        seen.add(technique)
        out.append(technique)
    return out


# Canonical MITRE ATT&CK Enterprise tactics. The SigmaHQ tag
# specification (Tags_specification.md) uses underscore form
# (``attack.defense_evasion``), so that's our canonical key. Some
# community rules use hyphens; we normalise both forms before lookup.
_MITRE_TACTIC_LOOKUP: dict[str, tuple[str, str]] = {
    "reconnaissance": ("TA0043", "Reconnaissance"),
    "resource_development": ("TA0042", "Resource Development"),
    "initial_access": ("TA0001", "Initial Access"),
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege_escalation": ("TA0004", "Privilege Escalation"),
    "defense_evasion": ("TA0005", "Defense Evasion"),
    "credential_access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "lateral_movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"),
    "command_and_control": ("TA0011", "Command and Control"),
    "exfiltration": ("TA0010", "Exfiltration"),
    "impact": ("TA0040", "Impact"),
}


def _extract_mitre_tactics(tags: list[Any] | None) -> list[str]:
    """Pull MITRE ATT&CK tactic *IDs* from a Sigma ``tags`` list.

    Returns the TA-code form (``TA0005``) so we can join against the
    canonical ATT&CK matrix without lossy string matching. Tags that
    don't map to a known tactic are silently ignored — community Sigma
    rules sometimes carry other ``attack.*`` tags (``attack.g0007``)
    that aren't tactics, and we don't want noise in the column.

    Accepts both ``attack.defense_evasion`` (Sigma canonical) and
    ``attack.defense-evasion`` (occasional hyphenated form) by
    normalising hyphens to underscores before the lookup.
    """
    if not tags:
        return []

    out: list[str] = []
    seen: set[str] = set()
    for tag in tags:
        if not isinstance(tag, str):
            continue
        normalised = tag.strip().lower()
        if not normalised.startswith("attack."):
            continue
        candidate = normalised.split(".", 1)[1]
        # Skip technique tags (``attack.t1078``) — those are handled
        # by ``_extract_mitre_techniques``.
        if candidate.startswith("t") and len(candidate) > 1 and candidate[1].isdigit():
            continue
        # Normalise hyphenated form to underscore form before lookup.
        candidate = candidate.replace("-", "_")
        match = _MITRE_TACTIC_LOOKUP.get(candidate)
        if match is None:
            continue
        ta_code, _name = match
        if ta_code in seen:
            continue
        seen.add(ta_code)
        out.append(ta_code)
    return out


# Map upstream Sigma logsource buckets to AiSOC's six-folder taxonomy.
# Mirrors ``tools/detection_import/common.py::normalise_categories``.
_CATEGORY_ALIASES: dict[str, str] = {
    "aws": "cloud",
    "azure": "cloud",
    "gcp": "cloud",
    "m365": "cloud",
    "microsoft365": "cloud",
    "okta": "identity",
    "auth": "identity",
    "authentication": "identity",
    "windows": "endpoint",
    "linux": "endpoint",
    "macos": "endpoint",
    "process_creation": "endpoint",
    "file_event": "endpoint",
    "image_load": "endpoint",
    "registry_event": "endpoint",
    "proxy": "network",
    "firewall": "network",
    "dns": "network",
    "dns_query": "network",
    "network_connection": "network",
    "webserver": "application",
    "web": "application",
    "exfiltration": "data-exfil",
}

_NATIVE_CATEGORIES = frozenset(
    {
        "cloud",
        "identity",
        "endpoint",
        "network",
        "application",
        "data-exfil",
    }
)


def _category_for(logsource: dict[str, Any] | None) -> str:
    """Pick the AiSOC category folder for a Sigma rule.

    Tries ``logsource.product`` first (most reliable for cloud rules),
    then ``logsource.category``, then ``logsource.service``. Falls back
    to ``endpoint`` because that's where the bulk of community Sigma
    rules belong and a wrong-but-present category is more useful than
    no category at all.
    """
    if not isinstance(logsource, dict):
        return "endpoint"

    for key in ("product", "category", "service"):
        candidate = logsource.get(key)
        if not candidate:
            continue
        candidate = str(candidate).strip().lower()
        if not candidate:
            continue
        if candidate in _CATEGORY_ALIASES:
            return _CATEGORY_ALIASES[candidate]
        if candidate in _NATIVE_CATEGORIES:
            return candidate
    return "endpoint"


def _map_severity(level: Any) -> str:
    """Coerce Sigma's ``level`` field into AiSOC's severity enum.

    See :data:`_SEVERITY_MAP` for the policy. Anything unrecognised
    becomes ``medium`` — never ``critical``, to avoid auto-paging on
    upstream typos.
    """
    if not level:
        return "medium"
    return _SEVERITY_MAP.get(str(level).strip().lower(), "medium")


# ─── Provenance ──────────────────────────────────────────────────────────────


def _build_provenance(
    raw: dict[str, Any],
    *,
    source: str,
    source_commit: str | None,
    license_id: str,
    license_url: str,
    upstream_path: str | None,
    ocsf_ref: OcsfClassRef,
) -> dict[str, Any]:
    """Build the JSONB provenance block for a single imported rule.

    The shape is queried by:

    * the upcoming detection management UI (W-B3) — ``license`` is the
      filter for legal review,
    * re-import idempotency — ``(source, source_id)``,
    * the OCSF coverage heatmap (W-B3) — ``ocsf.class_uid``.

    Don't add fields here without a downstream consumer in mind; the
    column is JSONB and we'd rather keep the shape lean than attract
    drive-by additions.
    """
    return {
        "source": source,
        "source_id": str(raw.get("id") or "").strip(),
        "source_commit": (source_commit or "").strip() or None,
        "license": license_id,
        "license_url": license_url,
        "imported_at": datetime.now(UTC).isoformat(),
        "imported_by": "sigma_import_service",
        "upstream_path": upstream_path,
        "ocsf": ocsf_ref.to_dict(),
        "upstream_status": str(raw.get("status") or "").strip().lower() or None,
    }


# ─── Conversion ──────────────────────────────────────────────────────────────


@dataclass(slots=True)
class _NormalisedRule:
    """Internal carrier for the normalised view of a Sigma rule.

    Not exported — the public surface is :class:`SigmaImportResult`.
    """

    name: str
    description: str
    rule_body: str
    category: str
    severity: str
    status: str  # "testing" | "disabled" (quarantine)
    enabled: bool  # informational only; the column is ``status``
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    tags: list[str]
    provenance: dict[str, Any]


def _normalise_rule(
    raw: dict[str, Any],
    *,
    source: str,
    source_commit: str | None,
    license_id: str,
    license_url: str,
    upstream_path: str | None,
) -> _NormalisedRule | None:
    """Convert one Sigma rule dict into the AiSOC-shaped record.

    Returns ``None`` when the rule should be skipped entirely (deprecated
    upstream, missing detection block, etc.). Quarantined rules (Sigma
    ``experimental``/``test``) come back with ``status="disabled"`` so
    they land in the table but don't fire until an operator flips them.
    """
    upstream_id = str(raw.get("id") or "").strip()
    title = str(raw.get("title") or "").strip()
    if not upstream_id or not title:
        return None

    upstream_status = str(raw.get("status") or "").strip().lower()
    if upstream_status in _SIGMA_SKIP_STATUSES:
        return None

    detection = raw.get("detection")
    if not isinstance(detection, dict) or not detection:
        # No detection block ⇒ unusable; runtime engine would just NOOP.
        return None

    quarantined = upstream_status in _SIGMA_QUARANTINE_STATUSES

    description = str(raw.get("description") or title).strip()
    severity = _map_severity(raw.get("level"))
    raw_tags = raw.get("tags") or []
    techniques = _extract_mitre_techniques(raw_tags)
    tactics = _extract_mitre_tactics(raw_tags)

    logsource = raw.get("logsource") or {}
    category = _category_for(logsource)
    ocsf_ref = map_logsource_to_ocsf(logsource if isinstance(logsource, dict) else None)

    # We persist the full upstream rule as YAML in ``rule_body`` so the
    # runtime engine has everything pySigma might want (selections,
    # condition, falsepositives, tags). Deferring the YAML serialisation
    # to import time avoids a costly re-read at evaluation time.
    rule_body = _serialise_to_yaml(raw)

    provenance = _build_provenance(
        raw,
        source=source,
        source_commit=source_commit,
        license_id=license_id,
        license_url=license_url,
        upstream_path=upstream_path,
        ocsf_ref=ocsf_ref,
    )

    flat_tags = [t for t in raw_tags if isinstance(t, str)]

    return _NormalisedRule(
        name=title,
        description=description,
        rule_body=rule_body,
        category=category,
        severity=severity,
        # We never auto-promote community rules to ``enabled``. Native
        # rules ship enabled; imports default to ``testing`` (flips to
        # ``disabled`` for quarantine) so the operator opts in explicitly.
        status="disabled" if quarantined else "testing",
        enabled=not quarantined,
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        tags=flat_tags,
        provenance=provenance,
    )


def _serialise_to_yaml(raw: dict[str, Any]) -> str:
    """Round-trip the upstream Sigma rule to YAML for ``rule_body``.

    PyYAML is already a dependency of the rule engine, so importing it
    here doesn't widen the dependency surface. ``sort_keys=False`` so
    the output reads in the same order the Sigma maintainer wrote it
    in — much friendlier when a human inspects the row.
    """
    import yaml  # local import: keeps module import cheap for non-import call sites

    return yaml.safe_dump(raw, sort_keys=False, allow_unicode=True)


# ─── Persistence ─────────────────────────────────────────────────────────────


async def _find_existing_rule(
    session: AsyncSession,
    *,
    source: str,
    source_id: str,
    tenant_id: uuid.UUID | None,
) -> DetectionRule | None:
    """Find an existing imported rule by ``(source, source_id, tenant)``.

    The provenance JSONB index makes this a single index scan — see the
    ``detection_rules_provenance_source_idx`` index in migration 036.
    """
    stmt = (
        select(DetectionRule)
        .where(
            DetectionRule.tenant_id.is_(None) if tenant_id is None else DetectionRule.tenant_id == tenant_id,
            DetectionRule.provenance["source"].astext == source,
            DetectionRule.provenance["source_id"].astext == source_id,
        )
        .limit(1)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


def _apply_normalised_to_rule(rule: DetectionRule, normalised: _NormalisedRule) -> None:
    """Copy the normalised view onto a (possibly existing) ORM row.

    Centralised so insert and update share the same field list — when
    we add a column to ``DetectionRule``, we add it once here and both
    paths pick it up.
    """
    rule.name = normalised.name
    rule.description = normalised.description
    rule.rule_language = "sigma"
    rule.rule_body = normalised.rule_body
    rule.category = normalised.category
    rule.severity = normalised.severity
    rule.status = normalised.status
    rule.mitre_tactics = list(normalised.mitre_tactics)
    rule.mitre_techniques = list(normalised.mitre_techniques)
    rule.tags = list(normalised.tags)
    rule.provenance = dict(normalised.provenance)
    # ``is_builtin`` flags content shipped by the platform. Imported
    # community content is *not* built-in — it's curated, but it can be
    # disabled or pruned by the operator at any time.
    rule.is_builtin = False


# ─── Public API ──────────────────────────────────────────────────────────────


async def import_sigma_rules(
    session: AsyncSession,
    rules: list[dict[str, Any]],
    *,
    source: str = "SigmaHQ/sigma",
    source_commit: str | None = None,
    license_id: str = "DRL-1.1",
    license_url: str = "https://github.com/SigmaHQ/Detection-Rule-License",
    tenant_id: uuid.UUID | None = None,
    upstream_paths: dict[str, str] | None = None,
) -> SigmaImportReport:
    """Import a batch of Sigma rules into the ``detection_rules`` table.

    The pipeline is intentionally batch-shaped — callers either ingest a
    full repo (CLI orchestrator) or a curated upload (future API). Both
    converge here. Idempotency is keyed on ``(source, source_id)``, so
    running the same input twice produces inserts the first time and
    updates (with the same field values) the second time.

    Args:
        session: an open async SQLAlchemy session. Caller owns commit/
            rollback. We flush after each rule so generated UUIDs are
            available for the report, but we don't commit — the caller
            decides whether to wrap many imports in a single transaction
            (typical for the CLI) or one each (typical for an API).
        rules: a list of parsed Sigma rule dicts (already YAML-loaded).
            Loading from disk is the caller's responsibility; this
            module stays I/O-light so it's testable without a tmpfs.
        source: provenance source identifier. Default
            ``SigmaHQ/sigma``; the CAR / Splunk / Chronicle importers
            pass their own value.
        source_commit: upstream commit SHA the rules came from. Stored
            short-form (7 chars) in provenance for audit.
        license_id: SPDX-ish license identifier for the upstream
            content. Default DRL-1.1 (Sigma's own license).
        license_url: link to the full license text. Surfaced in the
            management UI so operators can review attribution
            requirements per rule.
        tenant_id: optional tenant scope. ``None`` (default) means the
            rules are platform-wide and visible to every tenant. RLS
            policies on the table mean ``None`` rules never leak across
            tenants — they're explicitly platform content.
        upstream_paths: optional ``{source_id: upstream/path.yml}``
            map. Used by the CLI orchestrator to record where in the
            upstream repo a rule came from. The API import endpoint
            won't usually have this; the field is optional in
            provenance.

    Returns:
        :class:`SigmaImportReport` with per-rule outcomes and counts.

    Raises:
        :class:`SigmaImportError`: if the input shape is fundamentally
            wrong (e.g. ``rules`` is not a list). Per-rule problems are
            recorded in ``report.failures`` and don't raise.
    """
    if not isinstance(rules, list):
        raise SigmaImportError(f"`rules` must be a list, got {type(rules).__name__}")

    upstream_paths = upstream_paths or {}
    report = SigmaImportReport()

    for index, raw in enumerate(rules):
        if not isinstance(raw, dict):
            report.failures.append(
                {
                    "index": index,
                    "reason": "rule entry is not a dict",
                    "type": type(raw).__name__,
                }
            )
            continue

        upstream_id = str(raw.get("id") or "").strip()
        title = str(raw.get("title") or "").strip()
        if not upstream_id:
            report.failures.append({"index": index, "reason": "missing rule id", "title": title or None})
            continue

        upstream_path = upstream_paths.get(upstream_id)

        try:
            normalised = _normalise_rule(
                raw,
                source=source,
                source_commit=source_commit,
                license_id=license_id,
                license_url=license_url,
                upstream_path=upstream_path,
            )
        except Exception as exc:  # noqa: BLE001 -- per-rule failure isolation
            logger.exception("Sigma normalisation failed for %s", upstream_id)
            report.failures.append(
                {
                    "index": index,
                    "source_id": upstream_id,
                    "title": title,
                    "reason": f"normalisation error: {exc}",
                }
            )
            continue

        if normalised is None:
            # Skipped pre-DB: deprecated, no detection block, or
            # missing required fields. Surfaced as ``skipped`` rather
            # than ``failures`` because it's a deliberate filter, not
            # an error.
            report.skipped.append(
                SigmaImportResult(
                    rule_id=uuid.uuid4(),  # placeholder — never persisted
                    source=source,
                    source_id=upstream_id,
                    title=title,
                    action="skipped",
                    reason=_skip_reason(raw),
                )
            )
            continue

        try:
            existing = await _find_existing_rule(
                session,
                source=source,
                source_id=upstream_id,
                tenant_id=tenant_id,
            )

            if existing is None:
                rule = DetectionRule(
                    tenant_id=tenant_id,
                    confidence=50,
                    fp_rate=0.0,
                    suppression_config={},
                    threshold_config={},
                    total_hits=0,
                    version=1,
                )
                _apply_normalised_to_rule(rule, normalised)
                session.add(rule)
                await session.flush()
                report.inserted.append(
                    SigmaImportResult(
                        rule_id=rule.id,
                        source=source,
                        source_id=upstream_id,
                        title=normalised.name,
                        action="inserted",
                    )
                )
            else:
                _apply_normalised_to_rule(existing, normalised)
                # Bump version on every update so the management UI can
                # show "this rule changed N times since you opted in".
                existing.version = (existing.version or 1) + 1
                await session.flush()
                report.updated.append(
                    SigmaImportResult(
                        rule_id=existing.id,
                        source=source,
                        source_id=upstream_id,
                        title=normalised.name,
                        action="updated",
                        reason="re-import overwrote existing record",
                    )
                )
        except Exception as exc:  # noqa: BLE001 -- per-rule failure isolation
            logger.exception("Sigma persist failed for %s", upstream_id)
            report.failures.append(
                {
                    "index": index,
                    "source_id": upstream_id,
                    "title": title,
                    "reason": f"persist error: {exc}",
                }
            )
            continue

    logger.info(
        "Sigma import: %d inserted, %d updated, %d skipped, %d failed (source=%s commit=%s)",
        len(report.inserted),
        len(report.updated),
        len(report.skipped),
        len(report.failures),
        source,
        source_commit or "?",
    )
    return report


def _skip_reason(raw: dict[str, Any]) -> str:
    """Best-effort human-readable reason for a skipped rule.

    Used purely for the import report; never branched on by callers.
    """
    status = str(raw.get("status") or "").strip().lower()
    if status in _SIGMA_SKIP_STATUSES:
        return f"upstream status={status}"
    detection = raw.get("detection")
    if not isinstance(detection, dict) or not detection:
        return "missing or empty detection block"
    if not str(raw.get("title") or "").strip():
        return "missing title"
    if not str(raw.get("id") or "").strip():
        return "missing id"
    return "did not pass normalisation"


__all__ = [
    "SigmaImportError",
    "SigmaImportReport",
    "SigmaImportResult",
    "import_sigma_rules",
]
