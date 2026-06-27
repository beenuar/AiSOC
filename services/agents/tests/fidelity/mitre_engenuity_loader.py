"""MITRE Engenuity ATT&CK Evaluations loader → OCSF Detection Finding (class_uid 2004).

MITRE Engenuity publishes "ATT&CK Evaluations" rounds (rounds 1-7 as
of late 2025: APT3, APT29, Carbanak+FIN7, Wizard Spider+Sandworm,
OilRig, Turla, and Enterprise CyberArk respectively). Each round
exercises a real adversary's TTPs against a participating vendor's
EDR/XDR product and the participating-vendor JSONs include, per
procedure:

  * the ATT&CK Technique ID (`Txxxx[.yyy]`) the procedure exercises,
  * the tactic the technique falls under,
  * the participating vendor's *detection category* — one of
    ``None``, ``Telemetry``, ``General``, ``Tactic``, ``Technique`` —
    in the order MITRE explicitly grades them (higher = more detail),
  * optional adjacent modifiers (``Configuration Change``, ``Delayed``).

For the AiSOC fidelity harness we ingest the JSON of any one
participating vendor's round and emit one harness row per *procedure*
(not per *step*; a step can be sub-decomposed but MITRE reports
procedure-level grades). The canonical label families used here are
the **detection categories themselves** — the substrate classifier's
job is to predict the category given the technique + tactic + a few
heuristic features carried through to the runner.

  * `none`     — vendor did not see the procedure
  * `telemetry` — raw telemetry only; analyst can reconstruct
  * `general`   — alert fired, no ATT&CK context
  * `tactic`    — alert tagged with tactic
  * `technique` — alert tagged with technique

Lower categories collapse upward when MITRE annotates a procedure as
both `Telemetry` *and* `Technique` (we score on the **highest**
category present, matching the MITRE rubric).

The loader is stdlib-only (`json`, `re`) so CI can run it against the
committed micro fixture without adding a runtime dependency.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# MITRE category ladder, ordered low-to-high. ``score()`` uses the
# index to pick the *highest* category present on a procedure.
_CATEGORY_LADDER: tuple[str, ...] = (
    "none",
    "telemetry",
    "general",
    "tactic",
    "technique",
)

_CATEGORY_ALIASES: dict[str, str] = {
    "": "none",
    "n/a": "none",
    "na": "none",
    "no detection": "none",
    "miss": "none",
    "none": "none",
    "telemetry": "telemetry",
    "general": "general",
    "general behavior": "general",
    "tactic": "tactic",
    "technique": "technique",
    "subtechnique": "technique",
    "sub-technique": "technique",
}

# MITRE writes technique IDs as ``T1059.003`` for sub-techniques or
# ``T1059`` for parent techniques. The regex keeps the dotted form so
# the substrate classifier can key off the sub-technique when present.
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _normalise_category(raw: str) -> str:
    """Collapse a MITRE detection-category string to the canonical ladder."""

    key = (raw or "").strip().lower()
    return _CATEGORY_ALIASES.get(key, "telemetry" if key else "none")


def _category_score(category: str) -> int:
    """Return the ladder index for a canonical category. Lower = worse."""

    try:
        return _CATEGORY_LADDER.index(category)
    except ValueError:
        return 0


def _extract_techniques(raw: dict[str, Any]) -> list[str]:
    """Pull every Txxxx / Txxxx.yyy reference out of a procedure dict.

    MITRE's published JSONs vary by round: some carry an explicit
    ``Technique.Id`` key, some carry the technique inline in a
    ``Step.Description``. We probe a small list of canonical fields
    first, then fall back to a regex sweep of every string value.
    """

    canonical_keys = (
        "Technique.Id",
        "technique_id",
        "TechniqueId",
        "Technique",
    )
    out: list[str] = []
    seen: set[str] = set()
    for key in canonical_keys:
        val = raw.get(key)
        if isinstance(val, str):
            m = _TECHNIQUE_RE.findall(val)
            for hit in m:
                if hit not in seen:
                    seen.add(hit)
                    out.append(hit)
    if out:
        return out
    # Regex sweep of every string value.

    def _walk(node: Any) -> None:
        if isinstance(node, str):
            for hit in _TECHNIQUE_RE.findall(node):
                if hit not in seen:
                    seen.add(hit)
                    out.append(hit)
        elif isinstance(node, dict):
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for v in node:
                _walk(v)

    _walk(raw)
    return out


def _highest_category(raw: dict[str, Any]) -> str:
    """Inspect every detection annotation on a procedure and return
    the *highest* canonical category. Mirrors the MITRE rubric where a
    procedure with both `Telemetry` and `Technique` annotations is
    scored at `Technique`."""

    best_idx = 0
    best = "none"

    # Probe explicit detection-category fields first.
    for key in (
        "DetectionCategory",
        "detection_category",
        "Category",
        "category",
        "Detection",
    ):
        val = raw.get(key)
        if isinstance(val, str):
            canon = _normalise_category(val)
            idx = _category_score(canon)
            if idx > best_idx:
                best_idx = idx
                best = canon

    # Then probe a ``Detections`` / ``annotations`` array if present.
    for key in ("Detections", "detections", "annotations", "Modifiers"):
        val = raw.get(key)
        if isinstance(val, list):
            for ann in val:
                if isinstance(ann, dict):
                    for inner in ("Category", "category", "Type", "type"):
                        s = ann.get(inner)
                        if isinstance(s, str):
                            canon = _normalise_category(s)
                            idx = _category_score(canon)
                            if idx > best_idx:
                                best_idx = idx
                                best = canon
                elif isinstance(ann, str):
                    canon = _normalise_category(ann)
                    idx = _category_score(canon)
                    if idx > best_idx:
                        best_idx = idx
                        best = canon
    return best


def _coerce_tactic(raw: dict[str, Any]) -> str:
    for key in ("Tactic", "tactic", "TacticName"):
        v = raw.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _coerce_step(raw: dict[str, Any]) -> str:
    for key in ("Step", "step", "StepNumber", "step_number"):
        v = raw.get(key)
        if v is not None:
            return str(v).strip()
    return ""


def _normalise_procedure(raw: dict[str, Any], *, round_name: str, vendor: str) -> dict[str, Any]:
    """Collapse one MITRE Engenuity procedure dict into a harness row.

    The ``label`` is the *ground-truth* detection category reported by
    MITRE for this procedure-vendor pair. The substrate classifier will
    try to predict the same category from the technique + tactic +
    step features.
    """

    techniques = _extract_techniques(raw)
    category = _highest_category(raw)
    return {
        "round": round_name,
        "vendor": vendor,
        "step": _coerce_step(raw),
        "tactic": _coerce_tactic(raw),
        "techniques": techniques,
        "primary_technique": techniques[0] if techniques else "",
        "label": category,
    }


def to_ocsf(row: dict[str, Any]) -> dict[str, Any]:
    """Convert a normalised MITRE Engenuity row into an OCSF Detection
    Finding (class_uid 2004) event.

    The Detection Finding class is the natural OCSF home for an
    adversary-emulation grade. The fields the substrate classifier
    needs (the technique IDs, tactic, MITRE-graded category) live
    under the standard ``finding.attacks`` namespace plus the
    ``unmapped`` extension for the per-round vendor identity.
    """

    techniques = row.get("techniques") or []
    primary = row.get("primary_technique") or (techniques[0] if techniques else "")
    return {
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "type_uid": 200401,
        "activity_id": 1,
        "activity_name": "Create",
        "severity_id": 1,
        "severity": "Informational",
        "time": "",
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "MITRE Engenuity ATT&CK Evaluations",
                "vendor_name": "MITRE Engenuity",
            },
            "log_name": f"engenuity.{row.get('round', 'unknown')}",
        },
        "finding": {
            "title": f"Procedure step {row.get('step', '?')} — {row.get('tactic', 'unknown')} — {primary or 'no-technique'}",
            "uid": f"{row.get('round', 'unknown')}-{row.get('vendor', 'unknown')}-{row.get('step', '?')}",
            "attacks": [
                {
                    "technique": {
                        "uid": tid,
                    },
                    "tactic": {
                        "name": row.get("tactic", ""),
                    },
                }
                for tid in techniques
            ],
        },
        "unmapped": {
            "round": row.get("round", ""),
            "vendor": row.get("vendor", ""),
            "category": row.get("label", "none"),
        },
    }


def iter_flows(path: Path | str, *, limit: int | None = None) -> Iterator[dict[str, Any]]:
    """Stream a MITRE Engenuity round JSON as normalised harness rows.

    Accepts both shapes published across rounds 1-7:

      * top-level list of procedure dicts, or
      * dict with ``Steps`` / ``Procedures`` keys carrying the list.

    Vendor + round identifiers are read from the file's top-level
    metadata when present (``Round``, ``Vendor`` keys) and fall back
    to the file stem otherwise.
    """

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"MITRE Engenuity JSON not found: {p}")

    with p.open("r", encoding="utf-8") as fh:
        try:
            payload = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"MITRE Engenuity JSON not parseable: {p}: {exc}") from exc

    if isinstance(payload, list):
        meta: dict[str, Any] = {}
        procedures = payload
    elif isinstance(payload, dict):
        meta = payload
        procedures = payload.get("Procedures") or payload.get("Steps") or payload.get("procedures") or []
        if not isinstance(procedures, list):
            procedures = []
    else:
        raise ValueError(f"MITRE Engenuity JSON has unexpected shape: {type(payload).__name__}")

    round_name = str(meta.get("Round") or meta.get("round") or p.stem)
    vendor = str(meta.get("Vendor") or meta.get("vendor") or "unknown")

    count = 0
    for raw in procedures:
        if not isinstance(raw, dict):
            continue
        row = _normalise_procedure(raw, round_name=round_name, vendor=vendor)
        yield row
        count += 1
        if limit is not None and count >= limit:
            break
