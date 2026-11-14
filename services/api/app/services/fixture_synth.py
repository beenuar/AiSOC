"""Deterministically synthesise positive/negative fixtures from a Sigma rule.

The AI Detection Builder (Wave 3, W3.2) needs test fixtures so the non-circular
eval-gate can prove a generated rule fires on a positive and stays quiet on a
negative. Rather than trust an LLM to invent fixtures (which could be gamed to
pass), we DERIVE them from the rule's own ``detection.selection`` — a positive
event that satisfies every selector, and a negative that breaks one. The gate
then confirms the rule actually behaves as written.

Supports the common Sigma selection shapes (``field: value``,
``field|contains|startswith|endswith: value``, list values). Complex rules
(multiple selections, ``not`` conditions) may not yield a passing fixture — in
that case the eval-gate fails and the builder asks the human for fixtures,
which is the honest outcome.
"""

from __future__ import annotations

from typing import Any

import yaml

_SENTINEL = "aisoc-nonmatching-sentinel-0xdeadbeef"


def _matching_value(modifier: str, value: str) -> str:
    value = str(value)
    if modifier == "contains":
        return f"pre-{value}-post"
    if modifier == "startswith":
        return f"{value}-post"
    if modifier == "endswith":
        return f"pre-{value}"
    # equals / re / unknown → use the literal (best effort)
    return value


def _first_selection(detection: dict[str, Any]) -> dict[str, Any] | None:
    for key, val in detection.items():
        if key == "condition":
            continue
        if isinstance(val, dict):
            return val
    return None


def derive_fixtures_from_sigma(sigma_yaml: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]] | None:
    """Return ``([positive_event], [negative_event])`` or ``None`` if the rule's
    selection can't be turned into fixtures."""
    try:
        doc = yaml.safe_load(sigma_yaml)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict):
        return None
    detection = doc.get("detection")
    if not isinstance(detection, dict):
        return None
    selection = _first_selection(detection)
    if not selection:
        return None

    positive: dict[str, Any] = {}
    for raw_key, raw_value in selection.items():
        parts = str(raw_key).split("|")
        field = parts[0]
        modifier = parts[1] if len(parts) > 1 else "equals"
        value = raw_value[0] if isinstance(raw_value, list) and raw_value else raw_value
        if isinstance(value, dict | list):
            continue  # nested/keyless selectors — skip (can't synthesise cleanly)
        positive[field] = _matching_value(modifier, str(value))

    if not positive:
        return None

    negative = dict(positive)
    first_field = next(iter(positive))
    negative[first_field] = _SENTINEL
    return [positive], [negative]
