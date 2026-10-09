#!/usr/bin/env python3
"""One answer to "why is this rule not loaded", from every decision table.

Two tables record rules that leave the stateless corpus:
`windowed_translation.py` (depth plan 3.1) and `enrichment_decisions.py`
(3.3). `export_detection_ruleset.py` and `generate_detections.py` both need
the union, and both asking each table in turn is how one of them comes to
ask only one.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

__all__ = ["retired", "retirement_reason"]


def retired() -> dict[str, str]:
    """`<category>/<slug>` → the sentence the catalogue publishes."""
    from enrichment_decisions import DECISIONS as ENRICHMENT  # noqa: PLC0415
    from windowed_translation import DECISIONS as WINDOWED  # noqa: PLC0415
    from windowed_translation import retirement_reason as windowed_reason  # noqa: PLC0415

    out = {key: windowed_reason(key) for key in WINDOWED}
    overlap = sorted(set(out) & set(ENRICHMENT))
    if overlap:
        raise SystemExit(
            f"rule_retirement: {len(overlap)} rule(s) are retired by two tables: {', '.join(overlap)}. "
            "One rule, one reason — a reader of the catalogue cannot be given two."
        )
    for key, decision in ENRICHMENT.items():
        out[key] = f"not executable ({decision.kind}): {decision.reason}"
    return out


def retirement_reason(key: str) -> str:
    """The sentence for one rule, or '' when it still ships."""
    return retired().get(key, "")
